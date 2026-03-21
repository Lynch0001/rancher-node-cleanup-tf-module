#!/usr/bin/env python3
"""
cleanup_rancher_nodenotfound_production.py

Production-oriented Rancher node cleanup controller for RKE2 clusters on AWS.

Purpose
-------
Delete stale Rancher node records only when the backing EC2 instance is gone and
multiple safety checks pass. Handles:
  - classic NodeNotFound orphan records
  - ASG-backed nodes that transition through unavailable / error
  - Karpenter nodes that may briefly expose cordoned / unschedulable=true
  - Karpenter race where the transient Rancher signal is missed between polls

High-safety behavior
--------------------
1) AWS instance existence is the hard gate.
2) Rancher metadata is a confidence signal.
3) Karpenter fallback deletion is separately feature-flagged.
4) AWS-missing must be stable across consecutive polls before deletion.
5) Deletes are rate-limited and idempotent.
6) Controller uses leader election and persists tracker state in a ConfigMap.
7) Prometheus metrics and readiness/health endpoints are exposed.
8) A generic retry/backoff framework is used for Rancher, AWS, and Kubernetes
   operations that are expected to be transiently flaky.

Dependencies
------------
  pip install requests boto3 kubernetes prometheus_client
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import signal
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, TypeVar

import boto3
import botocore
import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest
except Exception:  # pragma: no cover - optional at import time
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    CollectorRegistry = None  # type: ignore[assignment]
    Counter = Gauge = Histogram = None  # type: ignore[assignment]
    generate_latest = None  # type: ignore[assignment]

T = TypeVar("T")

INSTANCE_ID_RE = re.compile(r"\b(i-[0-9a-f]{8,17})\b")
STATE_KEY = "node-tracker.json"
FINALIZER_SLEEP_SECONDS = 0.2


# ---------------------------------------------------------------------------
# Runtime flags / coordination
# ---------------------------------------------------------------------------
class ShutdownFlag:
    def __init__(self) -> None:
        self._event = threading.Event()

    def set(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        return self._event.wait(timeout)


shutdown_flag = ShutdownFlag()


class AppStatus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.ready = False
        self.last_ready_reason = "starting"
        self.last_successful_scan_ts = 0.0
        self.is_leader = False

    def set_ready(self, ready: bool, reason: str) -> None:
        with self._lock:
            self.ready = ready
            self.last_ready_reason = reason

    def mark_scan_success(self) -> None:
        with self._lock:
            self.last_successful_scan_ts = time.time()
            self.ready = True
            self.last_ready_reason = "ok"

    def set_leader(self, is_leader: bool) -> None:
        with self._lock:
            self.is_leader = is_leader

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "ready": self.ready,
                "reason": self.last_ready_reason,
                "last_successful_scan_ts": self.last_successful_scan_ts,
                "is_leader": self.is_leader,
            }


app_status = AppStatus()


# ---------------------------------------------------------------------------
# Config / models
# ---------------------------------------------------------------------------
@dataclass
class RancherConfig:
    url: str
    token: str
    verify_tls: bool = True
    timeout_s: int = 30


@dataclass
class RetryConfig:
    attempts: int
    initial_backoff_s: float
    max_backoff_s: float
    jitter_ratio: float


@dataclass
class RuntimeConfig:
    rancher: RancherConfig
    cluster_ids: List[str]
    aws_region: str
    poll_seconds: int
    grace_seconds: int
    karpenter_missing_only_grace_seconds: int
    aws_missing_consecutive_polls_required: int
    karpenter_missing_consecutive_polls_required: int
    stale_tracker_ttl_seconds: int
    dry_run: bool
    enable_delete: bool
    enable_karpenter_fallback: bool
    max_deletes_per_loop: int
    state_configmap: str
    lease_name: str
    lease_namespace: str
    lease_duration_seconds: int
    ready_stale_after_seconds: int
    health_port: int
    metrics_enabled: bool
    retry: RetryConfig


@dataclass
class NodeDecision:
    node_id: str
    node_name: str
    cluster_id: str
    instance_id: Optional[str]
    rancher_state: str
    is_karpenter: bool
    rancher_reasons: List[str] = field(default_factory=list)
    aws_state: str = "unknown"
    aws_missing: bool = False

    @property
    def key(self) -> str:
        return f"{self.cluster_id}:{self.node_id}"


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
class NullMetric:
    def labels(self, *args, **kwargs):
        return self

    def inc(self, amount: float = 1.0) -> None:
        return None

    def set(self, value: float) -> None:
        return None

    def observe(self, value: float) -> None:
        return None


class Metrics:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and CollectorRegistry is not None
        self.registry = CollectorRegistry() if self.enabled else None

        if not self.enabled:
            self.scans_total = NullMetric()
            self.scan_failures_total = NullMetric()
            self.nodes_seen_total = NullMetric()
            self.candidates_total = NullMetric()
            self.aws_missing_total = NullMetric()
            self.decisions_total = NullMetric()
            self.deletes_total = NullMetric()
            self.delete_failures_total = NullMetric()
            self.retry_total = NullMetric()
            self.loop_duration_seconds = NullMetric()
            self.tracked_nodes = NullMetric()
            self.last_successful_scan_timestamp = NullMetric()
            self.leader_status = NullMetric()
            return

        self.scans_total = Counter(
            "rancher_node_cleaner_scans_total",
            "Number of controller scan loops attempted",
            registry=self.registry,
        )
        self.scan_failures_total = Counter(
            "rancher_node_cleaner_scan_failures_total",
            "Number of scan loops with top-level failures",
            registry=self.registry,
        )
        self.nodes_seen_total = Counter(
            "rancher_node_cleaner_nodes_seen_total",
            "Rancher nodes observed",
            ["cluster_id"],
            registry=self.registry,
        )
        self.candidates_total = Counter(
            "rancher_node_cleaner_candidates_total",
            "Nodes tracked as deletion candidates",
            ["cluster_id", "karpenter"],
            registry=self.registry,
        )
        self.aws_missing_total = Counter(
            "rancher_node_cleaner_aws_missing_total",
            "Nodes whose backing EC2 instance was missing/terminated",
            ["cluster_id"],
            registry=self.registry,
        )
        self.decisions_total = Counter(
            "rancher_node_cleaner_decisions_total",
            "Delete decision outcomes",
            ["decision", "path"],
            registry=self.registry,
        )
        self.deletes_total = Counter(
            "rancher_node_cleaner_deletes_total",
            "Rancher node deletions attempted or skipped",
            ["result", "path"],
            registry=self.registry,
        )
        self.delete_failures_total = Counter(
            "rancher_node_cleaner_delete_failures_total",
            "Failed Rancher node deletions",
            ["reason"],
            registry=self.registry,
        )
        self.retry_total = Counter(
            "rancher_node_cleaner_retries_total",
            "Retries performed by operation name",
            ["operation"],
            registry=self.registry,
        )
        self.loop_duration_seconds = Histogram(
            "rancher_node_cleaner_loop_duration_seconds",
            "Loop duration in seconds",
            registry=self.registry,
            buckets=(0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120),
        )
        self.tracked_nodes = Gauge(
            "rancher_node_cleaner_tracked_nodes",
            "Current number of tracker entries",
            registry=self.registry,
        )
        self.last_successful_scan_timestamp = Gauge(
            "rancher_node_cleaner_last_successful_scan_timestamp_seconds",
            "Unix timestamp of the last successful scan loop",
            registry=self.registry,
        )
        self.leader_status = Gauge(
            "rancher_node_cleaner_is_leader",
            "1 when this pod currently holds leadership, else 0",
            registry=self.registry,
        )

    def render(self) -> bytes:
        if not self.enabled or generate_latest is None or self.registry is None:
            return b"# metrics disabled\n"
        return generate_latest(self.registry)


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


logger = logging.getLogger("rancher_node_cleaner")


def log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    logger.info(json.dumps(payload, sort_keys=True, default=str))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def utc_now_ts() -> float:
    return time.time()


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_to_ts(s: str) -> Optional[float]:
    try:
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def hostname_identity() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def parse_cluster_ids() -> List[str]:
    ids = os.getenv("CLUSTER_IDS", "").strip()
    if ids:
        return [x.strip() for x in ids.split(",") if x.strip()]
    single = os.getenv("CLUSTER_ID", "").strip()
    return [single] if single else []


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=6,
        connect=6,
        read=6,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# Retry / backoff framework
# ---------------------------------------------------------------------------
def sleep_with_shutdown(seconds: float) -> None:
    if seconds <= 0:
        return
    shutdown_flag.wait(seconds)


def compute_backoff_seconds(attempt_index: int, cfg: RetryConfig) -> float:
    base = min(cfg.max_backoff_s, cfg.initial_backoff_s * (2 ** max(0, attempt_index - 1)))
    jitter = base * cfg.jitter_ratio * random.random()
    return min(cfg.max_backoff_s, base + jitter)


def retry_call(
    operation_name: str,
    func: Callable[[], T],
    retry_cfg: RetryConfig,
    metrics: Metrics,
    is_retryable: Callable[[Exception], bool],
) -> T:
    last_exc: Optional[Exception] = None
    for attempt in range(1, retry_cfg.attempts + 1):
        if shutdown_flag.is_set():
            raise RuntimeError(f"shutdown requested before {operation_name} completed")
        try:
            return func()
        except Exception as exc:
            last_exc = exc
            if attempt >= retry_cfg.attempts or not is_retryable(exc):
                raise
            metrics.retry_total.labels(operation_name).inc()
            delay = compute_backoff_seconds(attempt, retry_cfg)
            logger.warning(
                "retrying operation=%s attempt=%s/%s delay=%.2fs error=%s",
                operation_name,
                attempt,
                retry_cfg.attempts,
                delay,
                exc,
            )
            sleep_with_shutdown(delay)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Health / readiness / metrics server
# ---------------------------------------------------------------------------
class HealthServer:
    def __init__(self, port: int, metrics: Metrics, ready_stale_after_seconds: int) -> None:
        self.port = port
        self.metrics = metrics
        self.ready_stale_after_seconds = ready_stale_after_seconds
        self.httpd: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                snapshot = app_status.snapshot()
                if self.path == "/healthz":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ok\n")
                    return

                if self.path == "/readyz":
                    now = time.time()
                    recent_scan = snapshot["last_successful_scan_ts"] > 0 and (
                        now - snapshot["last_successful_scan_ts"] <= parent.ready_stale_after_seconds
                    )
                    ready = bool(snapshot["ready"] and recent_scan)
                    body = (
                        f"ready={str(ready).lower()} reason={snapshot['reason']} "
                        f"leader={str(snapshot['is_leader']).lower()}\n"
                    ).encode()
                    self.send_response(200 if ready else 503)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path == "/metrics":
                    payload = parent.metrics.render()
                    self.send_response(200)
                    self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                return

        self.httpd = HTTPServer(("0.0.0.0", self.port), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()


# ---------------------------------------------------------------------------
# Rancher API helpers
# ---------------------------------------------------------------------------
def rancher_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def rancher_get_paginated(
    session: requests.Session,
    cfg: RancherConfig,
    path: str,
    metrics: Metrics,
    retry_cfg: RetryConfig,
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    url = cfg.url.rstrip("/") + path
    items: List[Dict[str, Any]] = []

    while True:
        def _do_get() -> requests.Response:
            resp = session.get(
                url,
                headers=rancher_headers(cfg.token),
                params=params,
                timeout=cfg.timeout_s,
                verify=cfg.verify_tls,
            )
            if resp.status_code >= 500 or resp.status_code == 429:
                raise RuntimeError(f"Rancher GET transient failure {resp.status_code}: {resp.text[:300]}")
            if resp.status_code >= 400:
                raise ValueError(f"Rancher GET failed {resp.status_code}: {resp.text[:300]}")
            return resp

        r = retry_call(
            operation_name="rancher_get_paginated",
            func=_do_get,
            retry_cfg=retry_cfg,
            metrics=metrics,
            is_retryable=lambda e: isinstance(e, RuntimeError) or isinstance(e, requests.RequestException),
        )
        payload = r.json()
        items.extend(payload.get("data", []) or [])
        next_url = (payload.get("pagination") or {}).get("next")
        if not next_url:
            break
        url = next_url
        params = None
    return items


def rancher_delete_node(
    session: requests.Session,
    cfg: RancherConfig,
    node_id: str,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> str:
    url = cfg.url.rstrip("/") + f"/v3/nodes/{node_id}"

    def _do_delete() -> requests.Response:
        resp = session.delete(
            url,
            headers=rancher_headers(cfg.token),
            timeout=cfg.timeout_s,
            verify=cfg.verify_tls,
        )
        if resp.status_code in (200, 202, 204, 404):
            return resp
        if resp.status_code >= 500 or resp.status_code == 429:
            raise RuntimeError(f"Rancher DELETE transient failure {resp.status_code}: {resp.text[:300]}")
        raise ValueError(f"Rancher DELETE failed {resp.status_code}: {resp.text[:300]}")

    resp = retry_call(
        operation_name="rancher_delete_node",
        func=_do_delete,
        retry_cfg=retry_cfg,
        metrics=metrics,
        is_retryable=lambda e: isinstance(e, RuntimeError) or isinstance(e, requests.RequestException),
    )
    return "already-gone" if resp.status_code == 404 else "deleted"


# ---------------------------------------------------------------------------
# Rancher node introspection
# ---------------------------------------------------------------------------
def flatten_strings(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        if value:
            yield value
        return
    if isinstance(value, bool):
        yield str(value)
        return
    if isinstance(value, (int, float)):
        yield str(value)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from flatten_strings(v)
        return
    if isinstance(value, list):
        for item in value:
            yield from flatten_strings(item)
        return


def strings_blob(node: Dict[str, Any]) -> str:
    interesting = {
        "state": node.get("state"),
        "transitioning": node.get("transitioning"),
        "transitioningMessage": node.get("transitioningMessage"),
        "message": node.get("message"),
        "status": node.get("status"),
        "conditions": node.get("conditions"),
        "annotations": node.get("annotations"),
        "labels": node.get("labels"),
        "taints": node.get("taints"),
        "nodeSpec": node.get("nodeSpec") or node.get("node_spec"),
    }
    return " | ".join(s.lower() for s in flatten_strings(interesting))


def collect_string_values(value: Any, prefix: str = "") -> Iterable[Tuple[str, str]]:
    if value is None:
        return
    if isinstance(value, (str, bool, int, float)):
        if prefix:
            yield prefix, str(value)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            yield from collect_string_values(v, key)
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            key = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            yield from collect_string_values(item, key)


def select_decision_metadata(node: Dict[str, Any]) -> Dict[str, Any]:
    labels = node.get("labels") or {}
    annotations = node.get("annotations") or {}
    node_spec = node.get("nodeSpec") or node.get("node_spec") or {}
    conditions = node.get("conditions") or []

    exact_label_keys = [
        "cattle.io/instance-id",
        "node.kubernetes.io/instance-id",
        "karpenter.k8s.aws/instance-id",
        "node.kubernetes.io/instance-type",
        "beta.kubernetes.io/instance-type",
        "topology.kubernetes.io/region",
        "topology.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/region",
        "failure-domain.beta.kubernetes.io/zone",
        "eks.amazonaws.com/nodegroup",
        "eks.amazonaws.com/capacityType",
        "karpenter.sh/nodepool",
        "karpenter.sh/provisioner-name",
        "karpenter.sh/capacity-type",
        "karpenter.k8s.aws/ec2nodeclass",
        "karpenter.k8s.aws/instance-category",
        "karpenter.k8s.aws/instance-family",
        "karpenter.k8s.aws/instance-generation",
        "karpenter.k8s.aws/instance-size",
        "karpenter.k8s.aws/capacity-type",
    ]
    exact_annotation_keys = [
        "rke.cattle.io/external-id",
        "cattle.io/external-id",
        "cluster.x-k8s.io/provider-id",
        "cluster.x-k8s.io/cluster-name",
        "karpenter.sh/nodeclaim",
        "karpenter.k8s.aws/ec2nodeclass",
    ]
    fuzzy_tokens = (
        "autoscaling", "nodegroup", "launch-template", "launchtemplate",
        "karpenter", "nodepool", "provisioner", "nodeclaim",
        "instance-id", "instance-type", "capacity-type", "zone", "region",
    )

    selected_labels = {k: labels[k] for k in exact_label_keys if k in labels}
    selected_annotations = {k: annotations[k] for k in exact_annotation_keys if k in annotations}

    for k, v in labels.items():
        if k not in selected_labels and any(tok in k.lower() for tok in fuzzy_tokens):
            selected_labels[k] = v
    for k, v in annotations.items():
        if k not in selected_annotations and any(tok in k.lower() for tok in fuzzy_tokens):
            selected_annotations[k] = v

    condition_bits: Dict[str, Any] = {}
    if isinstance(conditions, list):
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            cond_type = str(cond.get("type") or cond.get("name") or "").strip()
            status = str(cond.get("status") or cond.get("state") or cond.get("value") or "").strip()
            if cond_type and (cond_type.lower() in {"cordoned", "unschedulable", "ready"} or status.lower() in {"true", "false", "unknown"}):
                condition_bits[cond_type] = status

    provider_candidates = []
    for keyspace in (node, node_spec, annotations, labels):
        if isinstance(keyspace, dict):
            for k, v in keyspace.items():
                if k in {"providerID", "providerId", "provider_id"} and isinstance(v, str) and v:
                    provider_candidates.append(v)
    if isinstance(node_spec, dict):
        for k in ("providerID", "providerId", "provider_id", "unschedulable"):
            if k in node_spec:
                provider_candidates.append(node_spec[k])

    return {
        "name": node.get("name") or node.get("hostname") or node.get("id"),
        "provider_candidates": provider_candidates,
        "labels": selected_labels,
        "annotations": selected_annotations,
        "node_spec": {
            k: node_spec.get(k)
            for k in ("providerID", "providerId", "provider_id", "unschedulable")
            if isinstance(node_spec, dict) and k in node_spec
        },
        "conditions": condition_bits,
    }


def debug_log_node_evaluation(
    cluster_id: str,
    node_id: str,
    node: Dict[str, Any],
    decision: NodeDecision,
    record: Optional[Dict[str, Any]],
    should_delete_flag: bool,
    decision_path: str,
) -> None:
    if not logger.isEnabledFor(logging.DEBUG):
        return

    logger.debug(
        json.dumps(
            {
                "event": "node_evaluation_debug",
                "cluster_id": cluster_id,
                "node_id": node_id,
                "node_name": decision.node_name,
                "instance_id": decision.instance_id,
                "karpenter": decision.is_karpenter,
                "rancher_state": decision.rancher_state,
                "rancher_reasons": decision.rancher_reasons,
                "aws_state": decision.aws_state,
                "aws_missing": decision.aws_missing,
                "aws_missing_count": int((record or {}).get("aws_missing_count") or 0),
                "aws_missing_since": (record or {}).get("aws_missing_since"),
                "bad_since": (record or {}).get("bad_since"),
                "delete_attempts": int((record or {}).get("delete_attempts") or 0),
                "quarantined": bool((record or {}).get("quarantined") or False),
                "should_delete": should_delete_flag,
                "decision_path": decision_path,
                "decision_metadata": select_decision_metadata(node),
            },
            sort_keys=True,
            default=str,
        )
    )


def extract_instance_id(node: Dict[str, Any]) -> Optional[str]:
    prioritized_candidates: List[str] = []

    def add_candidate(value: Any) -> None:
        if isinstance(value, str) and value:
            prioritized_candidates.append(value)

    for k in ("providerId", "providerID", "provider_id"):
        add_candidate(node.get(k))

    node_spec = node.get("nodeSpec") or node.get("node_spec") or {}
    if isinstance(node_spec, dict):
        for k in ("providerID", "providerId", "provider_id"):
            add_candidate(node_spec.get(k))

    labels = node.get("labels") or {}
    if isinstance(labels, dict):
        for lk in (
            "cattle.io/instance-id",
            "node.kubernetes.io/instance-id",
            "karpenter.k8s.aws/instance-id",
        ):
            add_candidate(labels.get(lk))

    annotations = node.get("annotations") or {}
    if isinstance(annotations, dict):
        for ak in (
            "rke.cattle.io/external-id",
            "cattle.io/external-id",
            "cluster.x-k8s.io/provider-id",
        ):
            add_candidate(annotations.get(ak))

    for _, value in collect_string_values({
        "node": node,
        "nodeSpec": node_spec,
        "labels": labels,
        "annotations": annotations,
    }):
        if "i-" in value:
            prioritized_candidates.append(value)

    for candidate in prioritized_candidates:
        match = INSTANCE_ID_RE.search(candidate)
        if match:
            return match.group(1)
    return None


def is_karpenter_node(node: Dict[str, Any]) -> bool:
    labels = node.get("labels") or {}
    annotations = node.get("annotations") or {}

    strong_keys = (
        "karpenter.sh/nodepool",
        "karpenter.sh/provisioner-name",
        "karpenter.k8s.aws/instance-category",
        "karpenter.k8s.aws/instance-family",
        "karpenter.k8s.aws/instance-generation",
        "karpenter.k8s.aws/ec2nodeclass",
    )
    return any(k in labels or k in annotations for k in strong_keys)


def rancher_candidate_reasons(node: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    state = (node.get("state") or "").strip().lower()
    transitioning = str(node.get("transitioning") or "").strip().lower()
    blob = strings_blob(node)

    if state == "nodenotfound":
        reasons.append("state:nodenotfound")
    if state in {"unavailable", "error", "err", "removed", "inactive"}:
        reasons.append(f"state:{state}")
    if transitioning in {"error", "yes"} and any(
        token in blob for token in ("error", "unavailable", "notfound", "terminated")
    ):
        reasons.append(f"transitioning:{transitioning}")

    message_tokens = {
        "nodenotfound": "message:nodenotfound",
        "node not found": "message:node-not-found",
        "unavailable": "message:unavailable",
        "transitioning to error": "message:transitioning-to-error",
        "cordoned": "message:cordoned",
        "unschedulable": "message:unschedulable",
        "drain": "message:drain",
        "draining": "message:draining",
        "terminated": "message:terminated",
        "termination": "message:termination",
    }
    for needle, reason in message_tokens.items():
        if needle in blob:
            reasons.append(reason)

    node_spec = node.get("nodeSpec") or node.get("node_spec") or {}
    if isinstance(node_spec, dict) and node_spec.get("unschedulable") is True:
        reasons.append("nodeSpec.unschedulable:true")

    conditions_blob = json.dumps(node.get("conditions", ""), default=str).lower()
    if '"cordoned"' in conditions_blob and '"true"' in conditions_blob:
        reasons.append("conditions:cordoned")
    if '"unschedulable"' in conditions_blob and '"true"' in conditions_blob:
        reasons.append("conditions:unschedulable")

    deduped: List[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    return deduped


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------
def is_retryable_aws_error(exc: Exception) -> bool:
    if isinstance(exc, botocore.exceptions.EndpointConnectionError):
        return True
    if isinstance(exc, botocore.exceptions.ConnectionClosedError):
        return True
    if isinstance(exc, botocore.exceptions.ReadTimeoutError):
        return True
    if isinstance(exc, botocore.exceptions.ConnectTimeoutError):
        return True
    if isinstance(exc, botocore.exceptions.ClientError):
        code = ((exc.response or {}).get("Error") or {}).get("Code", "")
        return code in {
            "RequestLimitExceeded",
            "Throttling",
            "ThrottlingException",
            "InternalError",
            "ServiceUnavailable",
        }
    return False


def classify_instance_states_batched(
    ec2: Any,
    instance_ids: Sequence[str],
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> Dict[str, str]:
    states: Dict[str, str] = {}
    if not instance_ids:
        return states

    unique_ids = sorted(set(i for i in instance_ids if i))
    batch_size = 100

    for start in range(0, len(unique_ids), batch_size):
        batch = unique_ids[start : start + batch_size]

        def _describe() -> Dict[str, Any]:
            return ec2.describe_instances(InstanceIds=batch)

        try:
            resp = retry_call(
                operation_name="aws_describe_instances",
                func=_describe,
                retry_cfg=retry_cfg,
                metrics=metrics,
                is_retryable=is_retryable_aws_error,
            )
            found: Set[str] = set()
            for reservation in resp.get("Reservations") or []:
                for inst in reservation.get("Instances") or []:
                    instance_id = inst.get("InstanceId")
                    state = ((inst.get("State") or {}).get("Name") or "unknown").lower()
                    if instance_id:
                        found.add(instance_id)
                        states[instance_id] = state
            for instance_id in batch:
                if instance_id not in found:
                    states[instance_id] = "missing"
        except botocore.exceptions.ClientError as exc:
            code = ((exc.response or {}).get("Error") or {}).get("Code", "")
            if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
                for instance_id in batch:
                    states[instance_id] = "missing"
            else:
                raise

    return states


# ---------------------------------------------------------------------------
# Kubernetes ConfigMap state
# ---------------------------------------------------------------------------
def load_incluster_k8s() -> Tuple[client.CoreV1Api, client.CoordinationV1Api]:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.CoreV1Api(), client.CoordinationV1Api()


def is_retryable_k8s_error(exc: Exception) -> bool:
    if not isinstance(exc, ApiException):
        return False
    return exc.status in (409, 429, 500, 502, 503, 504)


def get_or_create_state_configmap(
    core: client.CoreV1Api,
    namespace: str,
    name: str,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> client.V1ConfigMap:
    def _read() -> client.V1ConfigMap:
        return core.read_namespaced_config_map(name=name, namespace=namespace)

    try:
        return retry_call(
            operation_name="k8s_read_configmap",
            func=_read,
            retry_cfg=retry_cfg,
            metrics=metrics,
            is_retryable=is_retryable_k8s_error,
        )
    except ApiException as exc:
        if exc.status != 404:
            raise

    def _create() -> client.V1ConfigMap:
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
            data={STATE_KEY: "{}"},
        )
        return core.create_namespaced_config_map(namespace=namespace, body=cm)

    try:
        return retry_call(
            operation_name="k8s_create_configmap",
            func=_create,
            retry_cfg=retry_cfg,
            metrics=metrics,
            is_retryable=is_retryable_k8s_error,
        )
    except ApiException as exc:
        if exc.status == 409:
            return _read()
        raise


def read_state(
    core: client.CoreV1Api,
    namespace: str,
    name: str,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> Tuple[Dict[str, Dict[str, Any]], str]:
    cm = get_or_create_state_configmap(core, namespace, name, metrics, retry_cfg)
    raw = (cm.data or {}).get(STATE_KEY) or "{}"
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            obj = {}
    except Exception:
        obj = {}
    resource_version = (cm.metadata.resource_version if cm.metadata else None) or ""
    return obj, resource_version


def write_state(
    core: client.CoreV1Api,
    namespace: str,
    name: str,
    state: Dict[str, Dict[str, Any]],
    resource_version: str,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> str:
    payload = json.dumps(state, sort_keys=True)

    def _replace() -> client.V1ConfigMap:
        cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace,
                resource_version=resource_version,
            ),
            data={STATE_KEY: payload},
        )
        return core.replace_namespaced_config_map(name=name, namespace=namespace, body=cm)

    replaced = retry_call(
        operation_name="k8s_replace_configmap",
        func=_replace,
        retry_cfg=retry_cfg,
        metrics=metrics,
        is_retryable=is_retryable_k8s_error,
    )
    return (replaced.metadata.resource_version if replaced.metadata else None) or resource_version


# ---------------------------------------------------------------------------
# Kubernetes Lease leader election
# ---------------------------------------------------------------------------
def ensure_lease(
    coord: client.CoordinationV1Api,
    namespace: str,
    lease_name: str,
    duration_seconds: int,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> client.V1Lease:
    def _read() -> client.V1Lease:
        return coord.read_namespaced_lease(name=lease_name, namespace=namespace)

    try:
        return retry_call(
            operation_name="k8s_read_lease",
            func=_read,
            retry_cfg=retry_cfg,
            metrics=metrics,
            is_retryable=is_retryable_k8s_error,
        )
    except ApiException as exc:
        if exc.status != 404:
            raise

    def _create() -> client.V1Lease:
        now = datetime.now(timezone.utc).isoformat()
        body = client.V1Lease(
            metadata=client.V1ObjectMeta(name=lease_name, namespace=namespace),
            spec=client.V1LeaseSpec(
                holder_identity="",
                lease_duration_seconds=duration_seconds,
                acquire_time=now,
                renew_time=now,
            ),
        )
        return coord.create_namespaced_lease(namespace=namespace, body=body)

    try:
        return retry_call(
            operation_name="k8s_create_lease",
            func=_create,
            retry_cfg=retry_cfg,
            metrics=metrics,
            is_retryable=is_retryable_k8s_error,
        )
    except ApiException as exc:
        if exc.status == 409:
            return _read()
        raise


def try_acquire_or_renew_leadership(
    coord: client.CoordinationV1Api,
    namespace: str,
    lease_name: str,
    holder: str,
    duration_seconds: int,
    metrics: Metrics,
    retry_cfg: RetryConfig,
) -> bool:
    lease = ensure_lease(coord, namespace, lease_name, duration_seconds, metrics, retry_cfg)
    spec = lease.spec or client.V1LeaseSpec()

    now = datetime.now(timezone.utc)
    renew_time = spec.renew_time
    holder_identity = spec.holder_identity or ""

    expired = True
    if renew_time:
        if isinstance(renew_time, str):
            try:
                rt = datetime.fromisoformat(renew_time.replace("Z", "+00:00"))
            except Exception:
                rt = None
        else:
            rt = renew_time
        if rt:
            expired = (now - rt).total_seconds() > duration_seconds

    if not holder_identity or expired or holder_identity == holder:
        spec.holder_identity = holder
        spec.lease_duration_seconds = duration_seconds
        spec.renew_time = now.isoformat()
        if not spec.acquire_time:
            spec.acquire_time = now.isoformat()
        lease.spec = spec

        def _replace() -> client.V1Lease:
            return coord.replace_namespaced_lease(name=lease_name, namespace=namespace, body=lease)

        try:
            retry_call(
                operation_name="k8s_replace_lease",
                func=_replace,
                retry_cfg=retry_cfg,
                metrics=metrics,
                is_retryable=is_retryable_k8s_error,
            )
            return True
        except ApiException as exc:
            logger.warning("Lease update failed; not leader this round: %s", exc)
            return False

    return False


# ---------------------------------------------------------------------------
# Decision engine / tracker state
# ---------------------------------------------------------------------------
def build_node_decision(
    cluster_id: str,
    node: Dict[str, Any],
    aws_states: Dict[str, str],
) -> NodeDecision:
    node_id = (node.get("id") or "").strip()
    node_name = str(node.get("name") or node.get("hostname") or node_id)
    rancher_state = str(node.get("state") or "").strip().lower()
    instance_id = extract_instance_id(node)
    reasons = rancher_candidate_reasons(node)
    is_karpenter = is_karpenter_node(node)
    aws_state = aws_states.get(instance_id or "", "unknown") if instance_id else "unknown"
    aws_missing = aws_state in {"missing", "terminated", "shutting-down"}
    return NodeDecision(
        node_id=node_id,
        node_name=node_name,
        cluster_id=cluster_id,
        instance_id=instance_id,
        rancher_state=rancher_state,
        is_karpenter=is_karpenter,
        rancher_reasons=reasons,
        aws_state=aws_state,
        aws_missing=aws_missing,
    )


def ensure_tracker_record(state: Dict[str, Dict[str, Any]], key: str, now_ts: float) -> Dict[str, Any]:
    record = state.get(key)
    if not isinstance(record, dict):
        record = {
            "first_seen": utc_iso(now_ts),
            "last_seen": utc_iso(now_ts),
            "bad_since": None,
            "aws_missing_since": None,
            "aws_missing_count": 0,
            "delete_attempts": 0,
            "last_delete_error": None,
            "quarantined": False,
        }
        state[key] = record
    return record


def update_tracker_record(state: Dict[str, Dict[str, Any]], decision: NodeDecision, now_ts: float) -> Dict[str, Any]:
    record = ensure_tracker_record(state, decision.key, now_ts)
    record["last_seen"] = utc_iso(now_ts)
    record["node_name"] = decision.node_name
    record["cluster_id"] = decision.cluster_id
    record["instance_id"] = decision.instance_id
    record["is_karpenter"] = decision.is_karpenter
    record["rancher_state"] = decision.rancher_state
    record["rancher_reasons"] = list(decision.rancher_reasons)
    record["aws_state"] = decision.aws_state

    if decision.rancher_reasons:
        if not record.get("bad_since"):
            record["bad_since"] = utc_iso(now_ts)
    else:
        record["bad_since"] = None

    if decision.aws_missing:
        if not record.get("aws_missing_since"):
            record["aws_missing_since"] = utc_iso(now_ts)
            record["aws_missing_count"] = 1
        else:
            record["aws_missing_count"] = int(record.get("aws_missing_count") or 0) + 1
    else:
        record["aws_missing_since"] = None
        record["aws_missing_count"] = 0

    return record


def decision_age_seconds(record: Dict[str, Any], field_name: str, now_ts: float) -> float:
    ts = parse_iso_to_ts(str(record.get(field_name) or ""))
    return max(0.0, now_ts - ts) if ts is not None else 0.0


def should_delete(
    decision: NodeDecision,
    record: Dict[str, Any],
    cfg: RuntimeConfig,
    now_ts: float,
) -> Tuple[bool, str]:
    if not decision.instance_id:
        return False, "no-instance-id"
    if record.get("quarantined"):
        return False, "quarantined"
    if not decision.aws_missing:
        return False, "aws-present"

    aws_missing_count = int(record.get("aws_missing_count") or 0)
    aws_missing_age = decision_age_seconds(record, "aws_missing_since", now_ts)
    bad_age = decision_age_seconds(record, "bad_since", now_ts)
    has_rancher_signal = bool(decision.rancher_reasons)

    if aws_missing_count < cfg.aws_missing_consecutive_polls_required:
        return False, "aws-missing-not-stable"

    if has_rancher_signal and bad_age >= cfg.grace_seconds and aws_missing_age >= cfg.grace_seconds:
        return True, "standard"

    if has_rancher_signal:
        return False, "waiting-standard-grace"

    if (
        cfg.enable_karpenter_fallback
        and decision.is_karpenter
        and aws_missing_count >= cfg.karpenter_missing_consecutive_polls_required
        and aws_missing_age >= cfg.karpenter_missing_only_grace_seconds
    ):
        return True, "karpenter-fallback"

    if decision.is_karpenter and cfg.enable_karpenter_fallback:
        return False, "waiting-karpenter-fallback-grace"

    return False, "no-terminal-signal"


def prune_stale_state(
    state: Dict[str, Dict[str, Any]],
    seen_keys: Set[str],
    ttl_seconds: int,
    now_ts: float,
) -> bool:
    changed = False
    for key in list(state.keys()):
        rec = state.get(key)
        if key in seen_keys:
            continue
        if not isinstance(rec, dict):
            del state[key]
            changed = True
            continue
        last_seen_ts = parse_iso_to_ts(str(rec.get("last_seen") or ""))
        if last_seen_ts is None or (now_ts - last_seen_ts) >= ttl_seconds:
            del state[key]
            changed = True
    return changed


# ---------------------------------------------------------------------------
# Config loading / validation
# ---------------------------------------------------------------------------
def load_runtime_config() -> RuntimeConfig:
    rancher_url = os.getenv("RANCHER_URL", "").strip()
    rancher_token = os.getenv("RANCHER_TOKEN", "").strip()
    aws_region = os.getenv("AWS_REGION", "").strip()
    cluster_ids = parse_cluster_ids()

    if not rancher_url or not rancher_token:
        raise ValueError("Missing Rancher config: RANCHER_URL and/or RANCHER_TOKEN")
    if not aws_region:
        raise ValueError("Missing AWS_REGION")
    if not cluster_ids:
        raise ValueError("Missing target clusters: set CLUSTER_IDS or CLUSTER_ID")

    poll_seconds = int(os.getenv("POLL_SECONDS", "30"))
    grace_seconds = int(os.getenv("GRACE_SECONDS", "180"))
    karpenter_missing_only_grace_seconds = int(
        os.getenv("KARPENTER_MISSING_ONLY_GRACE_SECONDS", str(max(grace_seconds, poll_seconds * 4)))
    )
    return RuntimeConfig(
        rancher=RancherConfig(
            url=rancher_url,
            token=rancher_token,
            verify_tls=not env_bool("INSECURE_SKIP_TLS_VERIFY", False),
            timeout_s=int(os.getenv("RANCHER_TIMEOUT_SECONDS", "30")),
        ),
        cluster_ids=cluster_ids,
        aws_region=aws_region,
        poll_seconds=poll_seconds,
        grace_seconds=grace_seconds,
        karpenter_missing_only_grace_seconds=karpenter_missing_only_grace_seconds,
        aws_missing_consecutive_polls_required=int(os.getenv("AWS_MISSING_CONSECUTIVE_POLLS_REQUIRED", "3")),
        karpenter_missing_consecutive_polls_required=int(
            os.getenv("KARPENTER_MISSING_CONSECUTIVE_POLLS_REQUIRED", "4")
        ),
        stale_tracker_ttl_seconds=int(os.getenv("STALE_TRACKER_TTL_SECONDS", "86400")),
        dry_run=env_bool("DRY_RUN", False),
        enable_delete=env_bool("ENABLE_DELETE", False),
        enable_karpenter_fallback=env_bool("ENABLE_KARPENTER_FALLBACK", False),
        max_deletes_per_loop=int(os.getenv("MAX_DELETES_PER_LOOP", "5")),
        state_configmap=os.getenv("STATE_CONFIGMAP", "cleaner-state").strip(),
        lease_name=os.getenv("LEASE_NAME", "rancher-node-cleaner").strip(),
        lease_namespace=os.getenv("LEASE_NAMESPACE") or os.getenv("POD_NAMESPACE") or "default",
        lease_duration_seconds=int(os.getenv("LEASE_DURATION_SECONDS", "60")),
        ready_stale_after_seconds=int(os.getenv("READY_STALE_AFTER_SECONDS", str(max(120, poll_seconds * 3)))),
        health_port=int(os.getenv("HEALTH_PORT", "8080")),
        metrics_enabled=env_bool("METRICS_ENABLED", True),
        retry=RetryConfig(
            attempts=int(os.getenv("RETRY_ATTEMPTS", "5")),
            initial_backoff_s=float(os.getenv("RETRY_INITIAL_BACKOFF_SECONDS", "0.5")),
            max_backoff_s=float(os.getenv("RETRY_MAX_BACKOFF_SECONDS", "8")),
            jitter_ratio=float(os.getenv("RETRY_JITTER_RATIO", "0.25")),
        ),
    )


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------
def install_signal_handlers() -> None:
    def _handle(signum: int, _frame: Any) -> None:
        logger.warning("received signal=%s, shutting down", signum)
        shutdown_flag.set()
        app_status.set_ready(False, f"shutting-down-{signum}")

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def main() -> int:
    configure_logging(env_bool("VERBOSE", False))
    install_signal_handlers()

    try:
        runtime_cfg = load_runtime_config()
    except Exception as exc:
        logger.error("configuration error: %s", exc)
        return 2

    metrics = Metrics(runtime_cfg.metrics_enabled)
    health_server = HealthServer(
        port=runtime_cfg.health_port,
        metrics=metrics,
        ready_stale_after_seconds=runtime_cfg.ready_stale_after_seconds,
    )
    health_server.start()

    app_status.set_ready(False, "initializing")

    try:
        core, coord = load_incluster_k8s()
        session = build_session()
        ec2 = boto3.client("ec2", region_name=runtime_cfg.aws_region)

        # smoke checks
        read_state(
            core,
            runtime_cfg.lease_namespace,
            runtime_cfg.state_configmap,
            metrics,
            runtime_cfg.retry,
        )
        holder = hostname_identity()
        app_status.set_ready(True, "initialized")
    except Exception as exc:
        logger.error("startup dependency initialization failed: %s", exc)
        app_status.set_ready(False, f"startup-failed:{exc}")
        health_server.stop()
        return 2

    log_event(
        "controller_start",
        clusters=runtime_cfg.cluster_ids,
        poll_seconds=runtime_cfg.poll_seconds,
        grace_seconds=runtime_cfg.grace_seconds,
        karpenter_missing_only_grace_seconds=runtime_cfg.karpenter_missing_only_grace_seconds,
        enable_delete=runtime_cfg.enable_delete,
        enable_karpenter_fallback=runtime_cfg.enable_karpenter_fallback,
        dry_run=runtime_cfg.dry_run,
        lease_namespace=runtime_cfg.lease_namespace,
        lease_name=runtime_cfg.lease_name,
    )

    exit_code = 0

    try:
        while not shutdown_flag.is_set():
            loop_start = utc_now_ts()
            metrics.scans_total.inc()

            try:
                is_leader = try_acquire_or_renew_leadership(
                    coord=coord,
                    namespace=runtime_cfg.lease_namespace,
                    lease_name=runtime_cfg.lease_name,
                    holder=holder,
                    duration_seconds=runtime_cfg.lease_duration_seconds,
                    metrics=metrics,
                    retry_cfg=runtime_cfg.retry,
                )
                app_status.set_leader(is_leader)
                metrics.leader_status.set(1 if is_leader else 0)

                if not is_leader:
                    app_status.set_ready(True, "standby-not-leader")
                    sleep_with_shutdown(runtime_cfg.poll_seconds)
                    continue

                state, state_resource_version = read_state(
                    core,
                    runtime_cfg.lease_namespace,
                    runtime_cfg.state_configmap,
                    metrics,
                    runtime_cfg.retry,
                )
                state_changed = False
                deletes_this_loop = 0
                deleted_count = 0
                seen_keys: Set[str] = set()
                now_ts = utc_now_ts()

                for cluster_id in runtime_cfg.cluster_ids:
                    params = {"clusterId": cluster_id, "limit": 1000}
                    nodes = rancher_get_paginated(
                        session=session,
                        cfg=runtime_cfg.rancher,
                        path="/v3/nodes",
                        params=params,
                        metrics=metrics,
                        retry_cfg=runtime_cfg.retry,
                    )
                    metrics.nodes_seen_total.labels(cluster_id).inc(len(nodes))

                    instance_ids: List[str] = []
                    for node in nodes:
                        extracted = extract_instance_id(node)
                        if extracted:
                            instance_ids.append(extracted)

                    aws_states = classify_instance_states_batched(
                        ec2=ec2,
                        instance_ids=instance_ids,
                        metrics=metrics,
                        retry_cfg=runtime_cfg.retry,
                    )

                    for node in nodes:
                        node_id = (node.get("id") or "").strip()
                        if not node_id:
                            continue

                        decision = build_node_decision(cluster_id, node, aws_states)
                        seen_keys.add(decision.key)

                        if decision.aws_missing:
                            metrics.aws_missing_total.labels(cluster_id).inc()

                        should_track = bool(decision.instance_id) and (decision.aws_missing or bool(decision.rancher_reasons))
                        record: Optional[Dict[str, Any]] = None

                        if should_track:
                            record = update_tracker_record(state, decision, now_ts)
                            state_changed = True
                            metrics.candidates_total.labels(cluster_id, str(decision.is_karpenter).lower()).inc()
                            delete_ok, delete_path = should_delete(decision, record, runtime_cfg, now_ts)
                        else:
                            if decision.key in state:
                                del state[decision.key]
                                state_changed = True
                            if not decision.instance_id:
                                delete_ok, delete_path = False, "no-instance-id"
                            else:
                                delete_ok, delete_path = False, "healthy"

                        metrics.decisions_total.labels("delete" if delete_ok else "keep", delete_path).inc()

                        log_event(
                            "node_evaluation",
                            cluster_id=cluster_id,
                            node_id=node_id,
                            node_name=decision.node_name,
                            instance_id=decision.instance_id,
                            karpenter=decision.is_karpenter,
                            rancher_state=decision.rancher_state,
                            rancher_reasons=decision.rancher_reasons,
                            aws_state=decision.aws_state,
                            aws_missing=decision.aws_missing,
                            aws_missing_count=(record or {}).get("aws_missing_count", 0),
                            delete=delete_ok,
                            decision_path=delete_path,
                        )
                        debug_log_node_evaluation(
                            cluster_id=cluster_id,
                            node_id=node_id,
                            node=node,
                            decision=decision,
                            record=record,
                            should_delete_flag=delete_ok,
                            decision_path=delete_path,
                        )

                        if not delete_ok:
                            continue

                        if deletes_this_loop >= runtime_cfg.max_deletes_per_loop:
                            logger.warning("delete rate limit reached for loop")
                            metrics.deletes_total.labels("rate-limited", delete_path).inc()
                            break

                        if runtime_cfg.dry_run or not runtime_cfg.enable_delete:
                            reason = "dry-run" if runtime_cfg.dry_run else "delete-disabled"
                            logger.warning(
                                "%s: would delete cluster=%s node=%s id=%s instance=%s path=%s",
                                reason,
                                cluster_id,
                                decision.node_name,
                                node_id,
                                decision.instance_id,
                                delete_path,
                            )
                            metrics.deletes_total.labels(reason, delete_path).inc()
                            continue

                        try:
                            result = rancher_delete_node(
                                session=session,
                                cfg=runtime_cfg.rancher,
                                node_id=node_id,
                                metrics=metrics,
                                retry_cfg=runtime_cfg.retry,
                            )
                            metrics.deletes_total.labels(result, delete_path).inc()
                            deleted_count += 1
                            deletes_this_loop += 1
                            if decision.key in state:
                                del state[decision.key]
                            state_changed = True
                            time.sleep(FINALIZER_SLEEP_SECONDS)
                        except Exception as exc:
                            record["delete_attempts"] = int(record.get("delete_attempts") or 0) + 1
                            record["last_delete_error"] = str(exc)
                            metrics.delete_failures_total.labels(type(exc).__name__).inc()
                            metrics.deletes_total.labels("failed", delete_path).inc()
                            logger.error(
                                "failed to delete cluster=%s node=%s id=%s instance=%s path=%s error=%s",
                                cluster_id,
                                decision.node_name,
                                node_id,
                                decision.instance_id,
                                delete_path,
                                exc,
                            )

                if prune_stale_state(state, seen_keys, runtime_cfg.stale_tracker_ttl_seconds, utc_now_ts()):
                    state_changed = True

                if state_changed:
                    state_resource_version = write_state(
                        core,
                        runtime_cfg.lease_namespace,
                        runtime_cfg.state_configmap,
                        state,
                        state_resource_version,
                        metrics,
                        runtime_cfg.retry,
                    )

                metrics.tracked_nodes.set(len(state))
                metrics.last_successful_scan_timestamp.set(time.time())
                metrics.loop_duration_seconds.observe(utc_now_ts() - loop_start)
                app_status.mark_scan_success()
                log_event(
                    "loop_complete",
                    deleted_count=deleted_count,
                    tracked=len(state),
                    leader=True,
                    elapsed_seconds=round(utc_now_ts() - loop_start, 3),
                    state_resource_version=state_resource_version,
                )
            except Exception as exc:
                metrics.scan_failures_total.inc()
                app_status.set_ready(False, f"loop-failed:{type(exc).__name__}")
                logger.exception("loop failed: %s", exc)

            sleep_with_shutdown(runtime_cfg.poll_seconds)
    finally:
        app_status.set_ready(False, "stopped")
        app_status.set_leader(False)
        metrics.leader_status.set(0)
        health_server.stop()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
