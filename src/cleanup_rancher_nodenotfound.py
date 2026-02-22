#!/usr/bin/env python3
"""
cleanup_rancher_nodenotfound.py (controller mode)

Continuously scans Rancher /v3/nodes for NodeNotFound-like nodes and deletes
the Rancher node record if:
  - node has been "bad" continuously for >= GRACE_SECONDS (default 180)
  - AND the corresponding EC2 instance is confirmed missing/terminated in AWS

Designed to run as a Kubernetes Deployment in the *management/local* cluster.

Dependencies:
  pip install requests boto3 kubernetes

Auth / Config:
  Rancher:
    - RANCHER_URL (e.g. https://rancher.example.com)
    - RANCHER_TOKEN (Bearer token)
  Targets:
    - CLUSTER_IDS (comma-separated Rancher cluster IDs, e.g. "c-abcde,c-fghij")
      OR CLUSTER_ID (single cluster id)
  AWS:
    - AWS_REGION (e.g. us-east-1), plus standard boto3 auth (instance role)

Controller behavior:
  - POLL_SECONDS (default 30)
  - GRACE_SECONDS (default 180)
  - DRY_RUN ("true"/"false", default "false")
  - STATE_CONFIGMAP (default "cleaner-state")
  - LEASE_NAME (default "rancher-node-cleaner")
  - LEASE_NAMESPACE (default current namespace via env or "default")

State persistence:
  - Stores bad-since timestamps in a ConfigMap key "bad-nodes.json"
    so restarts/rollouts don't reset the grace timer.

Leader election:
  - Uses coordination.k8s.io Lease. Only the leader performs deletions.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Kubernetes client (in-cluster)
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from http.server import BaseHTTPRequestHandler, HTTPServer


INSTANCE_ID_RE = re.compile(r"\b(i-[0-9a-f]{8,17})\b")


# --------------------------
# Small health server
# --------------------------
class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/healthz", "/readyz"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()

    # reduce noisy logs
    def log_message(self, format, *args):
        return


def start_health_server(port: int = 8080) -> None:
    def _run():
        httpd = HTTPServer(("0.0.0.0", port), _HealthHandler)
        httpd.serve_forever()

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# --------------------------
# Config
# --------------------------
@dataclass
class RancherConfig:
    url: str
    token: str
    verify_tls: bool = True
    timeout_s: int = 30


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
        # Handles "2026-02-22T06:12:30Z"
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


# --------------------------
# HTTP session to Rancher
# --------------------------
def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=8,
        connect=8,
        read=8,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "DELETE"]),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s


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
    params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    url = cfg.url.rstrip("/") + path
    items: List[Dict[str, Any]] = []
    while True:
        r = session.get(
            url,
            headers=rancher_headers(cfg.token),
            params=params,
            timeout=cfg.timeout_s,
            verify=cfg.verify_tls,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Rancher GET failed {r.status_code}: {r.text}")
        payload = r.json()
        items.extend(payload.get("data", []) or [])
        next_url = (payload.get("pagination") or {}).get("next")
        if not next_url:
            break
        url = next_url
        params = None
    return items


def rancher_delete_node(session: requests.Session, cfg: RancherConfig, node_id: str) -> None:
    url = cfg.url.rstrip("/") + f"/v3/nodes/{node_id}"
    r = session.delete(
        url,
        headers=rancher_headers(cfg.token),
        timeout=cfg.timeout_s,
        verify=cfg.verify_tls,
    )
    if r.status_code not in (200, 202, 204):
        raise RuntimeError(f"Rancher DELETE node {node_id} failed {r.status_code}: {r.text}")


# --------------------------
# Node detection/extraction
# --------------------------
def node_is_bad(node: Dict[str, Any]) -> bool:
    """
    "Bad" means: very likely NodeNotFound-ish / orphaned.

    Rancher varies, but common signals:
      - state == "nodenotfound"
      - conditions/messages contain "nodenotfound"
      - transitioningMessage / message contains "nodenotfound"
    """
    state = (node.get("state") or "").lower()
    if state == "nodenotfound":
        return True

    # Some clusters won't use "state" but will surface it in message fields
    for k in ("transitioningMessage", "message", "status"):
        v = node.get(k)
        if isinstance(v, str) and "nodenotfound" in v.lower():
            return True

    # Conservative fallback: conditions blob contains nodenotfound
    try:
        cond_blob = json.dumps(node.get("conditions", ""), default=str).lower()
        if "nodenotfound" in cond_blob:
            return True
    except Exception:
        pass

    return False


def extract_instance_id(node: Dict[str, Any]) -> Optional[str]:
    candidates: List[str] = []

    for k in ("providerId", "providerID", "provider_id"):
        v = node.get(k)
        if isinstance(v, str) and v:
            candidates.append(v)

    node_spec = node.get("nodeSpec") or node.get("node_spec") or {}
    if isinstance(node_spec, dict):
        for k in ("providerID", "providerId", "provider_id"):
            v = node_spec.get(k)
            if isinstance(v, str) and v:
                candidates.append(v)

    labels = node.get("labels") or {}
    if isinstance(labels, dict):
        for lk in ("cattle.io/instance-id", "node.kubernetes.io/instance-id"):
            v = labels.get(lk)
            if isinstance(v, str) and v:
                candidates.append(v)

    annotations = node.get("annotations") or {}
    if isinstance(annotations, dict):
        for ak in ("rke.cattle.io/external-id", "cattle.io/external-id", "cluster.x-k8s.io/provider-id"):
            v = annotations.get(ak)
            if isinstance(v, str) and v:
                candidates.append(v)

    for k in ("name", "hostname", "nodeName"):
        v = node.get(k)
        if isinstance(v, str) and v:
            candidates.append(v)

    blob = " | ".join(candidates)
    m = INSTANCE_ID_RE.search(blob)
    return m.group(1) if m else None


# --------------------------
# AWS checks
# --------------------------
def ec2_instance_missing_or_terminated(ec2, instance_id: str) -> bool:
    """
    True if instance is definitely gone or terminated.
    - InvalidInstanceID.NotFound -> gone
    - state == terminated -> treat as delete-safe
    False otherwise.
    """
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        # If AWS knows the ID, inspect state
        reservations = resp.get("Reservations") or []
        for res in reservations:
            for inst in (res.get("Instances") or []):
                if inst.get("InstanceId") == instance_id:
                    state = (inst.get("State") or {}).get("Name", "")
                    return state.lower() == "terminated"
        # If weird empty response but no error, be conservative
        return False
    except botocore.exceptions.ClientError as e:
        code = (e.response.get("Error") or {}).get("Code", "")
        if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            return True
        raise


# --------------------------
# K8s state: ConfigMap
# --------------------------
STATE_KEY = "bad-nodes.json"


def load_incluster_k8s() -> Tuple[client.CoreV1Api, client.CoordinationV1Api]:
    # Works in cluster; if running locally for testing, falls back to kubeconfig
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.CoreV1Api(), client.CoordinationV1Api()


def get_or_create_state_configmap(core: client.CoreV1Api, namespace: str, name: str) -> client.V1ConfigMap:
    try:
        return core.read_namespaced_config_map(name=name, namespace=namespace)
    except ApiException as e:
        if e.status != 404:
            raise
    cm = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        data={STATE_KEY: "{}"},
    )
    return core.create_namespaced_config_map(namespace=namespace, body=cm)


def read_state(core: client.CoreV1Api, namespace: str, name: str) -> Dict[str, str]:
    cm = get_or_create_state_configmap(core, namespace, name)
    raw = (cm.data or {}).get(STATE_KEY) or "{}"
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            # values are ISO timestamps
            return {str(k): str(v) for k, v in obj.items()}
    except Exception:
        pass
    return {}


def write_state(core: client.CoreV1Api, namespace: str, name: str, state: Dict[str, str]) -> None:
    cm = get_or_create_state_configmap(core, namespace, name)
    cm.data = cm.data or {}
    cm.data[STATE_KEY] = json.dumps(state, sort_keys=True)
    # optimistic replace (simple + good enough here)
    core.replace_namespaced_config_map(name=name, namespace=namespace, body=cm)


# --------------------------
# K8s leader election: Lease
# --------------------------
def hostname_identity() -> str:
    # stable-ish identity for holder
    return f"{socket.gethostname()}-{os.getpid()}"


def ensure_lease(
    coord: client.CoordinationV1Api,
    namespace: str,
    lease_name: str,
    duration_seconds: int,
) -> client.V1Lease:
    try:
        return coord.read_namespaced_lease(name=lease_name, namespace=namespace)
    except ApiException as e:
        if e.status != 404:
            raise

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


def try_acquire_or_renew_leadership(
    coord: client.CoordinationV1Api,
    namespace: str,
    lease_name: str,
    holder: str,
    duration_seconds: int,
) -> bool:
    """
    Simple leader election:
      - If lease is empty or expired -> claim it
      - If held by us -> renew
      - Else -> not leader
    """
    lease = ensure_lease(coord, namespace, lease_name, duration_seconds)
    spec = lease.spec or client.V1LeaseSpec()

    now = datetime.now(timezone.utc)
    renew_time = spec.renew_time
    holder_identity = spec.holder_identity or ""

    expired = True
    if renew_time:
        # renew_time might be str depending on client version; handle both
        if isinstance(renew_time, str):
            try:
                rt = datetime.fromisoformat(renew_time.replace("Z", "+00:00"))
            except Exception:
                rt = None
        else:
            rt = renew_time
        if rt:
            expired = (now - rt).total_seconds() > duration_seconds

    if (not holder_identity) or expired or holder_identity == holder:
        # claim/renew
        spec.holder_identity = holder
        spec.lease_duration_seconds = duration_seconds
        spec.renew_time = now.isoformat()
        if not spec.acquire_time:
            spec.acquire_time = now.isoformat()
        lease.spec = spec
        try:
            coord.replace_namespaced_lease(name=lease_name, namespace=namespace, body=lease)
            return True
        except ApiException as e:
            logging.warning("Lease update failed (%s). Not leader this round.", e)
            return False

    return False


# --------------------------
# Controller loop
# --------------------------
def parse_cluster_ids() -> List[str]:
    # Prefer CLUSTER_IDS, fallback to CLUSTER_ID
    ids = os.getenv("CLUSTER_IDS", "").strip()
    if ids:
        return [x.strip() for x in ids.split(",") if x.strip()]
    single = os.getenv("CLUSTER_ID", "").strip()
    return [single] if single else []


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG if env_bool("VERBOSE", False) else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    start_health_server(port=int(os.getenv("HEALTH_PORT", "8080")))

    rancher_url = os.getenv("RANCHER_URL", "").strip()
    rancher_token = os.getenv("RANCHER_TOKEN", "").strip()
    aws_region = os.getenv("AWS_REGION", "").strip()

    cluster_ids = parse_cluster_ids()
    poll_seconds = int(os.getenv("POLL_SECONDS", "30"))
    grace_seconds = int(os.getenv("GRACE_SECONDS", "180"))
    dry_run = env_bool("DRY_RUN", False)

    state_cm = os.getenv("STATE_CONFIGMAP", "cleaner-state").strip()
    lease_name = os.getenv("LEASE_NAME", "rancher-node-cleaner").strip()
    lease_ns = os.getenv("LEASE_NAMESPACE") or os.getenv("POD_NAMESPACE") or "default"
    lease_duration = int(os.getenv("LEASE_DURATION_SECONDS", "60"))  # should be > poll interval

    insecure_skip_tls_verify = env_bool("INSECURE_SKIP_TLS_VERIFY", False)

    if not rancher_url or not rancher_token:
        logging.error("Missing Rancher config: RANCHER_URL and/or RANCHER_TOKEN.")
        return 2
    if not cluster_ids:
        logging.error("Missing target clusters: set CLUSTER_IDS or CLUSTER_ID.")
        return 2
    if not aws_region:
        logging.error("Missing AWS_REGION.")
        return 2

    cfg = RancherConfig(
        url=rancher_url,
        token=rancher_token,
        verify_tls=not insecure_skip_tls_verify,
        timeout_s=int(os.getenv("RANCHER_TIMEOUT_SECONDS", "30")),
    )

    # AWS client
    ec2 = boto3.client("ec2", region_name=aws_region)

    # HTTP session
    session = build_session()

    # Kubernetes clients
    core, coord = load_incluster_k8s()

    holder = hostname_identity()
    logging.info(
        "Starting rancher-node-cleaner: clusters=%s poll=%ss grace=%ss dry_run=%s lease=%s/%s",
        ",".join(cluster_ids),
        poll_seconds,
        grace_seconds,
        dry_run,
        lease_ns,
        lease_name,
    )

    while True:
        is_leader = try_acquire_or_renew_leadership(
            coord=coord,
            namespace=lease_ns,
            lease_name=lease_name,
            holder=holder,
            duration_seconds=lease_duration,
        )

        if not is_leader:
            logging.debug("Not leader. Sleeping %ss.", poll_seconds)
            time.sleep(poll_seconds)
            continue

        loop_start = utc_now_ts()
        try:
            state = read_state(core, lease_ns, state_cm)
        except Exception as e:
            logging.error("Failed to read state ConfigMap %s/%s: %s", lease_ns, state_cm, e)
            state = {}

        state_changed = False
        deleted_count = 0

        for cluster_id in cluster_ids:
            params = {"clusterId": cluster_id, "limit": 1000}
            try:
                nodes = rancher_get_paginated(session, cfg, "/v3/nodes", params=params)
            except Exception as e:
                logging.error("Failed to list Rancher nodes for clusterId=%s: %s", cluster_id, e)
                continue

            # Build a set of currently-bad node keys so we can prune recovered ones
            bad_keys_this_round: set[str] = set()

            for node in nodes:
                if not node_is_bad(node):
                    continue

                node_id = (node.get("id") or "").strip()
                if not node_id:
                    continue

                node_name = node.get("name") or node.get("hostname") or node_id
                instance_id = extract_instance_id(node)

                # Key includes cluster to avoid collisions across clusters
                key = f"{cluster_id}:{node_id}"
                bad_keys_this_round.add(key)

                if not instance_id:
                    logging.warning(
                        "Bad node detected but no instance id extracted; skipping. cluster=%s node=%s id=%s",
                        cluster_id, node_name, node_id
                    )
                    # We do NOT start the grace timer because we can't safely delete without instance proof
                    if key in state:
                        del state[key]
                        state_changed = True
                    continue

                now = utc_now_ts()
                if key not in state:
                    state[key] = utc_iso(now)
                    state_changed = True
                    logging.info(
                        "Marked bad_since for node. cluster=%s node=%s id=%s instance=%s bad_since=%s",
                        cluster_id, node_name, node_id, instance_id, state[key]
                    )

                bad_since_ts = parse_iso_to_ts(state.get(key, "")) or now
                age = now - bad_since_ts

                if age < grace_seconds:
                    logging.debug(
                        "Grace not met yet. cluster=%s node=%s id=%s age=%.1fs/%ss",
                        cluster_id, node_name, node_id, age, grace_seconds
                    )
                    continue

                # Grace met -> verify with AWS
                try:
                    missing_or_terminated = ec2_instance_missing_or_terminated(ec2, instance_id)
                except Exception as e:
                    logging.error(
                        "AWS check failed. cluster=%s node=%s id=%s instance=%s err=%s",
                        cluster_id, node_name, node_id, instance_id, e
                    )
                    continue

                if not missing_or_terminated:
                    logging.info(
                        "AWS says instance still exists (or not terminated). Not deleting. cluster=%s node=%s id=%s instance=%s",
                        cluster_id, node_name, node_id, instance_id
                    )
                    # If it exists, we should remove from state so it needs to be bad for a full grace again
                    if key in state:
                        del state[key]
                        state_changed = True
                    continue

                if dry_run:
                    logging.warning(
                        "[DRY-RUN] Would delete Rancher node. cluster=%s node=%s id=%s instance=%s age=%.1fs",
                        cluster_id, node_name, node_id, instance_id, age
                    )
                    continue

                # Delete node in Rancher
                try:
                    logging.warning(
                        "Deleting Rancher node. cluster=%s node=%s id=%s instance=%s age=%.1fs",
                        cluster_id, node_name, node_id, instance_id, age
                    )
                    rancher_delete_node(session, cfg, node_id)
                    deleted_count += 1
                    # Remove from state after delete
                    if key in state:
                        del state[key]
                        state_changed = True
                    time.sleep(0.2)
                except Exception as e:
                    logging.error(
                        "Failed to delete Rancher node. cluster=%s node=%s id=%s err=%s",
                        cluster_id, node_name, node_id, e
                    )

            # Prune state for nodes that recovered (no longer bad)
            # Only prune entries for this cluster.
            keys_to_prune = [k for k in state.keys() if k.startswith(cluster_id + ":") and k not in bad_keys_this_round]
            if keys_to_prune:
                for k in keys_to_prune:
                    del state[k]
                state_changed = True

        # Persist state if changed
        if state_changed:
            try:
                write_state(core, lease_ns, state_cm, state)
            except Exception as e:
                logging.error("Failed to write state ConfigMap %s/%s: %s", lease_ns, state_cm, e)

        elapsed = utc_now_ts() - loop_start
        logging.info("Loop done. leader=%s deleted=%d state_entries=%d elapsed=%.2fs", True, deleted_count, len(state), elapsed)

        # Sleep until next poll (simple)
        time.sleep(poll_seconds)

    # unreachable
    # return 0


if __name__ == "__main__":
    raise SystemExit(main())