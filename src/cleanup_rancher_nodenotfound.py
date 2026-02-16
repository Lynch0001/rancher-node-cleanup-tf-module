#!/usr/bin/env python3
"""
cleanup_rancher_nodenotfound.py

Checks a Rancher-managed RKE2 cluster for nodes in NodeNotFound state and,
if the corresponding EC2 instance no longer exists, deletes the Rancher node.

Requirements:
  pip install requests boto3

Auth:
  - Rancher: RANCHER_URL + RANCHER_TOKEN (API Key token) + CLUSTER_ID
  - AWS: standard boto3 auth (env vars, profile, instance role, etc.)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


INSTANCE_ID_RE = re.compile(r"\b(i-[0-9a-f]{8,17})\b")


@dataclass
class RancherConfig:
    url: str
    token: str
    cluster_id: str
    verify_tls: bool = True
    timeout_s: int = 30


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
    # Rancher API Key tokens are usually used as:
    # Authorization: Bearer <token>
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
    """
    Rancher v3 APIs commonly return: { data: [...], pagination: { next: "..." } }
    """
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
        data = payload.get("data", [])
        items.extend(data)

        next_url = payload.get("pagination", {}).get("next")
        if not next_url:
            break
        # 'next' is usually a full URL
        url = next_url
        params = None  # already encoded in next_url
    return items


def rancher_delete(
    session: requests.Session,
    cfg: RancherConfig,
    node_id: str,
) -> None:
    url = cfg.url.rstrip("/") + f"/v3/nodes/{node_id}"
    r = session.delete(
        url,
        headers=rancher_headers(cfg.token),
        timeout=cfg.timeout_s,
        verify=cfg.verify_tls,
    )
    if r.status_code not in (200, 202, 204):
        raise RuntimeError(f"Rancher DELETE node {node_id} failed {r.status_code}: {r.text}")


def node_is_nodenotfound(node: Dict[str, Any]) -> bool:
    """
    Rancher node objects can expose state in a couple ways depending on version.
    Typical: node['state'] == 'nodenotfound'
    Sometimes: node['transitioning'] / conditions.
    """
    state = (node.get("state") or "").lower()
    if state == "nodenotfound":
        return True

    # Fallback: look for conditions/messages that contain nodenotfound
    # (kept conservative to avoid deleting wrong nodes)
    msg = json.dumps(node.get("conditions", ""), default=str).lower()
    if "nodenotfound" in msg:
        return True

    return False


def extract_instance_id(node: Dict[str, Any]) -> Optional[str]:
    """
    Try hard to find the EC2 instance id for a Rancher node.

    Common places:
      - node['providerId'] (or providerID) like: aws:///us-east-1a/i-0123456789abcdef0
      - node['nodeSpec']['providerID'] (varies)
      - node['labels'] / annotations sometimes include instance id
      - node['name'] or hostname might include i-... (less common)
    """
    candidates: List[str] = []

    for k in ("providerId", "providerID", "provider_id"):
        v = node.get(k)
        if isinstance(v, str) and v:
            candidates.append(v)

    # Some Rancher objects put more under "nodeSpec" or "nodeTemplateSpec"
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
        for ak in (
            "rke.cattle.io/external-id",
            "cattle.io/external-id",
            "cluster.x-k8s.io/provider-id",
        ):
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


def ec2_instance_exists(ec2, instance_id: str) -> bool:
    """
    Returns True if DescribeInstances finds the instance, even if stopped/terminated.
    Returns False if AWS says it's not found.
    """
    try:
        # DescribeInstances returns terminated instances for a while too;
        # "exists" here means "ID is known to AWS" (still a strong signal to NOT delete in Rancher).
        ec2.describe_instances(InstanceIds=[instance_id])
        return True
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            return False
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete Rancher nodes in NodeNotFound state when their EC2 instance no longer exists."
    )
    parser.add_argument("--rancher-url", default=os.getenv("RANCHER_URL"), help="e.g. https://rancher.example.com")
    parser.add_argument("--rancher-token", default=os.getenv("RANCHER_TOKEN"), help="Rancher API token (Bearer)")
    parser.add_argument("--cluster-id", default=os.getenv("CLUSTER_ID"), help="Rancher cluster ID (e.g. c-m-xxxxx)")
    parser.add_argument("--aws-region", default=os.getenv("AWS_REGION"), help="AWS region (e.g. us-east-1)")
    parser.add_argument("--aws-profile", default=os.getenv("AWS_PROFILE"), help="Optional AWS profile name")
    parser.add_argument("--insecure-skip-tls-verify", action="store_true", help="Skip TLS verification to Rancher")
    parser.add_argument("--dry-run", action="store_true", help="Do not delete, only print actions")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.rancher_url or not args.rancher_token or not args.cluster_id:
        logging.error("Missing Rancher config. Provide --rancher-url, --rancher-token, --cluster-id (or env vars).")
        return 2
    if not args.aws_region:
        logging.error("Missing AWS region. Provide --aws-region (or AWS_REGION env var).")
        return 2

    cfg = RancherConfig(
        url=args.rancher_url,
        token=args.rancher_token,
        cluster_id=args.cluster_id,
        verify_tls=not args.insecure_skip_tls_verify,
    )

    # AWS client
    if args.aws_profile:
        boto3.setup_default_session(profile_name=args.aws_profile, region_name=args.aws_region)
    ec2 = boto3.client("ec2", region_name=args.aws_region)

    session = build_session()

    # Pull nodes for this cluster. Rancher v3 nodes support clusterId filtering.
    # Using a broad fetch + local filter keeps compatibility if server ignores filters.
    params = {"clusterId": cfg.cluster_id, "limit": 1000}
    logging.info("Fetching Rancher nodes for clusterId=%s ...", cfg.cluster_id)
    nodes = rancher_get_paginated(session, cfg, "/v3/nodes", params=params)
    logging.info("Found %d total nodes in Rancher response.", len(nodes))

    candidates: List[Tuple[str, str, Optional[str]]] = []
    for node in nodes:
        if not node_is_nodenotfound(node):
            continue
        node_id = node.get("id") or ""
        node_name = node.get("name") or node.get("hostname") or node_id
        instance_id = extract_instance_id(node)
        candidates.append((node_id, node_name, instance_id))

    if not candidates:
        logging.info("No NodeNotFound nodes detected. Nothing to do.")
        return 0

    logging.info("Detected %d NodeNotFound nodes.", len(candidates))

    deleted = 0
    skipped_no_instance_id = 0
    skipped_exists = 0

    for node_id, node_name, instance_id in candidates:
        if not node_id:
            logging.warning("Skipping node with no id (name=%s).", node_name)
            continue
        if not instance_id:
            skipped_no_instance_id += 1
            logging.warning(
                "Skipping NodeNotFound node=%s (id=%s): could not extract EC2 instance id.",
                node_name,
                node_id,
            )
            continue

        logging.info("Checking AWS for node=%s (id=%s) instance_id=%s ...", node_name, node_id, instance_id)
        exists = ec2_instance_exists(ec2, instance_id)
        if exists:
            skipped_exists += 1
            logging.info("AWS instance exists (%s). Not deleting Rancher node %s.", instance_id, node_name)
            continue

        # If instance truly not found -> delete Rancher node
        if args.dry_run:
            logging.info("[DRY-RUN] Would delete Rancher node=%s (id=%s) for missing instance_id=%s", node_name, node_id, instance_id)
            continue

        logging.warning("Deleting Rancher node=%s (id=%s): instance_id=%s not found in AWS", node_name, node_id, instance_id)
        rancher_delete(session, cfg, node_id)
        deleted += 1

        # Gentle pacing; Rancher sometimes needs a moment to reconcile deletions
        time.sleep(0.3)

    logging.info(
        "Done. deleted=%d skipped_exists=%d skipped_no_instance_id=%d dry_run=%s",
        deleted,
        skipped_exists,
        skipped_no_instance_id,
        args.dry_run,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())