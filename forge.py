#!/usr/bin/env python3
"""
Forge — AWS / Azure / GCP cloud control-plane security auditor.

Token protocol (emitted on stdout for Crucible-style managers):
  __CRUCIBLE_LOG__     <message>
  __CRUCIBLE_ERR__     <message>
  __CRUCIBLE_STATUS__  <json>
  __CRUCIBLE_FINDING__ <json>

Run direct (CLI) or under a Flask manager that sets CRUCIBLE_MANAGED=1
to switch outputs to token mode.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None

try:
    import pr0t31n_event_log as _el
except ImportError:
    _el = None

try:
    from pr0t31n_pause import PauseManager as _PP
except ImportError:
    _PP = None

_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_findings: list = []

_RUN_DIR: Optional[Path] = None
_RUNLOG = None
_pause = None

_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]


def _check_pause():
    if _pause is not None and _pause.check_and_pause():
        sys.exit(42)


def _rel(p) -> str:
    if not p:
        return ""
    if _us is not None and _RUN_DIR is not None:
        try:
            r = _us.to_relative_output_file(p, str(_RUN_DIR))
            if r:
                return r
        except Exception:
            pass
    return str(p)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        ts = datetime.now().isoformat()
        print(f"{token}:[{ts}] {msg}", flush=True)
    else:
        print(f"[{_ts()}] {msg}", flush=True)


def log(msg: str) -> None:
    _tok("__CRUCIBLE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__CRUCIBLE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    rec = {"phase": phase, "label": label, "state": state, "step": step}
    _tok("__CRUCIBLE_STATUS__", json.dumps(rec))


def finding(*, title: str, severity: str, description: str, ip: str = "",
             port: int = 0, data: dict | None = None,
             output_file: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    if _us is not None:
        rec = _us.make_finding(
            tool="forge", title=title, risk=severity.upper(),
            description=description, ip=ip, port=port,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=(data or {}).get("affected", ""),
            remediation=(data or {}).get("remediation", ""),
            sources="forge", catalogue_id=(data or {}).get("catalogue_id", ""),
        )
    else:
        rec = {
            "id": str(uuid.uuid4()),
            "tool": "forge",
            "title": title,
            "risk": severity.upper(),
            "description": description,
            "ip": ip, "port": port,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "output_file": of_rel,
            "data": data or {},
        }
    _findings.append(rec)
    _tok("__CRUCIBLE_FINDING__", json.dumps(rec))


def _save_checkpoint():
    if _RUN_DIR is None:
        return
    try:
        cp = {
            "findings_count": len(_findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        (_RUN_DIR / "checkpoint.json").write_text(
            json.dumps(cp, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── Azure auditor ─────────────────────────────────────────────────────────────

def audit_azure(subscription_id: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[azure] Starting Azure audit — subscription {subscription_id}")
    status("azure", "Azure Subscription Audit", "running")
    az = shutil.which("az")
    if not az:
        err("az CLI not installed — skipping Azure audit")
        status("azure", "Azure Subscription Audit", "skipped")
        return
    log(f"[azure] az CLI found at {az}")

    out_dir = output_dir / "azure"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _az_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [az] + args + ["--subscription", subscription_id, "--output", "json"]
        log(f"[azure] Running: az {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="az",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"az {args[0] if args else '?'} failed: {exc}")
            return None

    _save_checkpoint()
    log("[azure] Enumerating storage accounts...")
    accounts = _az_run(["storage", "account", "list"], "storage_accounts.json") or []
    log(f"[azure] Found {len(accounts)} storage account(s)")
    _check_pause()
    for acct in accounts:
        name = acct.get("name", "")
        rg   = acct.get("resourceGroup", "")
        log(f"[azure] Checking storage account {name} (rg={rg})...")
        if acct.get("enableHttpsTrafficOnly") is False:
            log(f"[azure] {name} — HTTPS-only disabled (HIGH)")
            finding(title=f"Azure Storage: Azure Storage Account allows HTTP: {name}",
                     severity="HIGH",
                     description=("Storage account does not enforce HTTPS-only. "
                                   "Data in transit may traverse plaintext."),
                     data={"catalogue_id": "FORGE-AZ-001",
                           "affected": f"{rg}/{name}",
                           "remediation": "az storage account update --https-only true"},
                     output_file=str(out_dir / "storage_accounts.json"))
        else:
            log(f"[azure] {name} — HTTPS-only OK")
        net_acl = (acct.get("networkRuleSet") or {}).get("defaultAction", "")
        if net_acl == "Allow":
            log(f"[azure] {name} — network ACL defaults to Allow (HIGH)")
            finding(title=f"Azure Storage: Azure Storage Account publicly accessible: {name}",
                     severity="HIGH",
                     description=("Storage account network ACL defaults to Allow "
                                   "(no IP restrictions configured)."),
                     data={"catalogue_id": "FORGE-AZ-002",
                           "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "storage_accounts.json"))
        else:
            log(f"[azure] {name} — network ACL: {net_acl}")

    _check_pause()
    _save_checkpoint()
    log("[azure] Enumerating key vaults...")
    vaults = _az_run(["keyvault", "list"], "keyvaults.json") or []
    log(f"[azure] Found {len(vaults)} key vault(s)")
    _check_pause()
    for kv in vaults:
        name = kv.get("name", "")
        props = kv.get("properties") or {}
        log(f"[azure] Checking key vault {name}...")
        if not props.get("enableSoftDelete", True):
            log(f"[azure] {name} — soft-delete disabled (MEDIUM)")
            finding(title=f"Azure Key Vault: Azure Key Vault soft-delete disabled: {name}",
                     severity="MEDIUM",
                     description="Soft-delete not enabled — accidental deletions are unrecoverable.",
                     data={"catalogue_id": "FORGE-AZ-010", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))
        if not props.get("enablePurgeProtection"):
            log(f"[azure] {name} — purge-protection disabled (MEDIUM)")
            finding(title=f"Azure Key Vault: Azure Key Vault purge-protection disabled: {name}",
                     severity="MEDIUM",
                     description="Purge-protection disabled — soft-deleted keys can be purged immediately.",
                     data={"catalogue_id": "FORGE-AZ-011", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))
        if props.get("enableSoftDelete", True) and props.get("enablePurgeProtection"):
            log(f"[azure] {name} — soft-delete + purge-protection OK")

    _check_pause()
    _save_checkpoint()
    log("[azure] Enumerating virtual machines...")
    vms = _az_run(["vm", "list"], "vms.json") or []
    log(f"[azure] Found {len(vms)} VM(s)")
    _check_pause()
    for vm in vms:
        name = vm.get("name", "")
        rg   = vm.get("resourceGroup", "")
        log(f"[azure] Checking VM {name} (rg={rg})...")
        sd   = (vm.get("storageProfile") or {}).get("osDisk") or {}
        enc  = (sd.get("encryptionSettings") or {}).get("enabled") if sd else None
        if enc is False:
            log(f"[azure] {name} — OS disk unencrypted (HIGH)")
            finding(title=f"Azure VM: Azure VM OS disk unencrypted: {name}",
                     severity="HIGH",
                     description="Azure Disk Encryption (ADE) is disabled on the OS disk.",
                     data={"catalogue_id": "FORGE-AZ-020", "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "vms.json"))
        else:
            log(f"[azure] {name} — disk encryption OK")

    log(f"[azure] Azure audit complete — subscription {subscription_id}")
    status("azure", "Azure Subscription Audit", "complete")


# ── GCP auditor ───────────────────────────────────────────────────────────────

def audit_gcp(project_id: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[gcp] Starting GCP audit — project {project_id}")
    status("gcp", "GCP Project Audit", "running")
    gcloud = shutil.which("gcloud")
    if not gcloud:
        err("gcloud CLI not installed — skipping GCP audit")
        status("gcp", "GCP Project Audit", "skipped")
        return
    log(f"[gcp] gcloud CLI found at {gcloud}")

    out_dir = output_dir / "gcp"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _g_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [gcloud] + args + ["--project", project_id, "--format=json"]
        log(f"[gcp] Running: gcloud {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="gcloud",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"gcloud {' '.join(args[:2])} failed: {exc}")
            return None

    _save_checkpoint()
    log("[gcp] Enumerating GCS buckets...")
    buckets = _g_run(["storage", "buckets", "list"], "buckets.json") or []
    log(f"[gcp] Found {len(buckets)} bucket(s)")
    _check_pause()
    for b in buckets:
        name = b.get("name", "")
        log(f"[gcp] Checking bucket {name}...")
        iam_cfg = (b.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}
        if not iam_cfg.get("enabled"):
            log(f"[gcp] {name} — uniform access disabled (MEDIUM)")
            finding(title=f"GCS: GCS bucket uniform access disabled: {name}",
                     severity="MEDIUM",
                     description="Uniform bucket-level access disabled — legacy ACLs may grant unintended access.",
                     data={"catalogue_id": "FORGE-GCP-001", "affected": name},
                     output_file=str(out_dir / "buckets.json"))
        else:
            log(f"[gcp] {name} — uniform access OK")

    _check_pause()
    _save_checkpoint()
    log("[gcp] Enumerating compute instances...")
    instances = _g_run(["compute", "instances", "list"], "instances.json") or []
    log(f"[gcp] Found {len(instances)} instance(s)")
    _check_pause()
    for inst in instances:
        _check_pause()
        name = inst.get("name", "")
        log(f"[gcp] Checking instance {name}...")
        sas  = inst.get("serviceAccounts") or []
        for sa in sas:
            email = sa.get("email", "")
            if "compute@developer.gserviceaccount.com" in email:
                log(f"[gcp] {name} — uses default service account {email} (MEDIUM)")
                finding(title=f"GCE: GCE instance uses default service account: {name}",
                         severity="MEDIUM",
                         description="Default Compute Engine service account grants over-broad scopes.",
                         data={"catalogue_id": "FORGE-GCP-010",
                               "affected": name,
                               "service_account": email},
                         output_file=str(out_dir / "instances.json"))
        for iface in inst.get("networkInterfaces", []):
            if iface.get("accessConfigs"):
                log(f"[gcp] {name} — has external IP (INFO)")
                finding(title=f"GCE: GCE instance has public IP: {name}",
                         severity="INFO",
                         description="Instance has an ephemeral or static external IP configured.",
                         data={"catalogue_id": "FORGE-GCP-011",
                               "affected": name},
                         output_file=str(out_dir / "instances.json"))

    _check_pause()
    _save_checkpoint()
    log("[gcp] Retrieving IAM policy...")
    iam = _g_run(["projects", "get-iam-policy", project_id], "iam_policy.json") or {}
    bindings = iam.get("bindings", []) or []
    log(f"[gcp] IAM policy has {len(bindings)} binding(s)")
    _check_pause()
    for binding in bindings:
        role = binding.get("role", "")
        if role in ("roles/owner", "roles/editor"):
            for member in binding.get("members", []) or []:
                if member.startswith("user:") or member.startswith("serviceAccount:"):
                    sev = "HIGH" if role == "roles/owner" else "MEDIUM"
                    log(f"[gcp] {member} — project-level {role} ({sev})")
                    finding(title=f"GCP: GCP project-level {role} granted to {member}",
                             severity=sev,
                             description=("Over-privileged role granted at project level. "
                                           "Prefer per-resource or custom roles."),
                             data={"catalogue_id": "FORGE-GCP-020",
                                   "affected": member,
                                   "role": role},
                             output_file=str(out_dir / "iam_policy.json"))

    log(f"[gcp] GCP audit complete — project {project_id}")
    status("gcp", "GCP Project Audit", "complete")


# ── AWS auditor ───────────────────────────────────────────────────────────────

def audit_aws(profile: str, region: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[aws] Starting AWS audit — profile={profile or 'default'}, region={region or 'default'}")
    status("aws", "AWS Account Audit", "running")
    aws = shutil.which("aws")
    if not aws:
        err("aws CLI not installed — skipping AWS audit")
        status("aws", "AWS Account Audit", "skipped")
        return
    log(f"[aws] aws CLI found at {aws}")

    out_dir = output_dir / "aws"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _aws_run(args: list, out_name: str, use_region: bool = True) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [aws] + args + ["--output", "json"]
        if profile:
            cmd += ["--profile", profile]
        if use_region and region:
            cmd += ["--region", region]
        log(f"[aws] Running: aws {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="aws",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"aws {' '.join(args[:2])} failed: {exc}")
            return None

    # ── S3 ────────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting S3 bucket audit...")
    status("aws", "S3 bucket audit", "running")
    buckets_resp = _aws_run(["s3api", "list-buckets"], "s3_buckets.json", use_region=False) or {}
    buckets = buckets_resp.get("Buckets") or []
    log(f"[aws] Found {len(buckets)} S3 bucket(s)")
    _check_pause()
    for bucket in buckets:
        _check_pause()
        name = bucket.get("Name", "")
        log(f"[aws] Checking S3 bucket {name}...")

        log(f"[aws] {name} — checking public access block...")
        pab = _aws_run(["s3api", "get-public-access-block", "--bucket", name],
                        f"s3_{name}_public_access.json", use_region=False) or {}
        pab_cfg = pab.get("PublicAccessBlockConfiguration") or {}
        if not pab_cfg:
            log(f"[aws] {name} — no public access block configured (HIGH)")
            finding(title=f"S3 bucket missing public access block: {name}",
                     severity="HIGH",
                     description="No S3 public access block configured — objects may be publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-001", "affected": name,
                           "remediation": "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))
        elif not all(pab_cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                "BlockPublicPolicy", "RestrictPublicBuckets")):
            log(f"[aws] {name} — incomplete public access block (MEDIUM)")
            finding(title=f"S3 bucket incomplete public access block: {name}",
                     severity="MEDIUM",
                     description="Not all four public access block settings are enabled.",
                     data={"catalogue_id": "FORGE-AWS-002", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))
        else:
            log(f"[aws] {name} — public access block OK")

        log(f"[aws] {name} — checking versioning...")
        versioning = _aws_run(["s3api", "get-bucket-versioning", "--bucket", name],
                               f"s3_{name}_versioning.json", use_region=False) or {}
        if versioning.get("Status") != "Enabled":
            log(f"[aws] {name} — versioning disabled (LOW)")
            finding(title=f"S3 bucket versioning disabled: {name}",
                     severity="LOW",
                     description="Versioning is not enabled — accidental deletions or overwrites are unrecoverable.",
                     data={"catalogue_id": "FORGE-AWS-003", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_versioning.json"))
        else:
            log(f"[aws] {name} — versioning enabled")

        log(f"[aws] {name} — checking encryption...")
        enc = _aws_run(["s3api", "get-bucket-encryption", "--bucket", name],
                        f"s3_{name}_encryption.json", use_region=False)
        if enc is None:
            log(f"[aws] {name} — no default encryption (MEDIUM)")
            finding(title=f"S3 bucket default encryption not configured: {name}",
                     severity="MEDIUM",
                     description="No default server-side encryption configured on the bucket.",
                     data={"catalogue_id": "FORGE-AWS-004", "affected": name,
                           "remediation": "Enable SSE-S3 or SSE-KMS default encryption."},
                     output_file=str(out_dir / f"s3_{name}_encryption.json"))
        else:
            log(f"[aws] {name} — default encryption configured")

        log(f"[aws] {name} — checking access logging...")
        logging_resp = _aws_run(["s3api", "get-bucket-logging", "--bucket", name],
                                 f"s3_{name}_logging.json", use_region=False) or {}
        if not logging_resp.get("LoggingEnabled"):
            log(f"[aws] {name} — access logging disabled (LOW)")
            finding(title=f"S3 bucket access logging disabled: {name}",
                     severity="LOW",
                     description="Server access logging is not enabled — access patterns are not auditable.",
                     data={"catalogue_id": "FORGE-AWS-005", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_logging.json"))
        else:
            log(f"[aws] {name} — access logging enabled")
    log(f"[aws] S3 audit complete — checked {len(buckets)} bucket(s)")

    # ── EC2 ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting EC2 instance audit...")
    status("aws", "EC2 instance audit", "running")
    instances_resp = _aws_run(["ec2", "describe-instances"], "ec2_instances.json") or {}
    reservations = instances_resp.get("Reservations") or []
    total_instances = sum(len(r.get("Instances") or []) for r in reservations)
    log(f"[aws] Found {total_instances} EC2 instance(s) across {len(reservations)} reservation(s)")
    _check_pause()
    for reservation in reservations:
        for inst in reservation.get("Instances") or []:
            iid = inst.get("InstanceId", "")
            name_tag = ""
            for tag in inst.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name_tag = tag.get("Value", "")
            label = f"{name_tag} ({iid})" if name_tag else iid
            log(f"[aws] Checking EC2 instance {label}...")

            if inst.get("PublicIpAddress"):
                log(f"[aws] {label} — has public IP {inst['PublicIpAddress']} (INFO)")
                finding(title=f"EC2 instance with public IP: {label}",
                         severity="INFO",
                         description=f"Instance {iid} has public IP {inst['PublicIpAddress']}.",
                         data={"catalogue_id": "FORGE-AWS-010", "affected": label},
                         output_file=str(out_dir / "ec2_instances.json"))
            else:
                log(f"[aws] {label} — no public IP")

    _check_pause()
    log("[aws] Checking EBS volumes...")
    ebs_resp = _aws_run(["ec2", "describe-volumes"], "ec2_volumes.json") or {}
    volumes = ebs_resp.get("Volumes") or []
    log(f"[aws] Found {len(volumes)} EBS volume(s)")
    _check_pause()
    for vol in volumes:
        vid = vol.get("VolumeId", "")
        if not vol.get("Encrypted"):
            log(f"[aws] EBS {vid} — unencrypted (HIGH)")
            finding(title=f"EBS volume unencrypted: {vid}",
                     severity="HIGH",
                     description="EBS volume is not encrypted at rest.",
                     data={"catalogue_id": "FORGE-AWS-011", "affected": vid,
                           "remediation": "Create an encrypted snapshot and replace the volume."},
                     output_file=str(out_dir / "ec2_volumes.json"))
        else:
            log(f"[aws] EBS {vid} — encrypted OK")

    _check_pause()
    log("[aws] Checking security groups...")
    sgs_resp = _aws_run(["ec2", "describe-security-groups"], "ec2_security_groups.json") or {}
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
    sgs = sgs_resp.get("SecurityGroups") or []
    log(f"[aws] Found {len(sgs)} security group(s)")
    _check_pause()
    for sg in sgs:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        log(f"[aws] Checking security group {sg_name} ({sg_id})...")
        for perm in sg.get("IpPermissions") or []:
            from_port = perm.get("FromPort", 0)
            to_port = perm.get("ToPort", 0)
            for ip_range in perm.get("IpRanges") or []:
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    exposed = {p for p in sensitive_ports if from_port <= p <= to_port}
                    if exposed:
                        log(f"[aws] {sg_name} ({sg_id}) — exposes ports {sorted(exposed)} to 0.0.0.0/0 (HIGH)")
                        finding(title=f"Security group {sg_name} ({sg_id}) exposes sensitive ports to 0.0.0.0/0",
                                 severity="HIGH",
                                 description=f"Inbound rule allows 0.0.0.0/0 access to port(s) {', '.join(str(p) for p in sorted(exposed))}.",
                                 data={"catalogue_id": "FORGE-AWS-012",
                                       "affected": f"{sg_name} ({sg_id})",
                                       "remediation": "Restrict source CIDR to known IP ranges."},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
                    elif from_port == 0 and to_port == 65535:
                        log(f"[aws] {sg_name} ({sg_id}) — allows ALL ports from 0.0.0.0/0 (CRITICAL)")
                        finding(title=f"Security group {sg_name} ({sg_id}) allows all ports from 0.0.0.0/0",
                                 severity="CRITICAL",
                                 description="Inbound rule allows unrestricted access (all ports) from any IP.",
                                 data={"catalogue_id": "FORGE-AWS-013",
                                       "affected": f"{sg_name} ({sg_id})"},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
    log(f"[aws] EC2 audit complete — {total_instances} instance(s), {len(volumes)} volume(s), {len(sgs)} SG(s)")

    # ── IAM ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting IAM audit...")
    status("aws", "IAM audit", "running")
    users_resp = _aws_run(["iam", "list-users"], "iam_users.json", use_region=False) or {}
    iam_users = users_resp.get("Users") or []
    log(f"[aws] Found {len(iam_users)} IAM user(s)")
    _check_pause()
    for user in iam_users:
        _check_pause()
        uname = user.get("UserName", "")
        log(f"[aws] Checking IAM user {uname}...")

        log(f"[aws] {uname} — checking MFA devices...")
        mfa_resp = _aws_run(["iam", "list-mfa-devices", "--user-name", uname],
                              f"iam_{uname}_mfa.json", use_region=False) or {}
        mfa_devices = mfa_resp.get("MFADevices") or []
        if not mfa_devices:
            log(f"[aws] {uname} — no MFA configured (HIGH)")
            finding(title=f"IAM user without MFA: {uname}",
                     severity="HIGH",
                     description=f"IAM user {uname} has no MFA device configured.",
                     data={"catalogue_id": "FORGE-AWS-020", "affected": uname,
                           "remediation": "Enable virtual or hardware MFA for this user."},
                     output_file=str(out_dir / f"iam_{uname}_mfa.json"))
        else:
            log(f"[aws] {uname} — MFA enabled ({len(mfa_devices)} device(s))")

        log(f"[aws] {uname} — checking attached policies...")
        policies_resp = _aws_run(["iam", "list-attached-user-policies", "--user-name", uname],
                                   f"iam_{uname}_policies.json", use_region=False) or {}
        attached = policies_resp.get("AttachedPolicies") or []
        log(f"[aws] {uname} — {len(attached)} attached polic(ies)")
        for pol in attached:
            if pol.get("PolicyArn", "").endswith("/AdministratorAccess"):
                log(f"[aws] {uname} — has AdministratorAccess directly attached (CRITICAL)")
                finding(title=f"IAM user has AdministratorAccess: {uname}",
                         severity="CRITICAL",
                         description=f"User {uname} has the AdministratorAccess managed policy directly attached.",
                         data={"catalogue_id": "FORGE-AWS-021", "affected": uname,
                               "remediation": "Remove direct AdministratorAccess; use role assumption with least-privilege."},
                         output_file=str(out_dir / f"iam_{uname}_policies.json"))

        log(f"[aws] {uname} — checking access keys...")
        keys_resp = _aws_run(["iam", "list-access-keys", "--user-name", uname],
                               f"iam_{uname}_keys.json", use_region=False) or {}
        access_keys = keys_resp.get("AccessKeyMetadata") or []
        log(f"[aws] {uname} — {len(access_keys)} access key(s)")
        for key in access_keys:
            created = key.get("CreateDate", "")
            if created:
                try:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
                    if age > 90:
                        log(f"[aws] {uname} — access key {key.get('AccessKeyId', '')} is {age} days old (MEDIUM)")
                        finding(title=f"IAM access key older than 90 days: {uname}/{key.get('AccessKeyId', '')}",
                                 severity="MEDIUM",
                                 description=f"Access key is {age} days old. Rotate keys regularly.",
                                 data={"catalogue_id": "FORGE-AWS-022", "affected": uname},
                                 output_file=str(out_dir / f"iam_{uname}_keys.json"))
                    else:
                        log(f"[aws] {uname} — access key {key.get('AccessKeyId', '')} age OK ({age} days)")
                except Exception:
                    pass
    log(f"[aws] IAM user audit complete — checked {len(iam_users)} user(s)")

    _check_pause()
    log("[aws] Generating credential report...")
    cred_report = _aws_run(["iam", "generate-credential-report"], "iam_cred_gen.json", use_region=False)
    log("[aws] Retrieving credential report...")
    cred_data = _aws_run(["iam", "get-credential-report"], "iam_cred_report.json", use_region=False) or {}
    if cred_data.get("Content"):
        log("[aws] Parsing credential report for root account keys...")
        import base64
        try:
            csv_text = base64.b64decode(cred_data["Content"]).decode("utf-8")
            for line in csv_text.strip().split("\n")[1:]:
                cols = line.split(",")
                if len(cols) > 1 and cols[0] == "<root_account>":
                    if len(cols) > 8 and cols[8].lower() == "true":
                        log("[aws] Root account has active access keys (CRITICAL)")
                        finding(title="Root account has active access keys",
                                 severity="CRITICAL",
                                 description="The AWS root account has access keys configured. Root keys should never exist.",
                                 data={"catalogue_id": "FORGE-AWS-023", "affected": "root",
                                       "remediation": "Delete root access keys and use IAM users/roles instead."},
                                 output_file=str(out_dir / "iam_cred_report.json"))
                    else:
                        log("[aws] Root account — no active access keys")
        except Exception:
            pass
    else:
        log("[aws] Credential report not available")

    # ── RDS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting RDS audit...")
    status("aws", "RDS audit", "running")
    rds_resp = _aws_run(["rds", "describe-db-instances"], "rds_instances.json") or {}
    rds_instances = rds_resp.get("DBInstances") or []
    log(f"[aws] Found {len(rds_instances)} RDS instance(s)")
    _check_pause()
    for db in rds_instances:
        db_id = db.get("DBInstanceIdentifier", "")
        engine = db.get("Engine", "unknown")
        log(f"[aws] Checking RDS instance {db_id} (engine={engine})...")

        if db.get("PubliclyAccessible"):
            log(f"[aws] {db_id} — publicly accessible (HIGH)")
            finding(title=f"RDS instance publicly accessible: {db_id}",
                     severity="HIGH",
                     description="RDS instance is configured as publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-030", "affected": db_id,
                           "remediation": "Disable public accessibility unless explicitly required."},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — not publicly accessible")

        if not db.get("StorageEncrypted"):
            log(f"[aws] {db_id} — storage unencrypted (HIGH)")
            finding(title=f"RDS instance unencrypted: {db_id}",
                     severity="HIGH",
                     description="RDS storage encryption is not enabled.",
                     data={"catalogue_id": "FORGE-AWS-031", "affected": db_id,
                           "remediation": "Enable encryption at rest (requires snapshot + restore for existing instances)."},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — storage encrypted")

        if db.get("BackupRetentionPeriod", 0) == 0:
            log(f"[aws] {db_id} — no automated backups (MEDIUM)")
            finding(title=f"RDS instance no automated backups: {db_id}",
                     severity="MEDIUM",
                     description="Automated backups are disabled (retention period is 0 days).",
                     data={"catalogue_id": "FORGE-AWS-032", "affected": db_id},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — backup retention: {db.get('BackupRetentionPeriod')} day(s)")
    log(f"[aws] RDS audit complete — checked {len(rds_instances)} instance(s)")

    # ── CloudTrail ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudTrail audit...")
    status("aws", "CloudTrail audit", "running")
    trails_resp = _aws_run(["cloudtrail", "describe-trails"], "cloudtrail_trails.json") or {}
    trails = trails_resp.get("trailList") or []
    log(f"[aws] Found {len(trails)} CloudTrail trail(s)")
    if not trails:
        log("[aws] No CloudTrail trails configured (HIGH)")
        finding(title="No CloudTrail trails configured",
                 severity="HIGH",
                 description="No CloudTrail trails exist in this region/account. API activity is not logged.",
                 data={"catalogue_id": "FORGE-AWS-040",
                       "remediation": "Create a multi-region trail logging to a dedicated S3 bucket."},
                 output_file=str(out_dir / "cloudtrail_trails.json"))
    else:
        _check_pause()
        for trail in trails:
            trail_name = trail.get("Name", "")
            log(f"[aws] Checking trail {trail_name}...")
            trail_status = _aws_run(["cloudtrail", "get-trail-status", "--name", trail_name],
                                      f"cloudtrail_{trail_name}_status.json") or {}
            if not trail_status.get("IsLogging"):
                log(f"[aws] {trail_name} — not actively logging (HIGH)")
                finding(title=f"CloudTrail not actively logging: {trail_name}",
                         severity="HIGH",
                         description=f"Trail {trail_name} exists but is not actively logging.",
                         data={"catalogue_id": "FORGE-AWS-041", "affected": trail_name,
                               "remediation": "aws cloudtrail start-logging --name <trail>"},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_status.json"))
            else:
                log(f"[aws] {trail_name} — actively logging OK")
    log(f"[aws] CloudTrail audit complete — {len(trails)} trail(s)")

    # ── KMS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting KMS audit...")
    status("aws", "KMS audit", "running")
    keys_resp = _aws_run(["kms", "list-keys"], "kms_keys.json") or {}
    kms_keys = keys_resp.get("Keys") or []
    log(f"[aws] Found {len(kms_keys)} KMS key(s)")
    _check_pause()
    for key in kms_keys:
        _check_pause()
        key_id = key.get("KeyId", "")
        log(f"[aws] Checking KMS key {key_id[:8]}...")
        key_detail = _aws_run(["kms", "describe-key", "--key-id", key_id],
                                f"kms_{key_id[:8]}_detail.json") or {}
        km = key_detail.get("KeyMetadata") or {}
        manager = km.get("KeyManager", "unknown")
        state = km.get("KeyState", "unknown")
        log(f"[aws] KMS {key_id[:8]} — manager={manager}, state={state}")
        if manager == "CUSTOMER" and state == "Enabled":
            log(f"[aws] KMS {key_id[:8]} — customer-managed + enabled, checking rotation...")
            rotation = _aws_run(["kms", "get-key-rotation-status", "--key-id", key_id],
                                  f"kms_{key_id[:8]}_rotation.json") or {}
            if not rotation.get("KeyRotationEnabled"):
                log(f"[aws] KMS {key_id[:8]} — rotation disabled (MEDIUM)")
                finding(title=f"KMS key rotation disabled: {key_id[:8]}...",
                         severity="MEDIUM",
                         description="Automatic key rotation is not enabled for this customer-managed KMS key.",
                         data={"catalogue_id": "FORGE-AWS-050", "affected": key_id,
                               "remediation": "aws kms enable-key-rotation --key-id <key>"},
                         output_file=str(out_dir / f"kms_{key_id[:8]}_rotation.json"))
            else:
                log(f"[aws] KMS {key_id[:8]} — rotation enabled OK")
        else:
            log(f"[aws] KMS {key_id[:8]} — skipped (not customer-managed or not enabled)")
    log(f"[aws] KMS audit complete — checked {len(kms_keys)} key(s)")

    log(f"[aws] AWS audit complete — profile={profile or 'default'}, region={region or 'default'}")
    status("aws", "AWS Account Audit", "complete")


# ── Output helpers (§13b) ──────────────────────────────────────────────────────

def _risk_counts(findings: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = str(f.get("risk", "")).upper()
        if r in rc:
            rc[r] += 1
    return rc


def _write_findings_csv(path: Path, findings: list) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            for fd in findings:
                w.writerow({k: fd.get(k, "") for k in _CSV_FIELDS})
    except Exception as exc:
        err(f"findings.csv write failed: {exc}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    global _pause

    parser = argparse.ArgumentParser(
        prog="forge",
        description="Forge — AWS / Azure / GCP cloud control-plane security auditor"
    )
    parser.add_argument("--azure-subscription", help="Azure subscription ID to audit")
    parser.add_argument("--gcp-project", help="GCP project ID to audit")
    parser.add_argument("--aws-profile", default="", help="AWS CLI profile name (default: default profile)")
    parser.add_argument("--aws-region", default="", help="AWS region (leave blank for default region)")
    parser.add_argument("--client-short", default="default", help="Short client identifier")
    parser.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    parser.add_argument("--engagement-name", default="forge run", help="Engagement name for meta.json")
    parser.add_argument("--project", help="Override project output directory")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return 0

    has_aws = args.aws_profile or args.aws_region
    if not (args.azure_subscription or args.gcp_project or has_aws):
        parser.error("provide at least one of --azure-subscription / --gcp-project / --aws-profile / --aws-region")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        project_dir = Path(args.project)
    elif _us is not None:
        project_dir = _us.universal_run_dir(args.client_short, "forge",
                                              year=datetime.now().strftime("%Y"),
                                              ts=ts)
    else:
        project_dir = Path.cwd() / f"forge_{args.client_short}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)

    global _RUN_DIR, _RUNLOG
    _RUN_DIR = project_dir
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
        except Exception:
            _RUNLOG = None

    if _PP is not None:
        _pause = _PP(project_dir, "forge")
        _pause.start_watcher(
            checkpoint_callback=_save_checkpoint,
            grace_period=30,
        )

    target_desc = args.azure_subscription or args.gcp_project or args.aws_profile or "aws-default"
    clouds = []
    if args.azure_subscription:
        clouds.append(f"Azure (subscription={args.azure_subscription})")
    if args.gcp_project:
        clouds.append(f"GCP (project={args.gcp_project})")
    if has_aws or (not args.azure_subscription and not args.gcp_project):
        clouds.append(f"AWS (profile={args.aws_profile or 'default'}, region={args.aws_region or 'default'})")
    log(f"Forge v{VERSION} starting — project: {project_dir}")
    log(f"Cloud targets: {', '.join(clouds)}")
    if _us is not None:
        meta = _us.make_meta(tool="forge", version=VERSION,
                              client_short=args.client_short,
                              client_name=(args.client_name or args.client_short),
                              engagement_name=args.engagement_name,
                              target=target_desc)
        _us.write_meta(project_dir, meta)
        try:
            import pr0t31n_dep_snapshot as _ds
            _ds.write_snapshot(
                project_dir, "forge", VERSION,
                binaries=["aws", "az", "gcloud"],
                pip_packages=[],
            )
        except Exception:
            pass

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _check_pause()
    if args.azure_subscription:
        audit_azure(args.azure_subscription, project_dir)
    _check_pause()
    if args.gcp_project:
        audit_gcp(args.gcp_project, project_dir)
    _check_pause()
    if has_aws or (not args.azure_subscription and not args.gcp_project):
        audit_aws(args.aws_profile, args.aws_region, project_dir)

    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    log(f"All audits finished — writing output files...")
    rc = _risk_counts(_findings)
    log(f"Findings summary: {rc['CRITICAL']} CRITICAL, {rc['HIGH']} HIGH, "
        f"{rc['MEDIUM']} MEDIUM, {rc['LOW']} LOW, {rc['INFO']} INFO")
    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="forge") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        log(f"Wrote findings.json ({len(out)} finding(s))")
        _write_findings_csv(project_dir / "findings.csv", out)
        log("Wrote findings.csv")
        try:
            summary = _us.make_summary(
                tool="forge", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=target_desc,
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
            log("Wrote summary.json")
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        log(f"Wrote findings.json ({len(_findings)} finding(s)) — legacy mode")
        _write_findings_csv(project_dir / "findings.csv", _findings)
        log("Wrote findings.csv — legacy mode")

    if _pause is not None:
        _pause.write_stop_reason("completed", "all_phases_done")
    log(f"Forge v{VERSION} complete — {len(_findings)} finding(s) — output: {project_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
