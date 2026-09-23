#!/usr/bin/env python3
"""
Forge — AWS / Azure / GCP cloud control-plane security auditor.

Token protocol (emitted on stdout for Crucible-style managers):
  __VANTAGE_LOG__     <message>
  __VANTAGE_ERR__     <message>
  __VANTAGE_STATUS__  <json>
  __VANTAGE_FINDING__ <json>

Run direct (CLI) or under a Flask manager that sets FORGE_MANAGED=1
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

VERSION = "1.0.1"

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

_MANAGED = os.environ.get("FORGE_MANAGED", "") == "1"
_findings: list = []

_RUN_DIR: Optional[Path] = None
_RUNLOG = None

_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]


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


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:{msg}", flush=True)
    else:
        print(msg, flush=True)


def log(msg: str) -> None:
    _tok("__VANTAGE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__VANTAGE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    rec = {"phase": phase, "label": label, "state": state, "step": step}
    _tok("__VANTAGE_STATUS__", json.dumps(rec))


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
    _tok("__VANTAGE_FINDING__", json.dumps(rec))


# ── Azure auditor ─────────────────────────────────────────────────────────────

def audit_azure(subscription_id: str, output_dir: Path) -> None:
    status("azure", "Azure Subscription Audit", "running")
    az = shutil.which("az")
    if not az:
        err("az CLI not installed — skipping Azure audit")
        status("azure", "Azure Subscription Audit", "skipped")
        return

    out_dir = output_dir / "azure"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _az_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [az] + args + ["--subscription", subscription_id, "--output", "json"]
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

    accounts = _az_run(["storage", "account", "list"], "storage_accounts.json") or []
    for acct in accounts:
        name = acct.get("name", "")
        rg   = acct.get("resourceGroup", "")
        if acct.get("enableHttpsTrafficOnly") is False:
            finding(title=f"Azure Storage Account allows HTTP: {name}",
                     severity="HIGH",
                     description=("Storage account does not enforce HTTPS-only. "
                                   "Data in transit may traverse plaintext."),
                     data={"catalogue_id": "FORGE-AZ-001",
                           "affected": f"{rg}/{name}",
                           "remediation": "az storage account update --https-only true"},
                     output_file=str(out_dir / "storage_accounts.json"))
        net_acl = (acct.get("networkRuleSet") or {}).get("defaultAction", "")
        if net_acl == "Allow":
            finding(title=f"Azure Storage Account publicly accessible: {name}",
                     severity="HIGH",
                     description=("Storage account network ACL defaults to Allow "
                                   "(no IP restrictions configured)."),
                     data={"catalogue_id": "FORGE-AZ-002",
                           "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "storage_accounts.json"))

    vaults = _az_run(["keyvault", "list"], "keyvaults.json") or []
    for kv in vaults:
        name = kv.get("name", "")
        props = kv.get("properties") or {}
        if not props.get("enableSoftDelete", True):
            finding(title=f"Azure Key Vault soft-delete disabled: {name}",
                     severity="MEDIUM",
                     description="Soft-delete not enabled — accidental deletions are unrecoverable.",
                     data={"catalogue_id": "FORGE-AZ-010", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))
        if not props.get("enablePurgeProtection"):
            finding(title=f"Azure Key Vault purge-protection disabled: {name}",
                     severity="MEDIUM",
                     description="Purge-protection disabled — soft-deleted keys can be purged immediately.",
                     data={"catalogue_id": "FORGE-AZ-011", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))

    vms = _az_run(["vm", "list"], "vms.json") or []
    for vm in vms:
        name = vm.get("name", "")
        rg   = vm.get("resourceGroup", "")
        sd   = (vm.get("storageProfile") or {}).get("osDisk") or {}
        enc  = (sd.get("encryptionSettings") or {}).get("enabled") if sd else None
        if enc is False:
            finding(title=f"Azure VM OS disk unencrypted: {name}",
                     severity="HIGH",
                     description="Azure Disk Encryption (ADE) is disabled on the OS disk.",
                     data={"catalogue_id": "FORGE-AZ-020", "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "vms.json"))

    status("azure", "Azure Subscription Audit", "complete")


# ── GCP auditor ───────────────────────────────────────────────────────────────

def audit_gcp(project_id: str, output_dir: Path) -> None:
    status("gcp", "GCP Project Audit", "running")
    gcloud = shutil.which("gcloud")
    if not gcloud:
        err("gcloud CLI not installed — skipping GCP audit")
        status("gcp", "GCP Project Audit", "skipped")
        return

    out_dir = output_dir / "gcp"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _g_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [gcloud] + args + ["--project", project_id, "--format=json"]
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

    buckets = _g_run(["storage", "buckets", "list"], "buckets.json") or []
    for b in buckets:
        name = b.get("name", "")
        iam_cfg = (b.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}
        if not iam_cfg.get("enabled"):
            finding(title=f"GCS bucket uniform access disabled: {name}",
                     severity="MEDIUM",
                     description="Uniform bucket-level access disabled — legacy ACLs may grant unintended access.",
                     data={"catalogue_id": "FORGE-GCP-001", "affected": name},
                     output_file=str(out_dir / "buckets.json"))

    instances = _g_run(["compute", "instances", "list"], "instances.json") or []
    for inst in instances:
        name = inst.get("name", "")
        sas  = inst.get("serviceAccounts") or []
        for sa in sas:
            email = sa.get("email", "")
            if "compute@developer.gserviceaccount.com" in email:
                finding(title=f"GCE instance uses default service account: {name}",
                         severity="MEDIUM",
                         description="Default Compute Engine service account grants over-broad scopes.",
                         data={"catalogue_id": "FORGE-GCP-010",
                               "affected": name,
                               "service_account": email},
                         output_file=str(out_dir / "instances.json"))
        for iface in inst.get("networkInterfaces", []):
            if iface.get("accessConfigs"):
                finding(title=f"GCE instance has public IP: {name}",
                         severity="INFO",
                         description="Instance has an ephemeral or static external IP configured.",
                         data={"catalogue_id": "FORGE-GCP-011",
                               "affected": name},
                         output_file=str(out_dir / "instances.json"))

    iam = _g_run(["projects", "get-iam-policy", project_id], "iam_policy.json") or {}
    for binding in iam.get("bindings", []) or []:
        role = binding.get("role", "")
        if role in ("roles/owner", "roles/editor"):
            for member in binding.get("members", []) or []:
                if member.startswith("user:") or member.startswith("serviceAccount:"):
                    finding(title=f"GCP project-level {role} granted to {member}",
                             severity="HIGH" if role == "roles/owner" else "MEDIUM",
                             description=("Over-privileged role granted at project level. "
                                           "Prefer per-resource or custom roles."),
                             data={"catalogue_id": "FORGE-GCP-020",
                                   "affected": member,
                                   "role": role},
                             output_file=str(out_dir / "iam_policy.json"))

    status("gcp", "GCP Project Audit", "complete")


# ── AWS auditor ───────────────────────────────────────────────────────────────

def audit_aws(profile: str, region: str, output_dir: Path) -> None:
    status("aws", "AWS Account Audit", "running")
    aws = shutil.which("aws")
    if not aws:
        err("aws CLI not installed — skipping AWS audit")
        status("aws", "AWS Account Audit", "skipped")
        return

    out_dir = output_dir / "aws"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _aws_run(args: list, out_name: str, use_region: bool = True) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [aws] + args + ["--output", "json"]
        if profile:
            cmd += ["--profile", profile]
        if use_region and region:
            cmd += ["--region", region]
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
    status("aws", "S3 bucket audit", "running")
    buckets_resp = _aws_run(["s3api", "list-buckets"], "s3_buckets.json", use_region=False) or {}
    buckets = buckets_resp.get("Buckets") or []
    for bucket in buckets:
        name = bucket.get("Name", "")

        pab = _aws_run(["s3api", "get-public-access-block", "--bucket", name],
                        f"s3_{name}_public_access.json", use_region=False) or {}
        pab_cfg = pab.get("PublicAccessBlockConfiguration") or {}
        if not pab_cfg:
            finding(title=f"S3 bucket missing public access block: {name}",
                     severity="HIGH",
                     description="No S3 public access block configured — objects may be publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-001", "affected": name,
                           "remediation": "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))
        elif not all(pab_cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                "BlockPublicPolicy", "RestrictPublicBuckets")):
            finding(title=f"S3 bucket incomplete public access block: {name}",
                     severity="MEDIUM",
                     description="Not all four public access block settings are enabled.",
                     data={"catalogue_id": "FORGE-AWS-002", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))

        versioning = _aws_run(["s3api", "get-bucket-versioning", "--bucket", name],
                               f"s3_{name}_versioning.json", use_region=False) or {}
        if versioning.get("Status") != "Enabled":
            finding(title=f"S3 bucket versioning disabled: {name}",
                     severity="LOW",
                     description="Versioning is not enabled — accidental deletions or overwrites are unrecoverable.",
                     data={"catalogue_id": "FORGE-AWS-003", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_versioning.json"))

        enc = _aws_run(["s3api", "get-bucket-encryption", "--bucket", name],
                        f"s3_{name}_encryption.json", use_region=False)
        if enc is None:
            finding(title=f"S3 bucket default encryption not configured: {name}",
                     severity="MEDIUM",
                     description="No default server-side encryption configured on the bucket.",
                     data={"catalogue_id": "FORGE-AWS-004", "affected": name,
                           "remediation": "Enable SSE-S3 or SSE-KMS default encryption."},
                     output_file=str(out_dir / f"s3_{name}_encryption.json"))

        logging_resp = _aws_run(["s3api", "get-bucket-logging", "--bucket", name],
                                 f"s3_{name}_logging.json", use_region=False) or {}
        if not logging_resp.get("LoggingEnabled"):
            finding(title=f"S3 bucket access logging disabled: {name}",
                     severity="LOW",
                     description="Server access logging is not enabled — access patterns are not auditable.",
                     data={"catalogue_id": "FORGE-AWS-005", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_logging.json"))

    # ── EC2 ───────────────────────────────────────────────────────────────────
    status("aws", "EC2 instance audit", "running")
    instances_resp = _aws_run(["ec2", "describe-instances"], "ec2_instances.json") or {}
    for reservation in instances_resp.get("Reservations") or []:
        for inst in reservation.get("Instances") or []:
            iid = inst.get("InstanceId", "")
            name_tag = ""
            for tag in inst.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name_tag = tag.get("Value", "")
            label = f"{name_tag} ({iid})" if name_tag else iid

            if inst.get("PublicIpAddress"):
                finding(title=f"EC2 instance with public IP: {label}",
                         severity="INFO",
                         description=f"Instance {iid} has public IP {inst['PublicIpAddress']}.",
                         data={"catalogue_id": "FORGE-AWS-010", "affected": label},
                         output_file=str(out_dir / "ec2_instances.json"))

    ebs_resp = _aws_run(["ec2", "describe-volumes"], "ec2_volumes.json") or {}
    for vol in ebs_resp.get("Volumes") or []:
        vid = vol.get("VolumeId", "")
        if not vol.get("Encrypted"):
            finding(title=f"EBS volume unencrypted: {vid}",
                     severity="HIGH",
                     description="EBS volume is not encrypted at rest.",
                     data={"catalogue_id": "FORGE-AWS-011", "affected": vid,
                           "remediation": "Create an encrypted snapshot and replace the volume."},
                     output_file=str(out_dir / "ec2_volumes.json"))

    sgs_resp = _aws_run(["ec2", "describe-security-groups"], "ec2_security_groups.json") or {}
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
    for sg in sgs_resp.get("SecurityGroups") or []:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        for perm in sg.get("IpPermissions") or []:
            from_port = perm.get("FromPort", 0)
            to_port = perm.get("ToPort", 0)
            for ip_range in perm.get("IpRanges") or []:
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    exposed = {p for p in sensitive_ports if from_port <= p <= to_port}
                    if exposed:
                        finding(title=f"Security group {sg_name} ({sg_id}) exposes sensitive ports to 0.0.0.0/0",
                                 severity="HIGH",
                                 description=f"Inbound rule allows 0.0.0.0/0 access to port(s) {', '.join(str(p) for p in sorted(exposed))}.",
                                 data={"catalogue_id": "FORGE-AWS-012",
                                       "affected": f"{sg_name} ({sg_id})",
                                       "remediation": "Restrict source CIDR to known IP ranges."},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
                    elif from_port == 0 and to_port == 65535:
                        finding(title=f"Security group {sg_name} ({sg_id}) allows all ports from 0.0.0.0/0",
                                 severity="CRITICAL",
                                 description="Inbound rule allows unrestricted access (all ports) from any IP.",
                                 data={"catalogue_id": "FORGE-AWS-013",
                                       "affected": f"{sg_name} ({sg_id})"},
                                 output_file=str(out_dir / "ec2_security_groups.json"))

    # ── IAM ───────────────────────────────────────────────────────────────────
    status("aws", "IAM audit", "running")
    users_resp = _aws_run(["iam", "list-users"], "iam_users.json", use_region=False) or {}
    for user in users_resp.get("Users") or []:
        uname = user.get("UserName", "")

        mfa_resp = _aws_run(["iam", "list-mfa-devices", "--user-name", uname],
                              f"iam_{uname}_mfa.json", use_region=False) or {}
        if not (mfa_resp.get("MFADevices") or []):
            finding(title=f"IAM user without MFA: {uname}",
                     severity="HIGH",
                     description=f"IAM user {uname} has no MFA device configured.",
                     data={"catalogue_id": "FORGE-AWS-020", "affected": uname,
                           "remediation": "Enable virtual or hardware MFA for this user."},
                     output_file=str(out_dir / f"iam_{uname}_mfa.json"))

        policies_resp = _aws_run(["iam", "list-attached-user-policies", "--user-name", uname],
                                   f"iam_{uname}_policies.json", use_region=False) or {}
        for pol in policies_resp.get("AttachedPolicies") or []:
            if pol.get("PolicyArn", "").endswith("/AdministratorAccess"):
                finding(title=f"IAM user has AdministratorAccess: {uname}",
                         severity="CRITICAL",
                         description=f"User {uname} has the AdministratorAccess managed policy directly attached.",
                         data={"catalogue_id": "FORGE-AWS-021", "affected": uname,
                               "remediation": "Remove direct AdministratorAccess; use role assumption with least-privilege."},
                         output_file=str(out_dir / f"iam_{uname}_policies.json"))

        keys_resp = _aws_run(["iam", "list-access-keys", "--user-name", uname],
                               f"iam_{uname}_keys.json", use_region=False) or {}
        for key in keys_resp.get("AccessKeyMetadata") or []:
            created = key.get("CreateDate", "")
            if created:
                try:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
                    if age > 90:
                        finding(title=f"IAM access key older than 90 days: {uname}/{key.get('AccessKeyId', '')}",
                                 severity="MEDIUM",
                                 description=f"Access key is {age} days old. Rotate keys regularly.",
                                 data={"catalogue_id": "FORGE-AWS-022", "affected": uname},
                                 output_file=str(out_dir / f"iam_{uname}_keys.json"))
                except Exception:
                    pass

    cred_report = _aws_run(["iam", "generate-credential-report"], "iam_cred_gen.json", use_region=False)
    cred_data = _aws_run(["iam", "get-credential-report"], "iam_cred_report.json", use_region=False) or {}
    if cred_data.get("Content"):
        import base64
        try:
            csv_text = base64.b64decode(cred_data["Content"]).decode("utf-8")
            for line in csv_text.strip().split("\n")[1:]:
                cols = line.split(",")
                if len(cols) > 1 and cols[0] == "<root_account>":
                    if len(cols) > 8 and cols[8].lower() == "true":
                        finding(title="Root account has active access keys",
                                 severity="CRITICAL",
                                 description="The AWS root account has access keys configured. Root keys should never exist.",
                                 data={"catalogue_id": "FORGE-AWS-023", "affected": "root",
                                       "remediation": "Delete root access keys and use IAM users/roles instead."},
                                 output_file=str(out_dir / "iam_cred_report.json"))
        except Exception:
            pass

    # ── RDS ───────────────────────────────────────────────────────────────────
    status("aws", "RDS audit", "running")
    rds_resp = _aws_run(["rds", "describe-db-instances"], "rds_instances.json") or {}
    for db in rds_resp.get("DBInstances") or []:
        db_id = db.get("DBInstanceIdentifier", "")

        if db.get("PubliclyAccessible"):
            finding(title=f"RDS instance publicly accessible: {db_id}",
                     severity="HIGH",
                     description="RDS instance is configured as publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-030", "affected": db_id,
                           "remediation": "Disable public accessibility unless explicitly required."},
                     output_file=str(out_dir / "rds_instances.json"))

        if not db.get("StorageEncrypted"):
            finding(title=f"RDS instance unencrypted: {db_id}",
                     severity="HIGH",
                     description="RDS storage encryption is not enabled.",
                     data={"catalogue_id": "FORGE-AWS-031", "affected": db_id,
                           "remediation": "Enable encryption at rest (requires snapshot + restore for existing instances)."},
                     output_file=str(out_dir / "rds_instances.json"))

        if db.get("BackupRetentionPeriod", 0) == 0:
            finding(title=f"RDS instance no automated backups: {db_id}",
                     severity="MEDIUM",
                     description="Automated backups are disabled (retention period is 0 days).",
                     data={"catalogue_id": "FORGE-AWS-032", "affected": db_id},
                     output_file=str(out_dir / "rds_instances.json"))

    # ── CloudTrail ────────────────────────────────────────────────────────────
    status("aws", "CloudTrail audit", "running")
    trails_resp = _aws_run(["cloudtrail", "describe-trails"], "cloudtrail_trails.json") or {}
    trails = trails_resp.get("trailList") or []
    if not trails:
        finding(title="No CloudTrail trails configured",
                 severity="HIGH",
                 description="No CloudTrail trails exist in this region/account. API activity is not logged.",
                 data={"catalogue_id": "FORGE-AWS-040",
                       "remediation": "Create a multi-region trail logging to a dedicated S3 bucket."},
                 output_file=str(out_dir / "cloudtrail_trails.json"))
    else:
        for trail in trails:
            trail_name = trail.get("Name", "")
            trail_status = _aws_run(["cloudtrail", "get-trail-status", "--name", trail_name],
                                      f"cloudtrail_{trail_name}_status.json") or {}
            if not trail_status.get("IsLogging"):
                finding(title=f"CloudTrail not actively logging: {trail_name}",
                         severity="HIGH",
                         description=f"Trail {trail_name} exists but is not actively logging.",
                         data={"catalogue_id": "FORGE-AWS-041", "affected": trail_name,
                               "remediation": "aws cloudtrail start-logging --name <trail>"},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_status.json"))

    # ── KMS ───────────────────────────────────────────────────────────────────
    status("aws", "KMS audit", "running")
    keys_resp = _aws_run(["kms", "list-keys"], "kms_keys.json") or {}
    for key in keys_resp.get("Keys") or []:
        key_id = key.get("KeyId", "")
        key_detail = _aws_run(["kms", "describe-key", "--key-id", key_id],
                                f"kms_{key_id[:8]}_detail.json") or {}
        km = key_detail.get("KeyMetadata") or {}
        if km.get("KeyManager") == "CUSTOMER" and km.get("KeyState") == "Enabled":
            rotation = _aws_run(["kms", "get-key-rotation-status", "--key-id", key_id],
                                  f"kms_{key_id[:8]}_rotation.json") or {}
            if not rotation.get("KeyRotationEnabled"):
                finding(title=f"KMS key rotation disabled: {key_id[:8]}...",
                         severity="MEDIUM",
                         description="Automatic key rotation is not enabled for this customer-managed KMS key.",
                         data={"catalogue_id": "FORGE-AWS-050", "affected": key_id,
                               "remediation": "aws kms enable-key-rotation --key-id <key>"},
                         output_file=str(out_dir / f"kms_{key_id[:8]}_rotation.json"))

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

    target_desc = args.azure_subscription or args.gcp_project or args.aws_profile or "aws-default"
    log(f"Forge v{VERSION} starting — project: {project_dir}")
    if _us is not None:
        meta = _us.make_meta(tool="forge", version=VERSION,
                              client_short=args.client_short,
                              client_name=(args.client_name or args.client_short),
                              engagement_name=args.engagement_name,
                              target=target_desc)
        _us.write_meta(project_dir, meta)

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.azure_subscription:
        audit_azure(args.azure_subscription, project_dir)
    if args.gcp_project:
        audit_gcp(args.gcp_project, project_dir)
    if has_aws or (not args.azure_subscription and not args.gcp_project):
        audit_aws(args.aws_profile, args.aws_region, project_dir)

    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="forge") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        _write_findings_csv(project_dir / "findings.csv", out)
        try:
            summary = _us.make_summary(
                tool="forge", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=target_desc,
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        _write_findings_csv(project_dir / "findings.csv", _findings)

    log(f"Forge complete — {len(_findings)} finding(s) — output: {project_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
