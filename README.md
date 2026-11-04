# Forge — Azure / GCP Cloud Security Auditor

Forge audits the **control plane** of Azure and GCP environments for
insecure defaults and over-privileged access. Findings emit in the
universal pr0t31n schema (v1.1) so Crucible/Prometheus consume them
directly.

## Coverage (v0.3.0)

| Provider | Resource          | Checks |
|----------|-------------------|--------|
| Azure    | Storage Accounts  | HTTPS-only, default-action ACL |
| Azure    | Key Vaults        | Soft-delete, purge-protection |
| Azure    | VMs               | OS disk encryption |
| GCP      | GCS buckets       | Uniform bucket-level access |
| GCP      | Compute instances | Default service account, public IP |
| GCP      | Project IAM       | Project-level owner/editor bindings |

## Requirements

- Python 3.10+
- `az` CLI (Azure)
- `gcloud` CLI (GCP)
- Pre-authenticated session (`az login`, `gcloud auth login`)

## Install

```bash
python3 install.py
```

The installer auto-detects platform package manager (apt / brew / choco)
and falls back to pip for Python deps.

## Usage

```bash
# Azure only
python3 forge.py --azure-subscription 00000000-0000-0000-0000-000000000000

# GCP only
python3 forge.py --gcp-project my-project-id

# Both (writes to the same project dir)
python3 forge.py --azure-subscription <sub> --gcp-project <proj>
```

## Output

Run directories follow the pr0t31n universal structure (CLAUDE.md §13):

```
<clients_base>/<client_short>/<year>/forge/<client_short>_<ts>/
├── meta.json
├── findings.json                # universal findings (risk UPPERCASED)
├── findings.csv                 # CSV mirror
├── summary.json                 # risk_counts + timing
├── scan.log / scan.log.json     # timestamped event log (§13b/§14f)
├── errors.log / errors.log.json # ERROR-level + TOOL_ERROR (az/gcloud failures)
├── azure/
│   ├── storage_accounts.json    # + storage_accounts.json.log (§14 tool .log)
│   ├── keyvaults.json           # + .json.log
│   └── vms.json                 # + .json.log
└── gcp/
    ├── buckets.json             # + .json.log
    ├── instances.json           # + .json.log
    └── iam_policy.json          # + .json.log
```

Each `az`/`gcloud` invocation emits a `<output>.json.log` sibling (§14 via
`pr0t31n_tool_runner`). Every finding's `output_file` references **both** the
provider JSON dump **and** its `.log` sibling, run-dir-relative (§14i).

## Token protocol

When `FORGE_MANAGED=1` is set in the environment Forge emits the
canonical Crucible-style token stream so it can be wrapped by a Flask
manager:

```
__VANTAGE_LOG__:<message>
__VANTAGE_ERR__:<message>
__VANTAGE_STATUS__:<json>
__VANTAGE_FINDING__:<json>
```
