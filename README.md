<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Forge — Azure / GCP Cloud Security Auditor

Forge audits the **control plane** of Azure and GCP environments for
insecure defaults and over-privileged access. Findings emit in the
universal pr0t31n schema (v1.1) so Crucible/Prometheus consume them
directly.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/forge)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Coverage (v1.10.0)

| Provider | Resource          | Checks |
|----------|-------------------|--------|
| Azure    | Storage Accounts  | HTTPS-only, default-action ACL |
| Azure    | Key Vaults        | Soft-delete, purge-protection |
| Azure    | VMs               | OS disk encryption |
| Azure    | OpenAI Service    | Public network access, content filtering, diagnostic logging, managed identity, CMK |
| GCP      | GCS buckets       | Uniform bucket-level access |
| GCP      | Compute instances | Default service account, public IP |
| GCP      | Project IAM       | Project-level owner/editor bindings |
| GCP      | Vertex AI         | VPC peering, public endpoints, model monitoring, audit logging, notebook public IP, Feature Store CMEK |

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
│   ├── vms.json                 # + .json.log
│   ├── openai_accounts.json     # Azure OpenAI service accounts
│   ├── openai_*_deployments.json    # per-account deployment details
│   └── openai_*_diagnostics.json    # per-account diagnostic settings
└── gcp/
    ├── buckets.json             # + .json.log
    ├── instances.json           # + .json.log
    ├── iam_policy.json          # + .json.log
    ├── vertex_ai_endpoints.json     # Vertex AI model endpoints
    ├── vertex_ai_monitoring.json    # monitoring jobs
    ├── vertex_ai_notebooks.json     # Workbench notebooks
    └── vertex_ai_featurestores.json # Feature Store instances
```

Each `az`/`gcloud` invocation emits a `<output>.json.log` sibling (§14 via
`pr0t31n_tool_runner`). Every finding's `output_file` references **both** the
provider JSON dump **and** its `.log` sibling, run-dir-relative (§14i).

## Token protocol

When `FORGE_MANAGED=1` is set in the environment Forge emits the
canonical Crucible-style token stream so it can be wrapped by a Flask
manager:

```
__CRUCIBLE_LOG__:<message>
__CRUCIBLE_ERR__:<message>
__CRUCIBLE_STATUS__:<json>
__CRUCIBLE_FINDING__:<json>
```
