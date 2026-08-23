# AWS Cost Forensics

Causal AWS infrastructure cost forensics CLI. Root cause over symptom count.

> **Status:** v0.1 in active development — not yet released.

---

## The real problem

A cost report flags 46 orphan EBS volumes. $274/month in waste. Standard tooling treats them as 46 independent problems with 46 independent fixes.

A forensic investigation finds one cause.

All 46 volumes trace back to a single configuration defect: a Launch Template with `DeleteOnTermination=false` on the root block device. Every time the Auto Scaling Group launched and terminated an instance, it left a volume behind. The defect has been active for months — every scale-in event adds more.

The fix is one change to one Launch Template version and a one-time cleanup of the orphan volumes. Not 46 independent tasks.

`acf` generalizes that forensic workflow. Instead of listing symptoms, it finds causes.

---

## How it works

```
COLLECT → BUILD GRAPH → DETECT → CORRELATE → SUPERSEDE → PRICE → REMEDIATE → REPORT
```

`acf` reads your AWS account (no mutations, ever), builds a resource graph connecting volumes to snapshots to AMIs to Launch Template versions to Auto Scaling Groups, then runs forensic rules that trace causal chains rather than flag isolated resources.

When a causal chain is confirmed, individual observations (e.g. "this volume is orphaned") are superseded by the forensic case that explains all of them ("all 46 volumes came from this one LT defect"). The terminal output shows cases first, then any remaining active observations.

---

## Installation

Requires Python 3.12+.

```bash
pip install aws-cost-forensics  # not yet on PyPI — install from source for now
```

**From source:**

```bash
git clone https://github.com/umaryaseen/aws-cost-forensics.git
cd aws-cost-forensics
pip install -e .
```

---

## Quick start

```bash
# Scan your AWS account
acf scan --region eu-central-1 --output scan.json

# Explain a specific finding in detail
acf explain ASG_EBS_LEAK:123456789012:eu-central-1:lt-prod-web --input scan.json

# Re-render the full report from a saved scan (no AWS calls)
acf report --input scan.json

# Re-render as JSON
acf report --input scan.json --format json
```

**Example terminal output:**

```
 ────────────────────────────────────────────────────────────────────────
 AWS Cost Forensics  v0.1.0  ·  schema 1.0
 Account ****9012  ·  Region eu-central-1  ·  Pricing static
 Generated 2024-03-15 14:22:07 UTC
 ────────────────────────────────────────────────────────────────────────

 Summary
  Forensic Cases       1  (ACTIVE recurrence)
  Observations         51  (49 superseded)
  Affected Resources   46
  Monthly Waste        $274.40

 ──────────────────── Forensic Cases ────────────────────────────────────

[HIGH] ASG_EBS_LEAK   ACTIVE  ·  Evidence: HIGH
  Orphan EBS chain from launch template prod-web-lt
  Root Cause   prod-web-lt  (launch_template)  eu-central-1
  Affected     46 resource(s)
  Cost         $274.40/mo

  Remediation  [FIX_SOURCE_FIRST]
    1. Create a new launch template version with DeleteOnTermination=true
    2. Set the new version as the default
    3. Verify no ASGs are pinned to the broken version
    4. Snapshot and delete orphan volumes

  49 superseded observation(s) — resolve this case first:
    ↳ EBS_UNATTACHED_STALE  vol-0001aabbccdd  $5.95/mo
    ... (45 more)
```

Full example output: [docs/example-output/terminal-output.txt](docs/example-output/terminal-output.txt)
Full example scan artifact: [docs/example-output/scan-result.json](docs/example-output/scan-result.json)

---

## Configuration

**CLI flags (highest precedence):**

```bash
acf scan --profile my-profile --region eu-central-1 --stale-days 60 --output scan.json
```

**Environment variables:**

```bash
export ACF_PROFILE=my-profile
export ACF_REGION=eu-central-1
acf scan
```

**Config file** (`~/.acf/config.toml`):

```toml
profile = "my-profile"
region = "eu-central-1"
stale_volume_days = 60
mask_account_id = true   # default: true — masks account ID in terminal output
```

**Precedence:** CLI flags → `ACF_PROFILE`/`ACF_REGION` env vars → `~/.acf/config.toml` → boto3 configured region.

Region has no implicit fallback. If it cannot be resolved, `acf` prints a clear error.

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Clean scan — no findings |
| 1 | Fatal error (misconfiguration, missing region, AWS access failure) |
| 2 | Scan completed with forensic cases found (useful for CI) |

---

## v0.1 forensic rules

| Rule | Type | What it finds |
|---|---|---|
| `EBS_UNATTACHED_STALE` | Detector | EBS volumes unattached for ≥ N days (`--stale-days`, default 30) |
| `LT_DELETE_ON_TERMINATION_FALSE` | Detector | Launch Template root block device explicitly set to not delete on termination |
| `EBS_GP2_TO_GP3` | Detector | gp2 volumes where gp3 is cheaper at equivalent baseline performance |
| `EBS_ASG_ORPHAN_CHAIN` | Correlator | EBS volumes causally traced to a defective Launch Template via confirmed snapshot → AMI → LT version → ASG lineage |

`EBS_ASG_ORPHAN_CHAIN` supersedes `EBS_UNATTACHED_STALE` and `EBS_GP2_TO_GP3` observations for volumes it claims — those volumes are shown under the forensic case, not in the active observation list.

**What `EBS_ASG_ORPHAN_CHAIN` requires before creating a forensic case:**
- Confirmed lineage: volume's `snapshot_id` must appear in AMI block device mappings, and the AMI's `image_id` must appear in a Launch Template version
- Recurrence evaluated against the **effective** LT version each ASG actually uses (respecting `$Default`, `$Latest`, or pinned version selectors — not just the current default)
- Ambiguous lineage (volume traces to multiple LTs) → recorded as missing evidence on the observation; not arbitrarily assigned to either case

---

## Required IAM permissions

`acf` requires only read permissions. It makes no mutations.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AcfReadOnly",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "autoscaling:DescribeAutoScalingGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

Full policy document: [docs/iam-policy.json](docs/iam-policy.json)

To create this policy and attach it to an IAM role or user:

```bash
aws iam create-policy \
  --policy-name AcfReadOnly \
  --policy-document file://docs/iam-policy.json
```

---

## Scan artifacts

`acf scan --output scan.json` writes a versioned JSON artifact. The artifact separates `schema_version` (format contract, for consumers) from `tool_version` (package release). Consumers should gate on `schema_version`, not `tool_version`.

Artifacts can be re-rendered offline without making any AWS calls:

```bash
acf report --input scan.json            # terminal output
acf report --input scan.json --format json  # JSON passthrough
acf explain CASE_ID --input scan.json   # single case detail
```

---

## Security

- **No mutations.** All AWS operations are `Describe*` only. `ReadOnlyEC2Client` and `ReadOnlyASGClient` wrappers raise `ReadOnlyViolation` for any non-allowlisted operation — this is enforced architecturally, not by convention.
- **Account ID masking.** Terminal output always shows `****{last4}`. Full account IDs appear only in JSON artifacts.
- **No credentials logged.** Secret access keys, session tokens, and sensitive AWS metadata are never written to output.
- **No external network calls.** Pricing uses a bundled static table. No data leaves your machine except to AWS APIs.

See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

**Short version:**

```bash
git clone https://github.com/umaryaseen/aws-cost-forensics.git
cd aws-cost-forensics
pip install -e ".[dev]"
pytest tests/ -m "not integration"
ruff check src/ tests/
mypy src/
```

Before opening a PR, make sure all three pass. Integration tests (`-m integration`) require real AWS credentials and are skipped by default.

**Adding a new forensic rule:** rules live in `src/aws_cost_forensics/rules/`. Implement the `Detector` or `Correlator` protocol from `rules/base.py`. Rules must not import `boto3` — all AWS access goes through collectors.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
