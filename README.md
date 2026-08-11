# AWS Cost Forensics

Causal AWS infrastructure cost forensics CLI. Root cause over symptom count.

> **Status:** v0.1 in active development — not yet released.

## The problem it solves

Standard cost tools report 46 orphan EBS volumes. They treat them as 46 independent problems.

A forensic investigation finds something different: all 46 volumes trace back to a single Launch Template with `DeleteOnTermination=false` on the root device. Every time the Auto Scaling Group launched and terminated an instance, it left a volume behind. The root cause is one configuration defect — not 46 orphan volumes.

`acf` generalizes that forensic workflow. Instead of listing symptoms, it finds causes.

## Installation

```bash
pip install aws-cost-forensics  # not yet on PyPI
```

## Quick start

```bash
# Scan your AWS account
acf scan --region eu-central-1 --output scan.json

# Explain a specific finding
acf explain ASG_EBS_LEAK:123456789012:eu-central-1:lt-prod-web --input scan.json

# Re-render the full report from a saved scan
acf report --input scan.json
```

## Required IAM permissions

```json
{
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
```

See `docs/iam-policy.json` for the full policy document.

## v0.1 forensic rules

| Rule | Type | What it finds |
|---|---|---|
| `EBS_UNATTACHED_STALE` | Detector | EBS volumes unattached for > N days |
| `LT_DELETE_ON_TERMINATION_FALSE` | Detector | Launch Template root device explicitly set to not delete on termination |
| `EBS_GP2_TO_GP3` | Detector | gp2 volumes where gp3 is cheaper at equivalent performance |
| `EBS_ASG_ORPHAN_CHAIN` | Correlator | EBS volumes causally traced to a defective Launch Template via snapshot → AMI → LT → ASG lineage |

`acf` makes **no mutations**. It reads, it reasons, it reports.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
