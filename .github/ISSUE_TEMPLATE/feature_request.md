---
name: Feature request
about: Suggest a new forensic rule, CLI improvement, or output format
labels: enhancement
---

**What problem does this solve?**

Describe the infrastructure cost or operational problem this would address. If it's a forensic rule, describe the real-world scenario where the symptom (many resources wasted) traces back to a single root cause.

**Describe the solution you'd like**

**Is this a new forensic rule?**

- [ ] Yes — it's a `Detector` (flags individual resources)
- [ ] Yes — it's a `Correlator` (groups observations into a causal case)
- [ ] No — it's a CLI / output / configuration improvement

If it's a forensic rule, describe the causal chain:
- What is the root cause resource? (e.g. a Launch Template, a Security Group, a CloudFormation stack)
- What are the downstream affected resources? (e.g. EBS volumes, ENIs, snapshots)
- What AWS API calls confirm the lineage? (e.g. `DescribeLaunchTemplateVersions`, `DescribeVolumes`)
- What distinguishes a confirmed causal chain from a heuristic guess?

**Alternatives considered**

**What AWS resources / API operations would be needed?**

List the `Describe*` read operations required. `acf` v0.1 makes no mutations and requires all new API calls to be read-only.

**Additional context**
