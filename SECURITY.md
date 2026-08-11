# Security Policy

## Reporting vulnerabilities

Report security vulnerabilities by emailing umar.yaseen66.uy@gmail.com. Do not open a public issue.

## What this tool does

`acf` makes **read-only** AWS API calls only. It will never create, modify, or delete any AWS resource.

## What must never be committed

- AWS access keys or secret access keys
- AWS session tokens
- AWS account IDs in raw form (mask as `****{last4}` in examples)
- Scan artifacts containing real infrastructure identifiers from production accounts
- `.env` files or any file containing credentials

## Bundled data

The static pricing table (`src/aws_cost_forensics/pricing/data/ebs_prices.json`) contains only public AWS pricing data — no account-specific information.
