---
name: Bug report
about: Something is broken or producing incorrect output
labels: bug
---

**Describe the bug**

A clear description of what went wrong and what you expected instead.

**Command run**

```
acf <command> --region <region> ...
```

**Expected behavior**

**Actual behavior**

Include the full terminal output if possible. Use `--no-color` for clean copy-paste.

**`acf` version**

```
acf --version
```

**Environment**

- OS and version:
- Python version (`python --version`):
- AWS region:
- boto3 version (`pip show boto3 | grep Version`):

**Is this a reporting error or a detection error?**

- [ ] Wrong finding produced (false positive)
- [ ] Real finding missed (false negative)
- [ ] Crash or unhandled exception
- [ ] Incorrect cost estimate
- [ ] Other output/formatting issue

**Additional context**

If this involves a detection error, describe the infrastructure state (volume type, LT version selector, ASG configuration, etc.) without including real account IDs, access keys, resource ARNs with account numbers, or production scan artifacts.

<!-- IMPORTANT: Do NOT paste AWS account IDs, access keys, session tokens, or production scan artifacts here. Anonymize all identifiers before sharing. -->
