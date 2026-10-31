# llm-secrets-guard 🔐

> Detect leaked LLM API keys in your codebase before they reach production.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Security](https://img.shields.io/badge/Security-DevSecOps-red)](https://sopitacasera.github.io)

---

## Why this exists

Every week, thousands of API keys for OpenAI, Azure OpenAI, Anthropic, and other LLM providers get accidentally pushed to GitHub. The average cost of a leaked key: **$2,000–$50,000 in unauthorized API usage** before detection.

`llm-secrets-guard` catches leaked keys **before** the commit, before the PR, and before production — integrating directly into your CI/CD pipeline.

**Providers covered:** OpenAI · Azure OpenAI · Anthropic/Claude · Hugging Face · Google AI/Gemini · Cohere · Mistral AI · Generic token patterns

---

## Quick demo

```bash
$ llm-secrets-guard ./my-project

  FILE: my-project/config/settings.py
  Line   42  [HIGH]  OpenAI  —  OpenAI API key
             api_key = "sk-****...****"

  FILE: my-project/.env.dev
  Line    3  [HIGH]  Azure OpenAI  —  Azure OpenAI key in env var
             AZURE_OPENAI_API_KEY = "abcd****...****"

  ────────────────────────────────────────────────
  SUMMARY: 2 findings  |  2 HIGH  |  0 MEDIUM

  Action required: revoke and rotate the exposed keys immediately.
```

---

## Installation

```bash
git clone https://github.com/sopitacasera/llm-secrets-guard
cd llm-secrets-guard
pip install .
```

---

## Usage

### CLI — scan a directory or file

```bash
# Scan current directory
llm-secrets-guard .

# Scan specific path
llm-secrets-guard ./src

# Output JSON report
llm-secrets-guard . --json --output report.json

# Fail with exit code 1 if HIGH findings exist (use in CI)
llm-secrets-guard . --fail-on-findings
```

### Pre-commit hook — block commits automatically

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Now any `git commit` with a detected secret is blocked before it leaves your machine.

### GitHub Actions — catch it in your CI pipeline

Copy `.github/workflows/secrets-scan.yml` to your repo. Every push and PR is scanned automatically, and the report is uploaded as a build artifact.

### Python API — embed in your own security tooling

```python
from llm_secrets_guard import scan_path
from pathlib import Path

result = scan_path(Path("./src"))

for finding in result.high_severity:
    print(f"[{finding.severity}] {finding.provider} at {finding.file}:{finding.line_number}")

if result.high_severity:
    raise SystemExit("Blocking: exposed LLM keys detected.")
```

---

## Detected patterns

| Provider | Pattern | Severity |
|---|---|---|
| OpenAI | `sk-...` (48 chars) | HIGH |
| OpenAI | `sk-proj-...` | HIGH |
| Anthropic / Claude | `sk-ant-api...` | HIGH |
| Azure OpenAI | Key in env var assignment | HIGH |
| Hugging Face | `hf_...` | HIGH |
| Google AI / Gemini | `AIza...` | HIGH |
| Mistral AI | Key in env var assignment | HIGH |
| Generic | `api_key = "..."` patterns | MEDIUM |

---

## What to do when a key is detected

1. **Revoke the key immediately** in the provider's dashboard
2. **Generate a new key** and store it in Azure Key Vault / GitHub Secrets / `.env` (gitignored)
3. **Audit your git history** — if the key was already committed, assume it was scraped

```bash
# Remove a secret from git history
git filter-repo --path-glob '*.env' --invert-paths
```

---

## Stack

- Python 3.9+ · zero external dependencies
- GitHub Actions (CI/CD integration)
- Pre-commit hook (local protection)

---

## Contributing

Issues and PRs welcome. To add a new LLM provider pattern, edit `llm_secrets_guard/patterns.py` and open a PR.

---

## Author

**Johanna Huaraca** — DevSecOps & AI Security Engineer

[LinkedIn](https://www.linkedin.com/in/johanna-huaraca-71b114276) · [Portfolio](https://sopitacasera.github.io) · [GitHub](https://github.com/sopitacasera)
