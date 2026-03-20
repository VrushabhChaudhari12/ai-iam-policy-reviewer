# AI IAM Policy Reviewer

AI-powered AWS IAM policy security reviewer for cloud security teams.

## Overview

Analyzes IAM policy JSON and identifies overpermissive statements.
Returns risk rating, specific issues found, attack impact, and least-privilege rewrite.

## Features

- **Security Analysis**: Identifies wildcard permissions, open principals, and dangerous actions
- **Risk Scoring**: CRITICAL / HIGH / MEDIUM / LOW ratings
- **Least-Privilege Rewrites**: Provides corrected policy JSON

## Stack

- Python
- Ollama (localhost:11434)
- llama3.2 model

## Setup

1. Ensure Ollama is running with llama3.2 model:
   ```bash
   ollama run llama3.2
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Run

```bash
py main.py
```

This will analyze four sample IAM policy scenarios:
- wildcard_admin
- s3_overpermissive
- assume_role_open
- iam_dangerous