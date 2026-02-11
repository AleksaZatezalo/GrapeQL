[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# GrapeQL

GrapeQL is a modular security testing platform designed to identify vulnerabilities, misconfigurations, and attack paths within GraphQL APIs through dynamic analysis.

Built for security engineers and developers, GrapeQL combines automated testing, YAML-driven payload execution, structured logging, and optional AI-assisted analysis to support modern application security workflows.

## Why GrapeQL?

GraphQL introduces unique attack surfaces that traditional API scanners often overlook. GrapeQL focuses specifically on these risks, enabling teams to proactively assess security posture before deployment.

With GrapeQL, teams can:

- Detect injection vulnerabilities across queries and mutations  
- Identify authentication and authorization weaknesses  
- Discover information disclosure exposures  
- Validate denial-of-service resilience  
- Perform out-of-band testing for blind vulnerabilities  
- Generate structured, actionable security reports  

Whether used for standalone security assessments or integrated into automated pipelines, GrapeQL helps organizations shift security testing earlier in the development lifecycle.

---

## Overview

GrapeQL is a modular GraphQL security scanner that identifies common vulnerabilities and misconfigurations in GraphQL endpoints. It ships with a command-line interface for quick assessments and a Python library for integration into custom security workflows. Test logic is driven by YAML definitions, making it easy to extend coverage without modifying application code.

---

## Key Capabilities

- **GraphQL Fingerprinting** — Identify the underlying GraphQL engine through behavioral probes  
- **Information Disclosure Testing** — Detect introspection leaks, field suggestions, GraphiQL exposure, batch query support, and alternate transport acceptance  
- **SQL Injection Testing** — Test all String/ID arguments across queries and mutations  
- **Command Injection Testing** — Detect OS command execution vectors  
- **Out-of-Band (OOB) Injection** — Identify blind vulnerabilities via callback payloads  
- **Authentication & Authorization Testing** — Header bypass, IDOR enumeration, and unauthenticated access checks  
- **Denial of Service Testing** — Evaluate query complexity attacks such as deep nesting and fragment bombs  
- **AI-Assisted Analysis** — Generate executive summaries, risk insights, and recommended next steps  
- **YAML-Driven Test Cases** — Extend testing coverage without touching core code  
- **Structured Logging** — Capture detailed request/response telemetry  
- **Comprehensive Reporting** — Export findings in Markdown or JSON  

---

## Installation

```bash
# Clone the repository
git clone https://github.com/AleksaZatezalo/grapeql.git
cd grapeql

# Install in editable mode
pip install -e .
```

---

## Quick Start

Run a baseline security scan against a GraphQL endpoint:

```bash
grapeql --api https://example.com/graphql
```

Run a comprehensive scan including advanced modules:

```bash
grapeql --api https://example.com/graphql --modules fingerprint info injection auth dos
```

Generate a Markdown report:

```bash
grapeql --api https://example.com/graphql --report report.md
```

---

## Command Line Usage

```bash
# Basic scan
grapeql --api https://example.com/graphql

# Select specific modules
grapeql --api https://example.com/graphql --modules fingerprint injection

# Full scan including DoS (may impact availability)
grapeql --api https://example.com/graphql --modules fingerprint info injection auth dos

# Use a pre-captured schema
grapeql --api https://example.com/graphql --schema-file schema.json

# Scan through a proxy
grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080 --auth <token>

# JSON report with credentials and logging
grapeql --api https://example.com/graphql \
    --report results.json --report-format json \
    --username testuser --password testpass \
    --log-file scan.log
```

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--api URL` | URL of the GraphQL endpoint to test (required) |
| `--modules` | Modules to run: `auth`, `dos`, `fingerprint`, `info`, `injection` |
| `--proxy` | HTTP proxy address |
| `--auth` | Authorization token |
| `--auth-type` | Token prefix (default: `Bearer`) |
| `--cookie` | Cookie to include |
| `--schema-file` | JSON introspection schema file |
| `--report` | Output file for the report |
| `--report-format` | `markdown` or `json` |
| `--log-file` | Structured log output |
| `--include` | Restrict YAML test cases |
| `--listener-ip` | Enable OOB injection testing |
| `--listener-port` | Listener port |
| `--ai-key` | API key for AI-assisted analysis |
| `--ai-message` | Guidance passed to the AI agent |

---

## Architecture Overview

GrapeQL follows a top-down modular architecture where the CLI orchestrates shared infrastructure such as logging, test case loading, and baseline tracking. Each security module extends a common base class, ensuring consistent execution patterns and simplifying extensibility.

After module execution, findings can optionally be analyzed by an AI agent before a reporter generates structured output.

**Execution Order:**

1. Fingerprint  
2. Information Disclosure  
3. Injection Testing  
4. Authentication Testing  
5. Denial of Service  
6. AI Analysis (optional)  
7. Reporting  

This predictable flow improves scan reliability and supports statistically informed detection thresholds.

---

## Extending GrapeQL

All test logic is defined in YAML. To add new checks:

1. Create a `.yaml` file in the appropriate `test_cases/` directory  
2. Define payloads, probes, or detection indicators  
3. Run the scanner — new tests load automatically  

No modification to the scanning engine is required.

---

## AI-Assisted Analysis

When an API key is provided, GrapeQL submits findings for post-scan analysis, producing:

- Executive summaries  
- Risk evaluations  
- Recommended remediation steps  
- Coverage gap identification  

This helps teams prioritize remediation and accelerate security reviews.

---

## Library Usage

All components are importable for use in custom automation scripts, enabling integration into broader security workflows and CI/CD pipelines.

---

## Reporting

GrapeQL produces structured security reports in Markdown or JSON, allowing teams to:

- Share findings with stakeholders  
- Track remediation  
- Feed results into security tooling  
- Maintain audit records  
