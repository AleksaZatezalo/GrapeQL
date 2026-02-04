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
- **Authentication & Authorization Testing** — Header bypass, IDOR enumeration, and unauthenticated access checks
- **Denial of Service Testing** — Circular queries, deep nesting, field duplication, fragment bombs, and array batching
- **YAML-Driven Test Cases** — All payloads, probes, and detection rules are defined in YAML for easy extension
- **Baseline-Aware DoS Detection** — Response times from all modules feed a statistical baseline; DoS findings use mean + 3σ thresholds instead of arbitrary cutoffs
- **Structured Logging** — Every request/response pair is logged with module, test name, payload, HTTP verb, status, and timing
- **Comprehensive Reporting** — Generate detailed reports in Markdown or JSON

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

## Architecture

GrapeQL follows a top-down modular design. The CLI orchestrator instantiates shared infrastructure (logger, loader, baseline tracker) and passes it to each module through a uniform interface.

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
                      │  Reporter  │
                      └────────────┘
```

### Execution Order

Modules always run in this order regardless of `--modules` argument order:

1. **Fingerprint** → populates baseline
2. **Info** → populates baseline
3. **Injection** → populates baseline
4. **Auth** → populates baseline
5. **DoS** → reads baseline threshold (mean + 3σ)

### Core Components

| Component | File | Role |
|---|---|---|
| `GraphQLClient` | `client.py` | HTTP client with proxy, auth, cookie support, and structured logging |
| `VulnerabilityTester` | `tester.py` | Base class providing client setup, findings management, and baseline recording |
| `Fingerprinter` | `fingerprint.py` | Engine identification via behavioral probes |
| `InfoTester` | `info_tester.py` | Information disclosure checks |
| `InjectionTester` | `injection_tester.py` | SQL and command injection testing |
| `AuthTester` | `auth_tester.py` | Authentication bypass, IDOR, and unauth access |
| `DosTester` | `dos_tester.py` | Denial of service via query complexity attacks |
| `BaselineTracker` | `baseline.py` | Thread-safe response time statistics across modules |
| `TestCaseLoader` | `loader.py` | YAML test case discovery and parsing |
| `GrapeLogger` | `logger.py` | Structured logging with module/test/payload context |
| `Reporter` | `reporter.py` | Markdown and JSON report generation |

### Test Cases Directory

```
test_cases/
├── fingerprint/    # Engine probe definitions
│   └── engines.yaml
├── info/           # Information disclosure checks
│   └── checks.yaml
├── injection/      # SQLi and command injection payloads
│   ├── sqli.yaml
│   └── command.yaml
├── auth/           # Authentication bypass strategies
│   └── bypasses.yaml
└── dos/            # DoS attack configurations
    └── attacks.yaml
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
    result = await fp.run_test()

    inj = InjectionTester(logger=logger, loader=loader, baseline=baseline)
    await inj.setup_endpoint("https://example.com/graphql", pre_configured_client=client)
    findings = await inj.run_test()

    # Generate report
    reporter = Reporter()
    reporter.set_target("https://example.com/graphql")
    reporter.add_findings(fp.get_findings())
    reporter.add_findings(inj.get_findings())
    reporter.generate_report(output_format="markdown", output_file="report.md")

asyncio.run(scan())
```

## Author

Aleksa Zatezalo