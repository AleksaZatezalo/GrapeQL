[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# GrapeQL

GrapeQL is a modular security testing platform designed to identify vulnerabilities, misconfigurations, and attack paths within GraphQL APIs through dynamic analysis.

Built for security engineers and developers, GrapeQL combines automated testing, YAML-driven payload execution, structured logging, and AI-assisted exploit generation to support modern application security workflows.

## Why GrapeQL?

GraphQL introduces unique attack surfaces that traditional API scanners often overlook. GrapeQL focuses specifically on these risks, enabling teams to proactively assess security posture before deployment.

With GrapeQL, teams can:

- Detect injection vulnerabilities across queries and mutations
- Identify authentication and authorization weaknesses
- Discover information disclosure exposures
- Validate denial-of-service resilience
- Generate verified, non-destructive proof-of-concept exploits for findings
- Persist scans and PoCs as reviewable reports

Whether used for standalone security assessments or integrated into automated pipelines, GrapeQL helps organizations shift security testing earlier in the development lifecycle.

---

## Overview

GrapeQL is a modular GraphQL security scanner that identifies common vulnerabilities and misconfigurations in GraphQL endpoints. It ships with a command-line interface for quick assessments, a Python library for integration into custom security workflows, and a React web interface for running scans, managing test cases, and generating exploit proofs-of-concept. Test logic is driven by YAML definitions, making it easy to extend coverage without modifying application code.

---

## Key Capabilities

- **GraphQL Fingerprinting** — Identify the underlying GraphQL engine through behavioral probes
- **Information Disclosure Testing** — Detect introspection leaks, field suggestions, GraphiQL exposure, batch query support, and alternate transport acceptance
- **SQL Injection Testing** — Test all String/ID arguments across queries and mutations
- **Command Injection Testing** — Detect OS command execution vectors
- **NoSQL Injection Testing** — Probe MongoDB/CouchDB operator and `$where` injection behind resolvers
- **Authentication & Authorization Testing** — Header bypass, IDOR enumeration, and unauthenticated access checks
- **Denial of Service Testing** — Evaluate query complexity attacks such as deep nesting and fragment bombs
- **AI-Assisted Exploit Generation** — Produce a verified, non-destructive proof-of-concept `exploit.py` for a finding, reusing the exact payload that confirmed it (local Qwen via Ollama; no API keys)
- **YAML-Driven Test Cases** — Extend testing coverage without touching core code
- **Structured Logging** — Capture detailed request/response telemetry
- **Persistent Reports & Exploits** — The web UI saves each scan as an editable report and each generated PoC as an exploit in a local SQLite database, so they survive refreshes and restarts

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

## Web UI (Docker)

GrapeQL ships with a containerized React web interface for running scans,
editing or uploading YAML test cases, configuring the AI model, generating
per-finding exploit PoCs, and reviewing saved reports and exploits in the
browser.

The exploit agent runs entirely locally against a **Qwen** model served over an
OpenAI-compatible API — by default a local [Ollama](https://ollama.com) server.
**No API keys are required.** Pull a model first:

```bash
ollama pull qwen2.5-coder:7b
```

### Run with Docker Compose (recommended)

```bash
# From the repository root — build and start the app
docker compose up --build

# Then open:
#   http://localhost:8000
```

The container uses **host networking**, so:

- You can scan targets by `localhost`, `127.0.0.1`, or any host IP directly —
  e.g. `http://127.0.0.1:5013/graphql` for a local DVGA instance.
- The app reaches your local Ollama on `127.0.0.1:11434` with no extra setup.

Override the model or endpoint via environment variables if needed:

```bash
QWEN_MODEL=qwen2.5-coder:7b QWEN_BASE_URL=http://localhost:11434/v1 \
  docker compose up --build
```

Editable and uploaded test cases are persisted in the `grapeql-testcases`
Docker volume, so they survive container restarts. Saved reports and exploits
are stored in SQLite (`reports.db` / `exploits.db`); their location is
configurable with the `GRAPEQL_REPORTS_DB` and `GRAPEQL_EXPLOITS_DB`
environment variables.

### Run with plain Docker

```bash
docker build -t grapeql-ui:latest .
docker run --rm --network host \
  -v grapeql-testcases:/data/test_cases \
  grapeql-ui:latest
# open http://localhost:8000
```

### Using the interface

- **Scan tab** — Enter the target GraphQL endpoint (e.g.
  `http://127.0.0.1:5013/graphql`), choose which modules to run, optionally add
  an authorization token and a schema JSON (used when introspection is
  disabled), and give the scan a report name. Click **Run scan** — each scan is
  saved as a named **report**; the Scan tab itself does not render findings, it
  points you to the Reports tab.
- **Reports tab** — Browse saved scans (persisted to SQLite, newest first).
  Expand a report to see its findings grouped by severity, rename or edit it, or
  delete it. Each finding carries the exact request the scanner used to trigger
  it (its `evidence`) and offers a **🧪 Generate exploit** button.
- **Generate exploit (per finding)** — Produces a self-contained, non-destructive
  `exploit.py`. When the scanner confirmed the finding with a concrete request
  (e.g. injection), the PoC **reuses the exact payload that confirmed the
  vulnerability**: it replays the scanner's confirming request against the live
  endpoint and verifies it the same way the scanner did — by looking for the
  indicator the scanner matched. This path is deterministic and does not involve
  the model. For a finding with no captured request, an agentic loop drives the
  local **Qwen** model to craft and verify a PoC, proving execution by making the
  target echo a unique per-run token (`GRAPEQL_PROOF_…`). Either way, only two
  functions in a fixed template are filled — `build_request()` and
  `check_success()` — while the transport and `main()` stay fixed, and live
  requests are always sent to the scanned target only (the agent supplies the
  query, never the destination). A finding is marked **CONFIRMED** only when
  verification actually succeeded against a live response; otherwise the PoC ships
  the real confirming request marked **UNVERIFIED**. For authorized testing only.
- **Exploits tab** — Browse generated PoCs (persisted to SQLite). Expand one to
  read its explanation and code, see whether it is **✓ Verified** or
  **⚠ Unverified**, **⬇ Download** the `exploit.py`, rename, or delete it. Running
  the downloaded script self-verifies against the live response.
- **Test Cases tab** — Browse the bundled YAML test cases by module, edit them
  in place, create new files, upload your own `.yaml` files, or delete them.
  Every save is validated to ensure it has a proper `test_cases:` structure.
- **Ollama tab** — Set the Qwen base URL and model at runtime, test the
  connection (lists the models available on your Ollama server), or reset to the
  environment defaults.
- **Docs tab** — In-app reference for how test cases are structured per module.

> ⚠️ GrapeQL is an active security testing tool. Only scan endpoints you are
> authorized to test. The DoS module can render a target unresponsive.

### Local development (without Docker)

Run the API and the Vite dev server separately:

```bash
# Terminal 1 — backend API on :8000
pip install -e .
pip install -r webapi/requirements.txt
uvicorn webapi.server:app --reload --port 8000

# Terminal 2 — frontend dev server on :5173 (proxies /api to :8000)
cd frontend
npm install
npm run dev
# open http://localhost:5173
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

By default all modules except the destructive `dos` module run. Findings are
printed to the console as a severity-grouped summary.

---

## Command Line Usage

```bash
# Basic scan
grapeql --api https://example.com/graphql

# Select specific modules
grapeql --api https://example.com/graphql --modules fingerprint injection

# Full scan including DoS (may impact availability)
grapeql --api https://example.com/graphql --modules fingerprint info injection auth dos

# Use a pre-captured schema (introspection is still probed but not required)
grapeql --api https://example.com/graphql --schema-file schema.json

# Scan through a proxy with an auth token
grapeql --api https://example.com/graphql --proxy 127.0.0.1:8080 --auth <token>

# Scan with credentials and structured logging
grapeql --api https://example.com/graphql \
    --username testuser --password testpass \
    --log-file scan.log

# Restrict to specific YAML test-case files
grapeql --api https://example.com/graphql --modules injection --include sqli command
```

---

## CLI Options

| Option | Description |
|--------|-------------|
| `--api URL` | URL of the GraphQL endpoint to test (required) |
| `--modules` | Modules to run: `auth`, `dos`, `fingerprint`, `info`, `injection` (default: all except `dos`) |
| `--proxy` | HTTP proxy address (`host:port`) |
| `--auth` | Authorization token |
| `--auth-type` | Token prefix (default: `Bearer`) |
| `--cookie` | Cookie in `name:value` form (repeatable) |
| `--username` | Username for injection/auth testing |
| `--password` | Password for injection/auth testing |
| `--schema-file` | JSON introspection schema file (used when introspection is disabled) |
| `--include` | Restrict to specific YAML test-case files (basename, extension optional) |
| `--test-cases` | Directory of YAML test cases (default: bundled) |
| `--log-file` | Path to structured log output (default: stdout) |

---

## Architecture Overview

GrapeQL follows a top-down modular architecture where the CLI orchestrates shared infrastructure such as logging, test case loading, and baseline tracking. Each security module extends a common base class, ensuring consistent execution patterns and simplifying extensibility.

After module execution, a reporter prints a severity-grouped summary (CLI) or the web API persists the findings as a saved report.

**Execution Order:**

1. Fingerprint
2. Information Disclosure
3. Injection Testing
4. Authentication Testing
5. Denial of Service
6. Reporting

This predictable flow improves scan reliability and supports statistically informed detection thresholds.

---

## Extending GrapeQL

All test logic is defined in YAML. To add new checks:

1. Create a `.yaml` file in the appropriate `test_cases/` directory
2. Define payloads, probes, or detection indicators
3. Run the scanner — new tests load automatically

No modification to the scanning engine is required.

---

## AI-Assisted Exploit Generation

GrapeQL's only AI feature is the per-finding **exploit agent**, exposed in the
web UI. It runs entirely locally against a **Qwen** model served over an
OpenAI-compatible API (Ollama by default) — **no API keys required**. Given a
single finding it produces a verified, non-destructive `exploit.py`:

- **Evidence-based (preferred).** When the scanner captured the request that
  confirmed the finding, the PoC reuses that exact payload and verifies via the
  indicator the scanner matched — deterministic, with no model call.
- **Agentic fallback.** For a finding with no captured request, an agentic loop
  crafts and verifies a PoC against the live endpoint, proving execution by
  making the target echo a unique per-run token.

Live requests are always sent to the scanned target only. A PoC is marked
**CONFIRMED** only when verification actually succeeded; otherwise it ships the
real confirming request marked **UNVERIFIED**. Generated exploits are saved to
the Exploits tab and can be reviewed, downloaded, and re-run to self-verify.

---

## Library Usage

All components are importable for use in custom automation scripts, enabling integration into broader security workflows and CI/CD pipelines.

---

## Reporting

The CLI prints a severity-grouped summary of findings to the console. In the web
UI, every scan is persisted as a named **report** (SQLite) that can be expanded,
renamed, edited, and deleted, and every generated proof-of-concept is persisted
as an **exploit** — both survive server restarts. This lets teams:

- Share findings with stakeholders
- Track remediation
- Keep confirmed PoCs alongside the findings they prove
- Maintain audit records

---

## Contributing

Contributions are welcome. When adding new test cases or modules, maintain consistency with the existing architecture and YAML schema to ensure predictable execution behavior.

---

## License
MIT License.
