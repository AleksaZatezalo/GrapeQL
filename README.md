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

## Web UI (Docker)

GrapeQL ships with a containerized React web interface for running scans,
editing or uploading YAML test cases, configuring the AI model, and viewing
findings (including optional AI-assisted analysis) in the browser.

AI features (post-scan analysis and the per-finding exploit agent) run entirely
locally against a **Qwen** model served over an OpenAI-compatible API — by
default a local [Ollama](https://ollama.com) server. **No API keys are
required.** Pull a model first:

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
Docker volume, so they survive container restarts.

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
  disabled), and tick **AI analysis** to have Qwen summarise the findings.
  Click **Run scan** to see findings grouped by severity.
- **Generate exploit (per finding)** — Each finding shows a **🧪 Generate
  exploit** button. It runs an agentic loop: the agent crafts a GraphQL payload
  carrying a harmless test command (`whoami`), fires it at the live endpoint,
  inspects the response for proof, and retries up to an iteration cap. A spinner
  shows while it works. Once done it produces a self-contained `exploit.py` you
  can review inline and **⬇ Download**. The live requests are always sent to the
  scanned target only — the agent supplies the query, never the destination.
  Payloads are non-destructive proofs of exploitability, for authorized testing
  only.
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

Run a scan with local AI-assisted analysis (requires Ollama + a pulled model):

```bash
grapeql --api https://example.com/graphql --ai
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

# Scan with credentials and structured logging
grapeql --api https://example.com/graphql \
    --username testuser --password testpass \
    --log-file scan.log

# AI-assisted analysis with a specific local model
grapeql --api https://example.com/graphql \
    --ai --ai-model qwen2.5-coder:7b
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
| `--log-file` | Structured log output |
| `--include` | Restrict YAML test cases |
| `--listener-ip` | Enable OOB injection testing |
| `--listener-port` | Listener port |
| `--ai` | Enable AI-assisted analysis (local Qwen via Ollama) |
| `--ai-url` | OpenAI-compatible base URL (default `http://localhost:11434/v1`) |
| `--ai-model` | Qwen model/tag (default `qwen2.5-coder:7b`) |

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

---

## Contributing

Contributions are welcome. When adding new test cases or modules, maintain consistency with the existing architecture and YAML schema to ensure predictable execution behavior.

---

## License
MIT License.
