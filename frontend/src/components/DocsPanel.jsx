import React from "react";

function Code({ children }) {
  return <pre className="code-block">{children}</pre>;
}

export default function DocsPanel() {
  return (
    <div className="panel docs">
      <h2 style={{ marginTop: 0 }}>Writing test cases</h2>
      <p>
        GrapeQL is driven by YAML test-case files — no code changes are needed to
        add coverage. Files live under a per-module directory and every file has a
        single top-level <code>test_cases:</code> list. Manage them from the{" "}
        <strong>Test Cases</strong> tab (edit, create, upload, delete); each save
        is validated for this structure.
      </p>

      <Code>{`test_cases/
├── fingerprint/   engine detection probes
├── info/          information-disclosure checks
├── injection/     sqli / command / nosql payloads
├── auth/          authentication-bypass strategies
└── dos/           denial-of-service techniques`}</Code>

      <p>
        Files in the same module directory are merged in filename order, so you
        can split payloads across multiple files. The module a file lives in
        decides which fields each test case needs, described below.
      </p>

      <h3>Injection — <span className="muted">injection/*.yaml</span></h3>
      <p>
        A payload string plus the response substrings that prove it worked. The
        tester injects <code>payload</code> into every String/ID argument and
        flags a finding if any <code>indicators</code> string appears in the
        response.
      </p>
      <Code>{`test_cases:
  - name: single_quote
    payload: "'"
    indicators:
      - "SQL syntax"
      - "SQLite"
      - "ERROR: syntax error at or near"`}</Code>
      <p className="muted">
        Tip: YAML anchors (<code>&amp;name</code> / <code>*name</code>) let many
        payloads share one indicator list, as the bundled <code>sqli.yaml</code>{" "}
        does.
      </p>

      <h3>Auth — <span className="muted">auth/*.yaml</span></h3>
      <p>
        Each case swaps in a set of headers and checks whether a
        normally-protected operation still succeeds.
      </p>
      <Code>{`test_cases:
  - name: jwt_alg_none
    strategy: header_bypass
    headers:
      Authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<claims>."
    description: "JWT with alg:none — admin claim"

  - name: no_auth_header
    strategy: header_bypass
    headers: {}
    description: "Strip all authentication headers"`}</Code>

      <h3>Info — <span className="muted">info/*.yaml</span></h3>
      <p>
        A self-describing check: the query to send and how to detect a positive.
        The finding metadata (<code>title</code>, <code>severity</code>,{" "}
        <code>impact</code>, <code>remediation</code>) is reported verbatim.
      </p>
      <Code>{`test_cases:
  - name: field_suggestions
    title: "Field Suggestions Enabled"
    severity: LOW
    description: "Server provides field suggestions in error messages"
    impact: "Information Leakage - schema details disclosed"
    remediation: "Disable field suggestions in production"
    method: POST
    query: "query { __schema { directive } }"
    detection:
      type: error_contains      # match against returned errors
      value: "did you mean"
      case_insensitive: true`}</Code>

      <h3>DoS — <span className="muted">dos/*.yaml</span></h3>
      <p>
        Each case names a built-in <code>generator</code> that builds a
        schema-aware query, plus tuning parameters. ⚠️ DoS runs can render the
        target unresponsive.
      </p>
      <Code>{`test_cases:
  - name: circular_query
    title: "Circular Query DoS"
    generator: generate_circular_query   # built-in generator
    severity: HIGH
    description: "Deeply nested circular query exploiting self-references"
    impact: "Server resource exhaustion"
    remediation: "Implement query depth limiting and cost analysis"
    depth: 10          # generator-specific tuning
    duplicates: 3`}</Code>

      <h3>Fingerprint — <span className="muted">fingerprint/*.yaml</span></h3>
      <p>
        Each engine defines probe queries and the error signature that identifies
        it.
      </p>
      <Code>{`test_cases:
  - engine_id: apollo
    name: Apollo Server
    url: https://www.apollographql.com/
    tech: [Node.js, JavaScript]
    cve: [CVE-2023-30783]
    probes:
      - query: 'query @skip { __typename }'
        expect_error: 'Directive "@skip" argument "if" of type "Boolean!" is required'`}</Code>

      <h3>Running a subset</h3>
      <p>
        On the <strong>Scan</strong> tab, pick which modules to run. From the CLI
        you can also restrict to specific files with{" "}
        <code>--include sqli.yaml command.yaml</code>. New and uploaded files are
        picked up automatically on the next scan.
      </p>

      <p className="muted">
        Authorized testing only. Keep payloads non-destructive — GrapeQL is for
        assessing endpoints you own or have permission to test.
      </p>
    </div>
  );
}
