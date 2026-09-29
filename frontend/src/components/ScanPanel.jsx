import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import Findings from "./Findings.jsx";

export default function ScanPanel({ settings }) {
  const allModules = settings?.modules || [
    "fingerprint",
    "info",
    "injection",
    "auth",
    "dos",
  ];

  const [target, setTarget] = useState("");
  const [selected, setSelected] = useState(["fingerprint", "info", "injection", "auth"]);
  const [aiAnalysis, setAiAnalysis] = useState(false);
  const [auth, setAuth] = useState("");
  const [schemaText, setSchemaText] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  // Context captured from the scan that produced `result`, reused by the
  // per-finding exploit generator.
  const [scanContext, setScanContext] = useState(null);

  const qwenModel = settings?.qwen_model;

  useEffect(() => {
    if (settings?.modules) setSelected(settings.modules.filter((m) => m !== "dos"));
  }, [settings]);

  function toggleModule(m) {
    setSelected((prev) =>
      prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]
    );
  }

  async function runScan() {
    setError("");
    setResult(null);
    if (!target.trim()) {
      setError("Enter a target GraphQL endpoint URL.");
      return;
    }

    let graphql_schema = null;
    if (schemaText.trim()) {
      try {
        graphql_schema = JSON.parse(schemaText);
      } catch (e) {
        setError("Schema JSON is not valid JSON.");
        return;
      }
    }

    setRunning(true);
    try {
      const payload = {
        target: target.trim(),
        modules: selected,
        auth: auth.trim() || null,
        ai_analysis: aiAnalysis,
        graphql_schema,
      };
      const res = await api.scan(payload);
      setResult(res);
      setScanContext({
        target: res.target || target.trim(),
        auth: auth.trim() || null,
        // Prefer the schema introspected during the scan; fall back to a
        // manually pasted one. This gives the exploit agent real field names.
        graphql_schema: res.schema || graphql_schema,
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <div className="panel">
        <label>Target GraphQL endpoint</label>
        <input
          type="text"
          placeholder="http://127.0.0.1:5013/graphql"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />

        <label>Modules</label>
        <div className="modules">
          {allModules.map((m) => (
            <label key={m}>
              <input
                type="checkbox"
                checked={selected.includes(m)}
                onChange={() => toggleModule(m)}
              />
              {m}
              {m === "dos" ? " ⚠️" : ""}
            </label>
          ))}
        </div>

        <div className="row">
          <div>
            <label>Authorization token (optional)</label>
            <input
              type="text"
              placeholder="eyJhbGci..."
              value={auth}
              onChange={(e) => setAuth(e.target.value)}
            />
          </div>
        </div>

        <label>AI analysis</label>
        <div className="modules">
          <label>
            <input
              type="checkbox"
              checked={aiAnalysis}
              onChange={(e) => setAiAnalysis(e.target.checked)}
            />
            Summarise findings with Qwen{qwenModel ? ` (${qwenModel})` : ""}
          </label>
        </div>
        <div className="hint">
          Runs a local Qwen model over the findings and schema for an executive
          summary and next steps. Configure the model in the Ollama tab.
        </div>

        <label>Schema JSON (optional — used if introspection is disabled)</label>
        <textarea
          className="code"
          rows={4}
          placeholder='{ "__schema": { ... } }'
          value={schemaText}
          onChange={(e) => setSchemaText(e.target.value)}
        />

        <button className="primary" onClick={runScan} disabled={running}>
          {running && <span className="spinner" />}
          {running ? "Scanning…" : "Run scan"}
        </button>

        {error && <div className="error">{error}</div>}
      </div>

      <Findings result={result} context={scanContext} />
    </>
  );
}
