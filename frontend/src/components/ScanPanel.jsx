import React, { useEffect, useState } from "react";
import { api } from "../api.js";

export default function ScanPanel({ settings }) {
  const allModules = settings?.modules || [
    "fingerprint",
    "info",
    "injection",
    "auth",
    "dos",
  ];

  const [target, setTarget] = useState("");
  const [reportName, setReportName] = useState("");
  const [selected, setSelected] = useState(["fingerprint", "info", "injection", "auth"]);
  const [auth, setAuth] = useState("");
  const [schemaText, setSchemaText] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  // Result of saving the scan as a report — findings themselves live only in
  // the Reports tab, never on this tab.
  const [saved, setSaved] = useState(null);

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
    setSaved(null);
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
        name: reportName.trim() || null,
        modules: selected,
        auth: auth.trim() || null,
        graphql_schema,
      };
      const res = await api.scan(payload);
      setSaved(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <div className="panel">
        <label>Report name (optional)</label>
        <input
          type="text"
          placeholder="e.g. Prod API — Q3 assessment"
          value={reportName}
          onChange={(e) => setReportName(e.target.value)}
        />
        <div className="hint">
          Results are saved as a named report in the Reports tab. Leave blank to
          auto-name it after the target.
        </div>

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

        {saved && (
          <div className="status-ok" style={{ marginTop: "1rem" }}>
            ✓ Scan complete — saved as report{" "}
            <strong>{saved.name}</strong>. Open the <strong>Reports</strong> tab
            to view, expand and edit the findings.
          </div>
        )}
      </div>
    </>
  );
}
