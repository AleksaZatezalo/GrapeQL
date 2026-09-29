import React, { useEffect, useState } from "react";
import { api } from "../api.js";

export default function OllamaPanel({ onSaved }) {
  const [cfg, setCfg] = useState(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState(null);

  async function load() {
    setError("");
    try {
      const data = await api.getOllama();
      setCfg(data);
      setBaseUrl(data.base_url || "");
      setModel(data.model || "");
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function save() {
    setBusy(true);
    setError("");
    setStatus("");
    try {
      const data = await api.setOllama({ base_url: baseUrl, model });
      setCfg(data);
      setBaseUrl(data.base_url || "");
      setModel(data.model || "");
      setStatus("Configuration saved.");
      onSaved && onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setError("");
    setStatus("");
    setTestResult(null);
    try {
      const data = await api.testOllama({ base_url: baseUrl });
      setTestResult(data);
      setStatus(`Connected — ${data.models.length} model(s) available.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function resetDefaults() {
    setBusy(true);
    setError("");
    setStatus("");
    try {
      const data = await api.setOllama({ base_url: "", model: "" });
      setCfg(data);
      setBaseUrl(data.base_url || "");
      setModel(data.model || "");
      setStatus("Reset to environment defaults.");
      onSaved && onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Ollama / Qwen configuration</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        AI analysis and the exploit agent talk to a Qwen model over an
        OpenAI-compatible API. By default this is a local Ollama server. Changes
        here apply immediately to new scans and exploit generations.
      </p>

      <label>Base URL (OpenAI-compatible)</label>
      <input
        type="text"
        placeholder="http://localhost:11434/v1"
        value={baseUrl}
        onChange={(e) => setBaseUrl(e.target.value)}
      />
      <div className="hint">
        For a local Ollama server this is <code>http://localhost:11434/v1</code>.
      </div>

      <label>Model</label>
      <input
        type="text"
        placeholder="qwen2.5-coder:7b"
        value={model}
        onChange={(e) => setModel(e.target.value)}
      />
      <div className="hint">
        Must be a model you have pulled in Ollama (e.g.{" "}
        <code>ollama pull qwen2.5-coder:7b</code>). Use “Test connection” to list
        available models.
      </div>

      <div className="toolbar" style={{ marginTop: 16 }}>
        <button className="primary" onClick={save} disabled={busy}>
          {busy && <span className="spinner" />}
          Save
        </button>
        <button className="secondary" onClick={test} disabled={busy}>
          Test connection
        </button>
        <button className="secondary" onClick={resetDefaults} disabled={busy}>
          Reset to defaults
        </button>
        {status && <span className="status-ok">{status}</span>}
      </div>

      {error && <div className="error">{error}</div>}

      {cfg && (
        <div className="hint" style={{ marginTop: 14 }}>
          Environment defaults — base URL: <code>{cfg.default_base_url}</code>,
          model: <code>{cfg.default_model}</code>
          {cfg.override_active ? " (currently overridden above)" : ""}
        </div>
      )}

      {testResult && testResult.models.length > 0 && (
        <div className="exploit-result">
          <label>Available models at {testResult.base_url}</label>
          <div className="modules" style={{ marginTop: 4 }}>
            {testResult.models.map((m) => (
              <button
                key={m}
                className="secondary small"
                onClick={() => setModel(m)}
                title="Click to use this model"
              >
                {m}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
