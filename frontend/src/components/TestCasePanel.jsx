import React, { useEffect, useRef, useState } from "react";
import { api } from "../api.js";

const NEW_TEMPLATE = `test_cases:
  - name: example_case
    payload: "'"
    indicators:
      - "SQL syntax"
`;

export default function TestCasePanel() {
  const [files, setFiles] = useState([]);
  const [active, setActive] = useState(null); // {module, file}
  const [content, setContent] = useState("");
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const uploadRef = useRef(null);

  async function refresh() {
    try {
      const list = await api.listTestCases();
      setFiles(list);
      return list;
    } catch (e) {
      setError(e.message);
      return [];
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function open(module, file) {
    setError("");
    setStatus("");
    try {
      const data = await api.getTestCase(module, file);
      setActive({ module, file });
      setContent(data.content);
      setDirty(false);
    } catch (e) {
      setError(e.message);
    }
  }

  async function save() {
    if (!active) return;
    setBusy(true);
    setError("");
    setStatus("");
    try {
      await api.saveTestCase(active.module, active.file, content);
      setStatus(`Saved ${active.module}/${active.file}`);
      setDirty(false);
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function createNew() {
    const module = prompt(
      "Module (e.g. injection, auth, info, dos, fingerprint):"
    );
    if (!module) return;
    let file = prompt("New file name (e.g. custom.yaml):");
    if (!file) return;
    setBusy(true);
    setError("");
    setStatus("");
    try {
      await api.createTestCase(module.trim(), file.trim(), NEW_TEMPLATE);
      await refresh();
      await open(module.trim(), file.trim().endsWith(".yaml") || file.trim().endsWith(".yml") ? file.trim() : file.trim() + ".yaml");
      setStatus("Created new test case file.");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!active) return;
    if (!confirm(`Delete ${active.module}/${active.file}?`)) return;
    setBusy(true);
    try {
      await api.deleteTestCase(active.module, active.file);
      setActive(null);
      setContent("");
      setStatus("Deleted.");
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function onUpload(e) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const module = prompt(
      "Which module should this file go into? (e.g. injection)"
    );
    if (!module) return;
    const text = await file.text();
    setBusy(true);
    setError("");
    setStatus("");
    try {
      // Try create; if it exists, overwrite via PUT.
      try {
        await api.createTestCase(module.trim(), file.name, text);
      } catch (err) {
        await api.saveTestCase(module.trim(), file.name, text);
      }
      await refresh();
      await open(module.trim(), file.name);
      setStatus(`Uploaded ${file.name}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  // Group files by module for display.
  const byModule = {};
  files.forEach((f) => {
    (byModule[f.module] = byModule[f.module] || []).push(f);
  });

  return (
    <div className="panel">
      <div className="toolbar">
        <button className="secondary" onClick={createNew} disabled={busy}>
          + New file
        </button>
        <button
          className="secondary"
          onClick={() => uploadRef.current?.click()}
          disabled={busy}
        >
          ⬆ Upload YAML
        </button>
        <input
          ref={uploadRef}
          type="file"
          accept=".yaml,.yml"
          style={{ display: "none" }}
          onChange={onUpload}
        />
        {status && <span className="status-ok">{status}</span>}
      </div>

      {error && <div className="error">{error}</div>}

      <div className="tc-layout">
        <div className="tc-list">
          {Object.keys(byModule)
            .sort()
            .map((module) => (
              <div key={module}>
                <div className="tc-module">{module}</div>
                {byModule[module].map((f) => (
                  <div
                    key={f.file}
                    className={
                      "tc-item" +
                      (active &&
                      active.module === module &&
                      active.file === f.file
                        ? " active"
                        : "")
                    }
                    onClick={() => open(module, f.file)}
                  >
                    <span>{f.file}</span>
                    <span className="count">{f.count}</span>
                  </div>
                ))}
              </div>
            ))}
          {files.length === 0 && (
            <p className="muted">No test case files found.</p>
          )}
        </div>

        <div className="tc-editor">
          {active ? (
            <>
              <div className="toolbar">
                <strong>
                  {active.module}/{active.file}
                </strong>
                <button className="secondary" onClick={save} disabled={busy || !dirty}>
                  {busy ? "…" : "Save"}
                </button>
                <button className="secondary danger" onClick={remove} disabled={busy}>
                  Delete
                </button>
                {dirty && <span className="muted">unsaved changes</span>}
              </div>
              <textarea
                className="code"
                rows={22}
                value={content}
                onChange={(e) => {
                  setContent(e.target.value);
                  setDirty(true);
                }}
              />
              <div className="hint">
                YAML must have a top-level <code>test_cases:</code> list. It is
                validated on save.
              </div>
            </>
          ) : (
            <p className="muted">
              Select a file to edit, or create/upload a new one.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
