import React, { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import Findings from "./Findings.jsx";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function formatDate(ts) {
  if (!ts) return "";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch (_) {
    return "";
  }
}

function slugify(text) {
  return (text || "report")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 60);
}

// The list row shows a lightweight summary; derive it from a freshly-fetched
// full report so the collapsed header stays in sync after an edit.
function summaryPatch(report) {
  const result = report?.data?.result || {};
  return {
    name: report.name,
    target: report.target,
    counts: result.counts || {},
    total: result.total ?? 0,
    updated_at: report.updated_at,
  };
}

function ReportRow({ summary, onDeleted, onUpdated }) {
  const [open, setOpen] = useState(false);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Edit state.
  const [editing, setEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState(summary.name);
  const [jsonDraft, setJsonDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  const counts = summary.counts || {};

  async function load() {
    setLoading(true);
    setError("");
    try {
      const full = await api.getReport(summary.id);
      setReport(full);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && !report) load();
  }

  function startEdit() {
    setNameDraft(report?.name ?? summary.name);
    setJsonDraft(JSON.stringify(report?.data ?? {}, null, 2));
    setSaveMsg("");
    setEditing(true);
  }

  async function saveEdit() {
    setSaving(true);
    setSaveMsg("");
    setError("");
    let data;
    try {
      data = JSON.parse(jsonDraft);
    } catch (e) {
      setError("Report JSON is not valid JSON.");
      setSaving(false);
      return;
    }
    try {
      const updated = await api.updateReport(summary.id, {
        name: nameDraft.trim() || null,
        data,
      });
      setReport(updated);
      setEditing(false);
      setSaveMsg("Saved.");
      // Editing the JSON can change the name, target, findings and severity
      // counts — push the full derived summary so the collapsed row matches.
      onUpdated(summary.id, summaryPatch(updated));
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  function exportJson() {
    const payload = report ?? { ...summary };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${slugify(report?.name ?? summary.name)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function remove() {
    if (!window.confirm(`Delete report "${summary.name}"? This cannot be undone.`))
      return;
    try {
      await api.deleteReport(summary.id);
      onDeleted(summary.id);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="report-row">
      <div className="report-head" onClick={toggle}>
        <span className="report-toggle">{open ? "▾" : "▸"}</span>
        <span className="report-name">{summary.name}</span>
        <span className="report-target muted">{summary.target}</span>
        <span className="counts report-counts">
          {SEV_ORDER.map(
            (sev) =>
              counts[sev] > 0 && (
                <span key={sev} className={`chip ${sev}`}>
                  {sev}: {counts[sev]}
                </span>
              )
          )}
          <span className="chip INFO">Total: {summary.total ?? 0}</span>
        </span>
        <span className="report-date muted">{formatDate(summary.created_at)}</span>
      </div>

      {open && (
        <div className="report-body">
          {loading && <p className="muted">Loading…</p>}
          {error && <div className="error">{error}</div>}

          {report && !editing && (
            <>
              <div className="report-actions">
                <button className="secondary small" onClick={startEdit}>
                  ✎ Edit
                </button>
                <button className="secondary small" onClick={exportJson}>
                  ⬇ Export JSON
                </button>
                <button className="secondary small danger" onClick={remove}>
                  🗑 Delete
                </button>
                {saveMsg && <span className="status-ok">{saveMsg}</span>}
              </div>
              <Findings
                result={report.data?.result}
                context={report.data?.context}
              />
            </>
          )}

          {report && editing && (
            <div className="report-edit">
              <label>Report name</label>
              <input
                type="text"
                value={nameDraft}
                onChange={(e) => setNameDraft(e.target.value)}
              />
              <label>Report data (JSON)</label>
              <textarea
                className="code"
                rows={16}
                value={jsonDraft}
                onChange={(e) => setJsonDraft(e.target.value)}
              />
              <div className="report-actions">
                <button className="primary small" onClick={saveEdit} disabled={saving}>
                  {saving && <span className="spinner" />}
                  {saving ? "Saving…" : "Save changes"}
                </button>
                <button
                  className="secondary small"
                  onClick={() => setEditing(false)}
                  disabled={saving}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ReportsPanel({ active }) {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError("");
    api
      .listReports()
      .then(setReports)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  function handleDeleted(id) {
    setReports((prev) => prev.filter((r) => r.id !== id));
  }

  function handleUpdated(id, patch) {
    setReports((prev) =>
      prev.map((r) => (r.id === id ? { ...r, ...patch } : r))
    );
  }

  return (
    <div className="panel">
      <div className="report-toolbar">
        <h3 style={{ margin: 0 }}>Saved reports</h3>
        <button className="secondary small" onClick={load} disabled={loading}>
          {loading && <span className="spinner" />} ↻ Refresh
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      {!loading && reports.length === 0 && (
        <p className="muted">
          No reports yet. Run a scan from the <strong>Scan</strong> tab — each
          scan is saved here as a named report.
        </p>
      )}

      <div className="report-list">
        {reports.map((r) => (
          <ReportRow
            key={r.id}
            summary={r}
            onDeleted={handleDeleted}
            onUpdated={handleUpdated}
          />
        ))}
      </div>
    </div>
  );
}
