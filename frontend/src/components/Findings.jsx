import React, { useState } from "react";
import ReactMarkdown from "react-markdown";
import { api } from "../api.js";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function slugify(text) {
  return (text || "exploit")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
}

function ExploitControls({ finding, context }) {
  // state: idle | running | done | error
  const [state, setState] = useState("idle");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  const canRun = !!context; // need a scan context (target etc.)

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function generate() {
    setState("running");
    setError("");
    setData(null);
    try {
      const { job_id } = await api.startExploit({
        target: context.target,
        finding,
        graphql_schema: context.graphql_schema || null,
        auth: context.auth || null,
      });

      // Poll until the background job finishes. Local-model exploit generation
      // can take minutes, so each request here is short and never times out.
      // Cap total wait at ~20 minutes.
      for (let i = 0; i < 400; i++) {
        await sleep(3000);
        const job = await api.exploitStatus(job_id);
        if (job.status === "done") {
          setData(job.result);
          setState("done");
          return;
        }
        if (job.status === "error") {
          setError(job.error || "Exploit generation failed.");
          setState("error");
          return;
        }
      }
      setError("Timed out waiting for the exploit agent.");
      setState("error");
    } catch (e) {
      setError(e.message);
      setState("error");
    }
  }

  function download() {
    if (!data?.exploit_code) return;
    const blob = new Blob([data.exploit_code], { type: "text/x-python" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `exploit_${slugify(finding.title)}.py`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="exploit">
      <div className="exploit-bar">
        <button
          className="secondary small"
          onClick={generate}
          disabled={state === "running" || !canRun}
          title={
            canRun
              ? "Agentically build and verify a safe PoC against the live target"
              : "Run a scan first so the target is known"
          }
        >
          {state === "running" && <span className="spinner" />}
          {state === "running"
            ? "Building exploit…"
            : state === "done"
            ? "Regenerate exploit"
            : "🧪 Generate exploit"}
        </button>

        {state === "done" && data && (
          <>
            <button className="secondary small" onClick={download}>
              ⬇ Download exploit.py
            </button>
            <span className={data.confirmed ? "status-ok" : "status-warn"}>
              {data.confirmed
                ? `✓ Verified in ${data.iterations} request(s)`
                : `⚠ Unverified (${data.iterations} request(s))`}
            </span>
          </>
        )}
      </div>

      {state === "running" && (
        <div className="hint">
          The agent is crafting a benign (whoami) payload, firing it at the live
          endpoint, and checking the response — retrying until confirmed or the
          iteration cap is reached.
        </div>
      )}

      {state === "error" && <div className="error">{error}</div>}

      {state === "done" && data && (
        <div className="exploit-result">
          {data.explanation && <p className="muted">{data.explanation}</p>}
          <details>
            <summary>View exploit.py</summary>
            <pre className="code-block">{data.exploit_code}</pre>
          </details>
        </div>
      )}
    </div>
  );
}

export default function Findings({ result, context }) {
  if (!result) return null;

  const { counts = {}, findings = [], ai_analysis, target, total } = result;

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>
        Results for <span className="muted">{target}</span>
      </h3>

      <div className="counts">
        {SEV_ORDER.map(
          (sev) =>
            counts[sev] > 0 && (
              <span key={sev} className={`chip ${sev}`}>
                {sev}: {counts[sev]}
              </span>
            )
        )}
        <span className="chip INFO">Total: {total ?? findings.length}</span>
      </div>

      {findings.length === 0 && (
        <p className="status-ok">No vulnerabilities found. 🎉</p>
      )}

      {findings.map((f, i) => (
        <div key={i} className={`finding ${f.severity}`}>
          <h4>
            <span className={`sev chip ${f.severity}`}>{f.severity}</span>
            {f.title}
          </h4>
          <div className="meta">{f.endpoint}</div>
          {f.description && (
            <p>
              <span className="k">Description: </span>
              {f.description}
            </p>
          )}
          {f.impact && (
            <p>
              <span className="k">Impact: </span>
              {f.impact}
            </p>
          )}
          {f.remediation && (
            <p>
              <span className="k">Remediation: </span>
              {f.remediation}
            </p>
          )}
          <ExploitControls finding={f} context={context} />
        </div>
      ))}

      {ai_analysis && (
        <div className="ai">
          <ReactMarkdown>{ai_analysis}</ReactMarkdown>
        </div>
      )}
    </div>
  );
}
