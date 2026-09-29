import React, { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";
import ScanPanel from "./components/ScanPanel.jsx";
import TestCasePanel from "./components/TestCasePanel.jsx";
import OllamaPanel from "./components/OllamaPanel.jsx";
import DocsPanel from "./components/DocsPanel.jsx";

const TABS = [
  { id: "scan", label: "Scan" },
  { id: "testcases", label: "Test Cases" },
  { id: "ollama", label: "Ollama" },
  { id: "docs", label: "Docs" },
];

export default function App() {
  const [tab, setTab] = useState("scan");
  const [settings, setSettings] = useState(null);

  const loadSettings = useCallback(() => {
    api.settings().then(setSettings).catch(() => setSettings({ modules: [] }));
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  return (
    <div className="app">
      <header className="top">
        <span className="grape">🍇</span>
        <h1>GrapeQL</h1>
      </header>
      <p className="subtitle">
        GraphQL security testing — authorized use only.
      </p>

      <div className="tabs">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "scan" && <ScanPanel settings={settings} />}
      {tab === "testcases" && <TestCasePanel />}
      {tab === "ollama" && <OllamaPanel onSaved={loadSettings} />}
      {tab === "docs" && <DocsPanel />}
    </div>
  );
}
