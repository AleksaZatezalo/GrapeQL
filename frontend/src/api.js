// Thin wrapper around the GrapeQL Web API.

async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch (_) {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json();
}

export const api = {
  settings: () => request("/api/settings"),
  listTestCases: () => request("/api/testcases"),
  getTestCase: (module, file) =>
    request(`/api/testcases/${module}/${file}`),
  saveTestCase: (module, file, content) =>
    request(`/api/testcases/${module}/${file}`, {
      method: "PUT",
      body: JSON.stringify({ content }),
    }),
  createTestCase: (module, file, content) =>
    request(`/api/testcases/${module}/${file}`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),
  deleteTestCase: (module, file) =>
    request(`/api/testcases/${module}/${file}`, { method: "DELETE" }),
  scan: (payload) =>
    request("/api/scan", { method: "POST", body: JSON.stringify(payload) }),
  startExploit: (payload) =>
    request("/api/exploit", { method: "POST", body: JSON.stringify(payload) }),
  exploitStatus: (jobId) => request(`/api/exploit/${jobId}`),
  getOllama: () => request("/api/ollama"),
  setOllama: (payload) =>
    request("/api/ollama", { method: "PUT", body: JSON.stringify(payload) }),
  testOllama: (payload) =>
    request("/api/ollama/test", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};
