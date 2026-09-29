"""
GrapeQL Web API — FastAPI backend.

Exposes:
  GET    /api/health
  GET    /api/settings                     -> {modules: [...], qwen_base_url, qwen_model}
  GET    /api/ollama                        -> current + default Qwen/Ollama config
  PUT    /api/ollama                        -> set runtime Qwen/Ollama overrides
  POST   /api/ollama/test                   -> probe an endpoint's model list
  GET    /api/testcases                    -> list of {module, file, cases}
  GET    /api/testcases/{module}/{file}    -> raw YAML text
  PUT    /api/testcases/{module}/{file}    -> save / edit YAML (validated)
  POST   /api/testcases/{module}/{file}    -> create new YAML file (validated)
  DELETE /api/testcases/{module}/{file}    -> remove a YAML file
  POST   /api/scan                         -> run a scan, return findings + AI analysis
  POST   /api/exploit                      -> start an exploit-generation job -> {job_id}
  GET    /api/exploit/{job_id}             -> poll job status/result

The bundled test cases are copied into a writable directory on first start so
they can be edited and extended from the UI without touching the package.
"""

import asyncio
import os
import re
import shutil
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import grapeql
from grapeql.qwen import get_base_url, get_model
from .scan_runner import run_scan, ScanError, ALL_MODULES
from .exploit_agent import generate_exploit, ExploitAgentError

# The scan modules print findings (which contain em dashes and other non-ASCII
# characters) to stdout/stderr. On a host/container without a UTF-8 locale the
# default stream encoding can be ASCII, which raises UnicodeEncodeError mid-scan.
# Force UTF-8 on the standard streams so printing findings never crashes a scan.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
        pass

# --------------------------------------------------------------------------- #
#  Paths / config
# --------------------------------------------------------------------------- #

_BUNDLED_TC = Path(grapeql.__file__).resolve().parent / "test_cases"
TESTCASES_DIR = Path(
    os.environ.get("GRAPEQL_TESTCASES_DIR", str(_BUNDLED_TC))
).resolve()
STATIC_DIR = Path(os.environ.get("GRAPEQL_STATIC_DIR", "frontend/dist")).resolve()

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _seed_testcases() -> None:
    """Copy bundled YAML test cases into the writable dir if it is empty."""
    if TESTCASES_DIR == _BUNDLED_TC:
        return
    TESTCASES_DIR.mkdir(parents=True, exist_ok=True)
    already = any(TESTCASES_DIR.rglob("*.y*ml"))
    if not already and _BUNDLED_TC.is_dir():
        for module_dir in _BUNDLED_TC.iterdir():
            if module_dir.is_dir():
                shutil.copytree(
                    module_dir, TESTCASES_DIR / module_dir.name, dirs_exist_ok=True
                )


def _safe_yaml_path(module: str, file: str) -> Path:
    """Validate names and return the resolved path, guarding against traversal."""
    if not _SAFE_NAME.match(module) or not _SAFE_NAME.match(file):
        raise HTTPException(400, "Invalid module or file name.")
    if not (file.endswith(".yaml") or file.endswith(".yml")):
        file = file + ".yaml"
    path = (TESTCASES_DIR / module / file).resolve()
    if TESTCASES_DIR not in path.parents:
        raise HTTPException(400, "Path escapes the test-cases directory.")
    return path


def _validate_yaml(text: str) -> None:
    """Ensure the YAML parses and has the expected ``test_cases`` list shape."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise HTTPException(400, f"Invalid YAML: {exc}")
    if not isinstance(data, dict) or "test_cases" not in data:
        raise HTTPException(400, "YAML must contain a top-level 'test_cases' key.")
    if not isinstance(data["test_cases"], list):
        raise HTTPException(400, "'test_cases' must be a list.")


# --------------------------------------------------------------------------- #
#  App
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _seed_testcases()
    yield


app = FastAPI(title="GrapeQL Web API", version="1.0.0", lifespan=_lifespan)

# Also seed eagerly at import time so the directory is ready even when the
# lifespan startup hook is not triggered (e.g. certain test harnesses).
_seed_testcases()

# In-memory runtime overrides for the Qwen/Ollama connection, set from the UI.
# ``None`` means "fall back to the environment default" (QWEN_BASE_URL / QWEN_MODEL).
_RUNTIME_QWEN: Dict[str, Optional[str]] = {"base_url": None, "model": None}


def current_base_url() -> str:
    return get_base_url(_RUNTIME_QWEN["base_url"])


def current_model() -> str:
    return get_model(_RUNTIME_QWEN["model"])


# ---- models --------------------------------------------------------------- #


class TestCaseBody(BaseModel):
    content: str


class ScanRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None
    proxy: Optional[str] = None
    auth: Optional[str] = None
    auth_type: str = "Bearer"
    cookies: Optional[List[str]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    graphql_schema: Optional[Dict[str, Any]] = None
    ai_analysis: bool = False


class OllamaConfig(BaseModel):
    base_url: Optional[str] = None
    model: Optional[str] = None


class ExploitRequest(BaseModel):
    target: str
    finding: Dict[str, Any]
    graphql_schema: Optional[Dict[str, Any]] = None
    auth: Optional[str] = None
    auth_type: str = "Bearer"
    cookies: Optional[List[str]] = None
    iteration_cap: int = 8


# ---- meta ----------------------------------------------------------------- #


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/settings")
def settings() -> Dict[str, Any]:
    return {
        "modules": ALL_MODULES,
        "testcases_dir": str(TESTCASES_DIR),
        "qwen_base_url": current_base_url(),
        "qwen_model": current_model(),
    }


# ---- Ollama / Qwen configuration ------------------------------------------ #


@app.get("/api/ollama")
def get_ollama_config() -> Dict[str, Any]:
    """Return the effective Qwen/Ollama config plus the environment defaults."""
    return {
        "base_url": current_base_url(),
        "model": current_model(),
        "default_base_url": get_base_url(),
        "default_model": get_model(),
        "override_active": bool(
            _RUNTIME_QWEN["base_url"] or _RUNTIME_QWEN["model"]
        ),
    }


@app.put("/api/ollama")
def set_ollama_config(cfg: OllamaConfig) -> Dict[str, Any]:
    """Set runtime overrides. Empty/blank values reset to the env default."""
    _RUNTIME_QWEN["base_url"] = (cfg.base_url or "").strip() or None
    _RUNTIME_QWEN["model"] = (cfg.model or "").strip() or None
    return get_ollama_config()


@app.post("/api/ollama/test")
async def test_ollama_config(cfg: OllamaConfig) -> Dict[str, Any]:
    """
    Probe an OpenAI-compatible endpoint's ``/models`` list to verify the
    connection and report which models are available.
    """
    import httpx

    base_url = get_base_url((cfg.base_url or "").strip() or None)
    url = base_url + "/models"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(
            422, f"Could not reach {url}: {exc}. Is Ollama running?"
        )
    if resp.status_code != 200:
        raise HTTPException(422, f"Endpoint returned {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        models = [m.get("id") for m in data.get("data", []) if m.get("id")]
    except ValueError:
        models = []
    return {"ok": True, "base_url": base_url, "models": models}


# ---- test case management ------------------------------------------------- #


@app.get("/api/testcases")
def list_testcases() -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    if not TESTCASES_DIR.is_dir():
        return result
    for module_dir in sorted(TESTCASES_DIR.iterdir()):
        if not module_dir.is_dir():
            continue
        for yaml_path in sorted(module_dir.glob("*.y*ml")):
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                cases = data.get("test_cases", []) if isinstance(data, dict) else []
            except yaml.YAMLError:
                cases = []
            result.append(
                {
                    "module": module_dir.name,
                    "file": yaml_path.name,
                    "count": len(cases) if isinstance(cases, list) else 0,
                }
            )
    return result


@app.get("/api/testcases/{module}/{file}")
def get_testcase(module: str, file: str) -> Dict[str, str]:
    path = _safe_yaml_path(module, file)
    if not path.is_file():
        raise HTTPException(404, "Test case file not found.")
    return {"module": module, "file": path.name, "content": path.read_text("utf-8")}


@app.put("/api/testcases/{module}/{file}")
def save_testcase(module: str, file: str, body: TestCaseBody) -> Dict[str, str]:
    path = _safe_yaml_path(module, file)
    if not path.is_file():
        raise HTTPException(404, "File not found — use POST to create a new file.")
    _validate_yaml(body.content)
    path.write_text(body.content, encoding="utf-8")
    return {"status": "saved", "module": module, "file": path.name}


@app.post("/api/testcases/{module}/{file}")
def create_testcase(module: str, file: str, body: TestCaseBody) -> Dict[str, str]:
    path = _safe_yaml_path(module, file)
    if path.is_file():
        raise HTTPException(409, "File already exists — use PUT to edit it.")
    _validate_yaml(body.content)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.content, encoding="utf-8")
    return {"status": "created", "module": module, "file": path.name}


@app.delete("/api/testcases/{module}/{file}")
def delete_testcase(module: str, file: str) -> Dict[str, str]:
    path = _safe_yaml_path(module, file)
    if not path.is_file():
        raise HTTPException(404, "File not found.")
    path.unlink()
    return {"status": "deleted", "module": module, "file": path.name}


# ---- scanning ------------------------------------------------------------- #


@app.post("/api/scan")
async def scan(req: ScanRequest) -> Dict[str, Any]:
    if not req.target:
        raise HTTPException(400, "A target URL is required.")

    log_lines: List[str] = []

    try:
        result = await run_scan(
            target=req.target,
            modules=req.modules,
            test_cases_dir=str(TESTCASES_DIR),
            proxy=req.proxy,
            auth=req.auth,
            auth_type=req.auth_type,
            cookies=req.cookies,
            username=req.username,
            password=req.password,
            schema_dict=req.graphql_schema,
            ai_analysis=req.ai_analysis,
            ai_base_url=current_base_url(),
            ai_model=current_model(),
            log_lines=log_lines,
        )
    except ScanError as exc:
        raise HTTPException(422, str(exc))
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(500, f"Scan failed: {exc}")

    result["log"] = log_lines
    return result


# Exploit generation runs an agentic loop with many sequential local-LLM calls,
# which can take minutes. Running it as a background job (rather than one long
# HTTP request) avoids client/proxy timeouts — the UI polls for the result.
_EXPLOIT_JOBS: Dict[str, Dict[str, Any]] = {}
_EXPLOIT_TASKS: set = set()  # keep task references so they are not GC'd
_EXPLOIT_JOB_TTL = 3600  # seconds to retain a finished job


def _prune_jobs() -> None:
    now = time.time()
    stale = [
        jid
        for jid, job in _EXPLOIT_JOBS.items()
        if job.get("status") in ("done", "error")
        and now - job.get("finished_at", now) > _EXPLOIT_JOB_TTL
    ]
    for jid in stale:
        _EXPLOIT_JOBS.pop(jid, None)


async def _run_exploit_job(job_id: str, kwargs: Dict[str, Any]) -> None:
    try:
        result = await generate_exploit(**kwargs)
        _EXPLOIT_JOBS[job_id] = {
            "status": "done",
            "result": result,
            "finished_at": time.time(),
        }
    except ExploitAgentError as exc:
        _EXPLOIT_JOBS[job_id] = {
            "status": "error",
            "error": str(exc),
            "finished_at": time.time(),
        }
    except Exception as exc:  # pragma: no cover - defensive
        _EXPLOIT_JOBS[job_id] = {
            "status": "error",
            "error": f"Exploit generation failed: {exc}",
            "finished_at": time.time(),
        }


@app.post("/api/exploit")
async def exploit(req: ExploitRequest) -> Dict[str, Any]:
    if not req.target:
        raise HTTPException(400, "A target URL is required.")
    if not req.finding:
        raise HTTPException(400, "A finding is required.")

    _prune_jobs()

    # Build request headers (auth + cookies) forwarded to the live endpoint.
    headers: Dict[str, str] = {}
    if req.auth:
        headers["Authorization"] = f"{req.auth_type} {req.auth}"
    if req.cookies:
        cookie_pairs = []
        for c in req.cookies:
            if ":" in c:
                name, value = c.split(":", 1)
                cookie_pairs.append(f"{name.strip()}={value.strip()}")
        if cookie_pairs:
            headers["Cookie"] = "; ".join(cookie_pairs)

    cap = max(1, min(req.iteration_cap, 15))

    kwargs = dict(
        target=req.target,
        finding=req.finding,
        schema=req.graphql_schema,
        request_headers=headers or None,
        iteration_cap=cap,
        base_url=current_base_url(),
        model=current_model(),
        log_lines=[],
    )

    job_id = uuid.uuid4().hex
    _EXPLOIT_JOBS[job_id] = {"status": "running"}

    task = asyncio.create_task(_run_exploit_job(job_id, kwargs))
    _EXPLOIT_TASKS.add(task)
    task.add_done_callback(_EXPLOIT_TASKS.discard)

    return {"job_id": job_id, "status": "running"}


@app.get("/api/exploit/{job_id}")
async def exploit_status(job_id: str) -> Dict[str, Any]:
    job = _EXPLOIT_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "Unknown or expired exploit job.")
    return job


# --------------------------------------------------------------------------- #
#  Static frontend (mounted last so /api routes take precedence)
# --------------------------------------------------------------------------- #

if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str) -> FileResponse:
        candidate = (STATIC_DIR / full_path).resolve()
        if STATIC_DIR in candidate.parents and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")
