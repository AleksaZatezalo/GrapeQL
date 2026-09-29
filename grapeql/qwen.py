"""
GrapeQL Qwen client.

A small OpenAI-compatible chat-completions client used for all AI features
(post-scan analysis and the exploit agent). It talks to a Qwen model served
over an OpenAI-compatible API — by default a local Ollama server.

Configuration (all optional, resolved at call time):
    QWEN_BASE_URL   OpenAI-compatible base URL   (default http://localhost:11434/v1)
    QWEN_MODEL      Model name/tag               (default qwen2.5-coder:7b)
    QWEN_API_KEY    Bearer token, if the server needs one (default: none)

No API key is required for a local Ollama server.
"""

import os
from typing import Any, Dict, List, Optional

import httpx

DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_MODEL = "qwen2.5-coder:7b"


class QwenError(Exception):
    """Raised when the Qwen endpoint returns an error or is unreachable."""


def get_base_url(override: Optional[str] = None) -> str:
    return (override or os.environ.get("QWEN_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def get_model(override: Optional[str] = None) -> str:
    return override or os.environ.get("QWEN_MODEL") or DEFAULT_MODEL


def get_api_key(override: Optional[str] = None) -> Optional[str]:
    return override or os.environ.get("QWEN_API_KEY") or os.environ.get("OPENAI_API_KEY")


def _headers(api_key: Optional[str]) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


async def chat_completion(
    messages: List[Dict[str, Any]],
    *,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
    max_tokens: int = 4096,
    temperature: float = 0.3,
    timeout: float = 180.0,
) -> Dict[str, Any]:
    """
    Call the OpenAI-compatible ``/chat/completions`` endpoint and return the
    parsed JSON response. Raises :class:`QwenError` on any failure.
    """
    url = get_base_url(base_url) + "/chat/completions"
    body: Dict[str, Any] = {
        "model": get_model(model),
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if tools:
        body["tools"] = tools

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=body, headers=_headers(get_api_key(api_key)))
    except httpx.HTTPError as exc:
        raise QwenError(
            f"Could not reach the Qwen endpoint at {url}: {exc}. "
            "Is the server (e.g. Ollama) running and the model pulled?"
        )

    if resp.status_code != 200:
        raise QwenError(f"Qwen endpoint error ({resp.status_code}): {resp.text[:400]}")

    try:
        return resp.json()
    except ValueError as exc:
        raise QwenError(f"Invalid JSON from Qwen endpoint: {exc}")
