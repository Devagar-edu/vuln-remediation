"""
llm_client.py — GitHub Models (gpt-4o-mini) via the OpenAI-compatible endpoint.
All agents call chat() here; model/endpoint/token come from config.

Compatible with any openai>=1.0 release installed on the runner.
The client is initialised lazily so import failures don't abort agents at startup.
"""
from __future__ import annotations

import json
import logging
import re
import time

from scripts.utils.config import (
    GITHUB_MODELS_ENDPOINT,
    GITHUB_MODELS_TOKEN,
    GITHUB_MODELS_MODEL,
)

log = logging.getLogger(__name__)

_client = None  # lazy singleton


def _make_client():
    from openai import OpenAI
    return OpenAI(
        base_url=GITHUB_MODELS_ENDPOINT,
        api_key=GITHUB_MODELS_TOKEN,
    )


def _get_client():
    global _client
    if _client is None:
        _client = _make_client()
    return _client


def chat(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 4096,
    temperature: float = 0.1,
    retries: int = 4,
    json_mode: bool = False,
) -> str:
    """
    Send a chat completion request and return the assistant text.
    Retries with exponential back-off on rate-limit and transient API errors.

    json_mode=True instructs the model to respond with a JSON object only.
    Use for structured LLM calls (e.g. Stage 1 analysis in plan_agent).
    """
    from openai import RateLimitError, APIError

    client = _get_client()

    kwargs: dict = dict(
        model       = GITHUB_MODELS_MODEL,
        messages    = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        max_tokens  = max_tokens,
        temperature = temperature,
    )
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content.strip()

        except RateLimitError:
            wait = 2 ** (attempt + 2)   # 4, 8, 16, 32 s
            log.warning("Rate-limited. Retrying in %ds (attempt %d/%d)",
                        wait, attempt + 1, retries)
            time.sleep(wait)

        except APIError as exc:
            log.error("LLM API error: %s", exc)
            if attempt == retries - 1:
                raise
            time.sleep(5)

    raise RuntimeError("LLM call failed after all retries")


def parse_json_response(raw: str) -> dict:
    """
    Safely parse a JSON string returned by the LLM.
    Strips accidental markdown fences (```json ... ```) before parsing.
    Raises ValueError with context on failure.
    """
    cleaned = raw.strip()
    # Strip ```json ... ``` or ``` ... ``` fences
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"LLM returned invalid JSON: {exc}\n"
            f"Raw response (first 500 chars): {raw[:500]}"
        ) from exc
