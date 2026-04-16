"""
llm_client.py — GitHub Models (gpt-4o-mini) via the OpenAI-compatible endpoint.
All agents call chat() here; model/endpoint/token come from config.
"""
import logging
import time

from openai import OpenAI, RateLimitError, APIError

from scripts.utils.config import (
    GITHUB_MODELS_ENDPOINT,
    GITHUB_MODELS_TOKEN,
    GITHUB_MODELS_MODEL,
)

log = logging.getLogger(__name__)

_client = OpenAI(
    base_url=GITHUB_MODELS_ENDPOINT,
    api_key=GITHUB_MODELS_TOKEN,
)


def chat(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 4096,
    temperature: float = 0.1,
    retries: int = 4,
) -> str:
    """
    Send a chat completion request and return the assistant text.
    Retries with exponential back-off on rate-limit errors.
    """
    for attempt in range(retries):
        try:
            resp = _client.chat.completions.create(
                model=GITHUB_MODELS_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
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
