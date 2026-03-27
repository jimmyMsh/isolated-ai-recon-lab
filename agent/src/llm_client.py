"""Ollama API client with retry logic and structured JSON output.

Future thinking-mode support may add call_with_thinking() and vary the
think field. StageConfig.think is the intended trigger for that enhancement.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import requests

from config import AgentConfig, StageConfig

_HTTP_REQUEST_TIMEOUT = 120


class LLMError(Exception):
    """Raised when all retry attempts are exhausted or an unrecoverable LLM error occurs."""


@dataclass
class LLMResponse:
    """Structured response from an LLM call.

    Preserves both parsed output and raw content so callers can use parsed
    for orchestration logic and raw_content for logging without re-serializing.
    """

    parsed: dict[str, Any]
    raw_content: str
    thinking: str | None = None


class LLMClient:
    """Thin Ollama /api/chat wrapper with tiered retry logic."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._session = requests.Session()
        self._endpoint = f"{config.ollama_url}/api/chat"

    def call(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        stage_config: StageConfig | None = None,
    ) -> LLMResponse:
        body = self._build_request_body(messages, schema, stage_config)
        return self._execute_with_retry(body)

    def _resolve_options(self, stage_config: StageConfig | None) -> dict[str, Any]:
        if stage_config is not None:
            return {
                "temperature": stage_config.temperature,
                "top_p": stage_config.top_p,
                "top_k": stage_config.top_k,
                "num_ctx": self._config.num_ctx,
            }
        return {
            "temperature": self._config.interpretation_temperature,
            "top_p": self._config.interpretation_top_p,
            "top_k": self._config.interpretation_top_k,
            "num_ctx": self._config.num_ctx,
        }

    def _build_request_body(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        stage_config: StageConfig | None,
    ) -> dict[str, Any]:
        return {
            "model": self._config.model,
            "messages": messages,
            "format": schema,
            "think": False,
            "options": self._resolve_options(stage_config),
            "stream": False,
        }

    def _execute_with_retry(self, body: dict) -> LLMResponse:
        connection_retries = 0
        server_error_retries = 0
        json_retries = 0
        empty_retries = 0

        while True:
            # --- network layer ---
            try:
                response = self._session.post(
                    self._endpoint, json=body, timeout=_HTTP_REQUEST_TIMEOUT
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                connection_retries += 1
                if connection_retries > 3:
                    msg = f"Connection failed after 3 retries: {exc}"
                    raise LLMError(msg) from exc
                time.sleep(3)
                continue

            # --- HTTP status ---
            if response.status_code in (500, 503):
                server_error_retries += 1
                if server_error_retries > 2:
                    msg = f"Server error {response.status_code} after 2 retries"
                    raise LLMError(msg)
                time.sleep(5)
                continue

            if not response.ok:
                msg = f"HTTP {response.status_code}: {response.text}"
                raise LLMError(msg)

            # --- outer JSON parse ---
            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError) as exc:
                json_retries += 1
                if json_retries > 1:
                    msg = f"Invalid JSON response after 1 retry: {exc}"
                    raise LLMError(msg) from exc
                continue

            # --- extract content ---
            message = data.get("message")
            if not isinstance(message, dict):
                empty_retries += 1
                if empty_retries > 1:
                    msg = "Empty content after 1 retry"
                    raise LLMError(msg)
                continue
            content = message.get("content", "")
            if not content or not content.strip():
                empty_retries += 1
                if empty_retries > 1:
                    msg = "Empty content after 1 retry"
                    raise LLMError(msg)
                continue

            # --- inner JSON parse ---
            try:
                parsed = json.loads(content)
            except (json.JSONDecodeError, ValueError) as exc:
                json_retries += 1
                if json_retries > 1:
                    msg = f"Invalid JSON in message content after 1 retry: {exc}"
                    raise LLMError(msg) from exc
                continue

            return LLMResponse(parsed=parsed, raw_content=content)
