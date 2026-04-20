"""Test fakes for the LLM client and nmap executor boundaries.

All other collaborators (guardrails, parser, state, logger, prompt_templates,
command_builder, report_generator) use real instances in tests.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config import StageConfig
from llm_client import LLMResponse
from tool_executor import ExecutionResult


@dataclass
class LLMCallRecord:
    messages: list[dict[str, str]]
    schema: dict[str, Any]
    stage_config: StageConfig | None = None


class FakeLLMClient:
    """Queue-based fake with an optional callable escape hatch.

    List mode: items are `LLMResponse` (returned) or `Exception` (raised).
    Callable mode: returns `LLMResponse` or raises directly.
    """

    def __init__(
        self,
        responses: list[LLMResponse | Exception] | Callable[[LLMCallRecord, int], LLMResponse],
    ) -> None:
        if callable(responses):
            self._callable = responses
            self._queue: list[LLMResponse | Exception] | None = None
        else:
            self._callable = None
            self._queue = list(responses)
        self.history: list[LLMCallRecord] = []

    def call(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        stage_config: StageConfig | None = None,
    ) -> LLMResponse:
        record = LLMCallRecord(
            messages=[dict(m) for m in messages],
            schema=schema,
            stage_config=stage_config,
        )
        self.history.append(record)
        if self._callable is not None:
            return self._callable(record, len(self.history))
        assert self._queue is not None
        if not self._queue:
            raise RuntimeError("FakeLLMClient: no more queued responses")
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@dataclass
class ExecCallRecord:
    args: list[str]
    output_filename: str
    timeout: int


class FakeToolExecutor:
    """Fake nmap executor that can copy a fixture XML into the expected path.

    Queue items:
      - `(fixture_path: Path, ExecutionResult)`: copies fixture to dst and
        returns an ExecutionResult with `xml_output_path` set to dst.
      - plain `ExecutionResult`: returned unchanged (no file copy).
      - `Exception`: raised directly.
    """

    def __init__(
        self,
        results: list,
        output_dir: Path,
    ) -> None:
        self._queue = list(results)
        self._output_dir = Path(output_dir)
        self.history: list[ExecCallRecord] = []

    def execute_nmap(
        self, args: list[str], output_filename: str, timeout: int = 120
    ) -> ExecutionResult:
        self.history.append(
            ExecCallRecord(args=list(args), output_filename=output_filename, timeout=timeout)
        )
        if not self._queue:
            raise RuntimeError("FakeToolExecutor: no more queued results")
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, tuple):
            fixture_path, result = item
            dst = self._output_dir / output_filename
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(fixture_path, dst)
            return ExecutionResult(
                command=result.command,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
                xml_output_path=str(dst),
                duration_seconds=result.duration_seconds,
                timed_out=result.timed_out,
            )
        return item
