"""Tool executor — safe subprocess execution of nmap commands."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from config import AgentConfig
from guardrails import Guardrails, GuardrailViolation

_PERMISSION_PATTERNS = ["requires root privileges", "operation not permitted", "permission denied"]


def _is_permission_error(stderr: str) -> bool:
    lower = stderr.lower()
    return any(pattern in lower for pattern in _PERMISSION_PATTERNS)


def _extract_oxml_path(args: list[str]) -> str | None:
    """Extract the -oX value from nmap args, or None if not present."""
    for i, arg in enumerate(args):
        if arg == "-oX" and i + 1 < len(args):
            return args[i + 1]
    return None


class CommandBlockedError(Exception):
    def __init__(self, rule: str, detail: str, blocked_args: list[str]) -> None:
        self.rule = rule
        self.detail = detail
        self.blocked_args = blocked_args
        super().__init__(f"[{rule}] {detail}")


@dataclass
class ExecutionResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    xml_output_path: str | None
    duration_seconds: float
    timed_out: bool


class ToolExecutor:
    def __init__(self, config: AgentConfig, guardrails: Guardrails) -> None:
        self._config = config
        self._guardrails = guardrails

    def execute_nmap(
        self, args: list[str], output_filename: str, timeout: int = 120
    ) -> ExecutionResult:
        try:
            self._guardrails.validate_nmap_args(args)
        except GuardrailViolation as exc:
            raise CommandBlockedError(exc.rule, exc.detail, args) from exc

        full_command = [self._config.nmap_path, *args]
        output_dir = Path(self._config.output_dir)
        xml_path = (output_dir / output_filename).resolve()
        if not xml_path.is_relative_to(output_dir.resolve()):
            raise CommandBlockedError(
                "path_traversal",
                f"output_filename resolves outside output_dir: {output_filename}",
                args,
            )
        oxml_path = _extract_oxml_path(args)
        if oxml_path is not None and Path(oxml_path).resolve() != xml_path:
            raise CommandBlockedError(
                "oxml_path_mismatch",
                f"-oX path in args ({oxml_path}) does not match expected path ({xml_path})",
                args,
            )
        output_dir.mkdir(parents=True, exist_ok=True)

        overall_start = time.monotonic()
        proc = None

        for _attempt in range(2):
            try:
                proc = subprocess.run(full_command, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                duration = time.monotonic() - overall_start
                return ExecutionResult(
                    command=full_command,
                    return_code=-1,
                    stdout=exc.stdout or "",
                    stderr=exc.stderr or "",
                    xml_output_path=str(xml_path) if xml_path.exists() else None,
                    duration_seconds=duration,
                    timed_out=True,
                )

            if _is_permission_error(proc.stderr):
                break

            if proc.returncode == 0 and xml_path.exists():
                break

        duration = time.monotonic() - overall_start

        return ExecutionResult(
            command=full_command,
            return_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            xml_output_path=str(xml_path) if xml_path.exists() else None,
            duration_seconds=duration,
            timed_out=False,
        )
