"""Tests for the tool_executor module — safe subprocess execution."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from config import AgentConfig
from guardrails import Guardrails
from tool_executor import CommandBlockedError, ExecutionResult, ToolExecutor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config(tmp_path):
    return AgentConfig(
        ollama_url="http://localhost:11434",
        model="qwen3:8b",
        target_subnet="192.168.56.0/24",
        attacker_ip="192.168.56.10",
        nmap_path="/usr/bin/nmap",
        output_dir=str(tmp_path / "output"),
    )


@pytest.fixture()
def guardrails(config):
    return Guardrails(config)


@pytest.fixture()
def executor(config, guardrails):
    return ToolExecutor(config, guardrails)


# Valid args that pass guardrail validation (in-subnet, not attacker IP)
VALID_ARGS = ["-sS", "-T4", "-p-", "--open", "192.168.56.101", "-oX", "/tmp/test.xml"]
VALID_TARGET = "192.168.56.101"


def _make_completed_process(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["/usr/bin/nmap"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ---------------------------------------------------------------------------
# TestExecutionResult
# ---------------------------------------------------------------------------


class TestExecutionResult:
    def test_fields_accessible(self):
        result = ExecutionResult(
            command=["/usr/bin/nmap", "-sS", "192.168.56.101"],
            return_code=0,
            stdout="Host is up",
            stderr="",
            xml_output_path="/tmp/scan.xml",
            duration_seconds=1.5,
            timed_out=False,
        )
        assert result.command == ["/usr/bin/nmap", "-sS", "192.168.56.101"]
        assert result.return_code == 0
        assert result.stdout == "Host is up"
        assert result.stderr == ""
        assert result.xml_output_path == "/tmp/scan.xml"
        assert result.duration_seconds == 1.5
        assert result.timed_out is False

    def test_timed_out_true(self):
        result = ExecutionResult(
            command=["/usr/bin/nmap"],
            return_code=-1,
            stdout="",
            stderr="",
            xml_output_path=None,
            duration_seconds=120.0,
            timed_out=True,
        )
        assert result.timed_out is True

    def test_xml_output_path_none(self):
        result = ExecutionResult(
            command=["/usr/bin/nmap"],
            return_code=1,
            stdout="",
            stderr="",
            xml_output_path=None,
            duration_seconds=0.5,
            timed_out=False,
        )
        assert result.xml_output_path is None


# ---------------------------------------------------------------------------
# TestCommandBlockedError
# ---------------------------------------------------------------------------


class TestCommandBlockedError:
    def test_is_exception_subclass(self):
        err = CommandBlockedError("target_outside_subnet", "bad target", ["-sS", "10.0.0.1"])
        assert isinstance(err, Exception)

    def test_message_contains_rule_and_detail(self):
        err = CommandBlockedError("target_outside_subnet", "Target 10.0.0.1 is outside subnet", [])
        assert "target_outside_subnet" in str(err)
        assert "Target 10.0.0.1 is outside subnet" in str(err)

    def test_attributes_preserved(self):
        blocked = ["-sS", "10.0.0.1"]
        err = CommandBlockedError("no_target", "No scan target found", blocked)
        assert err.rule == "no_target"
        assert err.detail == "No scan target found"
        assert err.blocked_args == blocked


# ---------------------------------------------------------------------------
# TestToolExecutorInit
# ---------------------------------------------------------------------------


class TestToolExecutorInit:
    def test_stores_config_and_guardrails(self, config, guardrails):
        executor = ToolExecutor(config, guardrails)
        assert executor._config is config
        assert executor._guardrails is guardrails

    def test_accepts_dependency_injection(self, config):
        mock_guardrails = MagicMock(spec=Guardrails)
        executor = ToolExecutor(config, mock_guardrails)
        assert executor._guardrails is mock_guardrails


# ---------------------------------------------------------------------------
# TestExecuteNmapValidation
# ---------------------------------------------------------------------------


class TestExecuteNmapValidation:
    def test_out_of_subnet_raises_command_blocked(self, executor):
        bad_args = ["-sS", "10.0.0.1", "-oX", "/tmp/out.xml"]
        with pytest.raises(CommandBlockedError) as exc_info:
            executor.execute_nmap(bad_args, "out.xml")
        assert exc_info.value.rule == "target_outside_subnet"

    def test_command_blocked_preserves_violation_detail(self, executor):
        bad_args = ["-sS", "10.0.0.1", "-oX", "/tmp/out.xml"]
        with pytest.raises(CommandBlockedError) as exc_info:
            executor.execute_nmap(bad_args, "out.xml")
        assert "10.0.0.1" in exc_info.value.detail

    def test_subprocess_not_called_on_validation_failure(self, executor, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "tool_executor.subprocess.run",
            lambda *a, **kw: calls.append(1),
        )
        bad_args = ["-sS", "10.0.0.1", "-oX", "/tmp/out.xml"]
        with pytest.raises(CommandBlockedError):
            executor.execute_nmap(bad_args, "out.xml")
        assert len(calls) == 0

    def test_valid_args_proceed_to_execution(self, executor, monkeypatch, tmp_path):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            Path(executor._config.output_dir).mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        valid = ["-sS", VALID_TARGET, "-oX", str(xml_path)]
        result = executor.execute_nmap(valid, "scan.xml")
        assert result.return_code == 0

    def test_validation_on_raw_args_without_nmap_path(self, config, monkeypatch, tmp_path):
        captured_args = []

        class CapturingGuardrails(Guardrails):
            def validate_nmap_args(self, args):
                captured_args.append(list(args))
                super().validate_nmap_args(args)

        gr = CapturingGuardrails(config)
        ex = ToolExecutor(config, gr)
        xml_path = Path(config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            Path(config.output_dir).mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        valid = ["-sS", VALID_TARGET, "-oX", str(xml_path)]
        ex.execute_nmap(valid, "scan.xml")
        assert len(captured_args) == 1
        assert config.nmap_path not in captured_args[0]


# ---------------------------------------------------------------------------
# TestExecuteNmapSuccess
# ---------------------------------------------------------------------------


class TestExecuteNmapSuccess:
    def test_happy_path(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process(stdout="Nmap done", stderr="")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.return_code == 0
        assert result.xml_output_path == str(xml_path)
        assert result.timed_out is False

    def test_command_shape(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        captured = []

        def mock_run(cmd, **kwargs):
            captured.append(cmd)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        input_args = ["-sS", VALID_TARGET, "-oX", str(xml_path)]
        executor.execute_nmap(input_args, "scan.xml")
        assert captured[0][0] == executor._config.nmap_path
        assert captured[0][1:] == input_args

    def test_stdout_stderr_captured(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process(stdout="scan output", stderr="warning msg")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.stdout == "scan output"
        assert result.stderr == "warning msg"

    def test_duration_measured(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.duration_seconds >= 0

    def test_output_directory_created(self, executor, monkeypatch):
        output_dir = Path(executor._config.output_dir)
        assert not output_dir.exists()
        xml_path = output_dir / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert output_dir.exists()


# ---------------------------------------------------------------------------
# TestExecuteNmapTimeout
# ---------------------------------------------------------------------------


class TestExecuteNmapTimeout:
    def test_returns_timed_out_true(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            exc = subprocess.TimeoutExpired(cmd=args[0], timeout=10)
            exc.stdout = "partial"
            exc.stderr = ""
            raise exc

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.timed_out is True

    def test_return_code_is_negative_one(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            exc = subprocess.TimeoutExpired(cmd=args[0], timeout=10)
            exc.stdout = None
            exc.stderr = None
            raise exc

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.return_code == -1

    def test_no_retry_on_timeout(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            exc = subprocess.TimeoutExpired(cmd=args[0], timeout=10)
            exc.stdout = None
            exc.stderr = None
            raise exc

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 1

    def test_partial_xml_preserved(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<partial>")
            exc = subprocess.TimeoutExpired(cmd=args[0], timeout=10)
            exc.stdout = ""
            exc.stderr = ""
            raise exc

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert result.xml_output_path is not None
        assert result.xml_output_path == str(xml_path)

    def test_bytes_stdout_stderr_are_decoded(self, executor, config, monkeypatch):
        out_xml = str(Path(config.output_dir).resolve() / "out.xml")
        args = ["-sS", VALID_TARGET, "-oX", out_xml]

        def fake_run(*a, **kw):
            raise subprocess.TimeoutExpired(
                cmd=a[0],
                timeout=kw.get("timeout", 1),
                output=b"partial stdout\n",
                stderr=b"partial stderr\n",
            )

        monkeypatch.setattr("tool_executor.subprocess.run", fake_run)
        result = executor.execute_nmap(args, output_filename="out.xml", timeout=1)
        assert result.timed_out is True
        assert result.return_code == -1
        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)
        assert result.stdout == "partial stdout\n"
        assert result.stderr == "partial stderr\n"

    def test_logger_serializes_timeout_result(self, tmp_path, monkeypatch):
        import json

        from logger import AgentLogger

        cfg = AgentConfig(
            ollama_url="http://localhost:11434",
            model="qwen3:8b",
            target_subnet="192.168.56.0/24",
            attacker_ip="192.168.56.10",
            nmap_path="/usr/bin/nmap",
            output_dir=str(tmp_path),
            log_file=str(tmp_path / "agent.log.jsonl"),
        )
        ex = ToolExecutor(cfg, Guardrails(cfg))
        lg = AgentLogger(cfg)

        out_xml = str(Path(cfg.output_dir).resolve() / "out.xml")
        args = ["-sS", VALID_TARGET, "-oX", out_xml]

        def fake_run(*a, **kw):
            raise subprocess.TimeoutExpired(
                cmd=a[0],
                timeout=kw.get("timeout", 1),
                output=b"partial stdout\n",
                stderr=b"partial stderr\n",
            )

        monkeypatch.setattr("tool_executor.subprocess.run", fake_run)
        result = ex.execute_nmap(args, output_filename="out.xml", timeout=1)

        lg.log_event(
            "command_exec",
            "service_enum",
            {
                "command": result.command,
                "return_code": result.return_code,
                "stdout_preview": result.stdout[:500],
                "xml_output_path": result.xml_output_path,
                "duration_seconds": result.duration_seconds,
                "command_source": "llm",
            },
        )
        lg.close()

        lines = Path(cfg.log_file).read_text().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert isinstance(parsed["stdout_preview"], str)
        assert parsed["stdout_preview"] == "partial stdout\n"


# ---------------------------------------------------------------------------
# TestExecuteNmapRetry
# ---------------------------------------------------------------------------


class TestExecuteNmapRetry:
    def test_nonzero_exit_retries_then_succeeds(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            if len(calls) == 1:
                return _make_completed_process(returncode=1, stderr="error")
            xml_path.write_text("<xml/>")
            return _make_completed_process(returncode=0)

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        assert result.return_code == 0

    def test_nonzero_exit_retries_then_fails(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            return _make_completed_process(returncode=1, stderr="persistent error")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        assert result.return_code == 1

    def test_xml_missing_retries_then_succeeds(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            if len(calls) == 2:
                xml_path.write_text("<xml/>")
            return _make_completed_process(returncode=0)

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        assert result.xml_output_path == str(xml_path)

    def test_xml_missing_retries_still_missing(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            return _make_completed_process(returncode=0)

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        assert result.xml_output_path is None

    def test_permission_error_no_retry(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            return _make_completed_process(
                returncode=1, stderr="TCP/IP fingerprinting requires root privileges"
            )

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 1
        assert result.return_code == 1

    def test_retry_uses_identical_args(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        captured_cmds = []

        def mock_run(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            if len(captured_cmds) == 2:
                xml_path.write_text("<xml/>")
            return _make_completed_process(returncode=0)

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(captured_cmds) == 2
        assert captured_cmds[0] == captured_cmds[1]

    def test_duration_cumulative_across_retries(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        tick = [0.0]

        def fake_monotonic():
            tick[0] += 1.0
            return tick[0]

        monkeypatch.setattr("tool_executor.time.monotonic", fake_monotonic)

        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            if len(calls) == 1:
                return _make_completed_process(returncode=1)
            xml_path.write_text("<xml/>")
            return _make_completed_process(returncode=0)

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        # Two monotonic calls (start + end) with tick incrementing by 1.0 each → duration = 1.0
        assert result.duration_seconds == pytest.approx(1.0, abs=0.5)


# ---------------------------------------------------------------------------
# TestExecuteNmapMissingBinary
# ---------------------------------------------------------------------------


class TestExecuteNmapMissingBinary:
    def test_file_not_found_propagates(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            raise FileNotFoundError("No such file: /usr/bin/nmap")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        with pytest.raises(FileNotFoundError):
            executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")

    def test_os_error_propagates(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            raise OSError("Permission denied: /usr/bin/nmap")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        with pytest.raises(OSError):
            executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")


# ---------------------------------------------------------------------------
# TestExecuteNmapCommandSafety
# ---------------------------------------------------------------------------


class TestExecuteNmapCommandSafety:
    def test_command_is_list(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        captured = []

        def mock_run(cmd, **kwargs):
            captured.append(cmd)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert isinstance(captured[0], list)

    def test_nmap_path_is_first_element(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        captured = []

        def mock_run(cmd, **kwargs):
            captured.append(cmd)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert captured[0][0] == "/usr/bin/nmap"

    def test_shell_never_used(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        captured_kwargs = []

        def mock_run(cmd, **kwargs):
            captured_kwargs.append(kwargs)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert captured_kwargs[0].get("shell") is not True


# ---------------------------------------------------------------------------
# TestExecuteNmapPathTraversal
# ---------------------------------------------------------------------------


class TestExecuteNmapPathTraversal:
    def test_traversal_filename_blocked(self, executor):
        with pytest.raises(CommandBlockedError) as exc_info:
            executor.execute_nmap(
                ["-sS", VALID_TARGET, "-oX", "/tmp/out.xml"],
                "../../etc/poison.xml",
            )
        assert exc_info.value.rule == "path_traversal"

    def test_safe_filename_allowed(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan_result.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(
            ["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan_result.xml"
        )
        assert result.return_code == 0

    def test_oxml_mismatch_blocked(self, executor):
        with pytest.raises(CommandBlockedError) as exc_info:
            executor.execute_nmap(
                ["-sS", VALID_TARGET, "-oX", "/tmp/rogue.xml"],
                "legit.xml",
            )
        assert exc_info.value.rule == "oxml_path_mismatch"

    def test_no_oxml_in_args_allowed(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"

        def mock_run(*args, **kwargs):
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            xml_path.write_text("<xml/>")
            return _make_completed_process()

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET], "scan.xml")
        assert result.return_code == 0


# ---------------------------------------------------------------------------
# TestExecuteNmapCombinedFailure
# ---------------------------------------------------------------------------


class TestExecuteNmapCombinedFailure:
    def test_nonzero_exit_and_xml_missing_exhausts_retries(self, executor, monkeypatch):
        xml_path = Path(executor._config.output_dir) / "scan.xml"
        calls = []

        def mock_run(*args, **kwargs):
            calls.append(1)
            xml_path.parent.mkdir(parents=True, exist_ok=True)
            return _make_completed_process(returncode=2, stderr="nmap failed")

        monkeypatch.setattr("tool_executor.subprocess.run", mock_run)
        result = executor.execute_nmap(["-sS", VALID_TARGET, "-oX", str(xml_path)], "scan.xml")
        assert len(calls) == 2
        assert result.return_code == 2
        assert result.xml_output_path is None
        assert result.timed_out is False
