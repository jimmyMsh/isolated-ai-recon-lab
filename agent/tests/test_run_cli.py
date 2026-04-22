"""CLI contract tests for agent/run.py.

Tests import run in-process and monkeypatch run.AgentConfig, run.ReconAgent,
and run.os.geteuid at module scope so nothing touches real config files,
real nmap, real Ollama, or real root privileges.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# `run.py` lives at agent/run.py, outside the src/ pythonpath entry that
# pyproject.toml already configures. Add the agent/ directory explicitly so
# `import run` resolves to the CLI module under test.
_AGENT_DIR = Path(__file__).resolve().parent.parent
if str(_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENT_DIR))

import run  # noqa: E402


def _stub_config(**overrides) -> SimpleNamespace:
    defaults = {
        "target_subnet": "192.168.56.0/24",
        "attacker_ip": "192.168.56.10",
        "ollama_url": "http://localhost:11434",
        "model": "qwen3:8b",
        "pipeline_stages": [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ],
        "max_total_duration_seconds": 600,
        "output_dir": "./output",
        "log_file": "./output/agent.log.jsonl",
        "nmap_path": "/usr/bin/nmap",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _patch_from_yaml(monkeypatch, *, return_value=None, side_effect=None) -> MagicMock:
    mock = MagicMock()
    if side_effect is not None:
        mock.side_effect = side_effect
    else:
        mock.return_value = return_value
    monkeypatch.setattr(run.AgentConfig, "from_yaml", mock)
    return mock


class _ShouldNotInstantiate:
    def __init__(self, *args, **kwargs) -> None:
        raise AssertionError(
            f"ReconAgent must not be instantiated in this path; got args={args!r} kwargs={kwargs!r}"
        )


class TestHelp:
    def test_help_exits_zero_and_mentions_flags(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--help"])
        with pytest.raises(SystemExit) as exc_info:
            run.main()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "--config" in out
        assert "--dry-run" in out


class TestConfigPathForwarding:
    def test_default_config_path_is_config_default_yaml(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["run.py", "--dry-run"])
        fake_from_yaml = _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 1000)

        rc = run.main()

        assert rc == 0
        fake_from_yaml.assert_called_once()
        (path_arg,) = fake_from_yaml.call_args.args
        assert path_arg == Path("config/default.yaml")

    def test_custom_config_path_is_forwarded(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "custom/path.yaml", "--dry-run"])
        fake_from_yaml = _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 1000)

        rc = run.main()

        assert rc == 0
        fake_from_yaml.assert_called_once()
        (path_arg,) = fake_from_yaml.call_args.args
        assert path_arg == Path("custom/path.yaml")


class TestConfigErrors:
    def test_missing_config_exits_2_and_writes_stderr(self, monkeypatch, capsys):
        bad_path = "/nonexistent/config.yaml"
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", bad_path])
        _patch_from_yaml(
            monkeypatch,
            side_effect=FileNotFoundError(f"Config file not found: {bad_path}"),
        )
        monkeypatch.setattr(run, "ReconAgent", _ShouldNotInstantiate)

        rc = run.main()

        assert rc == 2
        err = capsys.readouterr().err
        assert bad_path in err

    def test_invalid_config_exits_2_and_writes_stderr(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "bad.yaml"])
        _patch_from_yaml(
            monkeypatch,
            side_effect=ValueError("Missing required config fields: target_subnet"),
        )
        monkeypatch.setattr(run, "ReconAgent", _ShouldNotInstantiate)

        rc = run.main()

        assert rc == 2
        err = capsys.readouterr().err
        assert "target_subnet" in err


class TestDryRun:
    def test_dry_run_without_root_prints_summary_and_skips_agent(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml", "--dry-run"])
        cfg = _stub_config()
        _patch_from_yaml(monkeypatch, return_value=cfg)
        monkeypatch.setattr(run.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(run, "ReconAgent", _ShouldNotInstantiate)

        rc = run.main()

        assert rc == 0
        out = capsys.readouterr().out
        assert "192.168.56.0/24" in out
        assert "qwen3:8b" in out
        assert "host_discovery" in out


class TestRootGate:
    def test_non_dry_run_as_non_root_exits_1_before_agent(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(run, "ReconAgent", _ShouldNotInstantiate)

        rc = run.main()

        assert rc == 1
        err = capsys.readouterr().err
        assert "root" in err.lower()


class TestHappyPath:
    def test_root_real_run_invokes_agent_and_prints_report_path(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        cfg = _stub_config()
        _patch_from_yaml(monkeypatch, return_value=cfg)
        monkeypatch.setattr(run.os, "geteuid", lambda: 0)

        fake_agent = MagicMock()
        fake_agent.run.return_value = "/tmp/output/report.md"
        fake_ctor = MagicMock(return_value=fake_agent)
        monkeypatch.setattr(run, "ReconAgent", fake_ctor)

        rc = run.main()

        assert rc == 0
        out = capsys.readouterr().out
        assert "/tmp/output/report.md" in out
        fake_ctor.assert_called_once_with(cfg)
        fake_agent.run.assert_called_once_with()


class TestKeyboardInterrupt:
    def test_keyboard_interrupt_during_agent_run_exits_130(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 0)

        fake_agent = MagicMock()
        fake_agent.run.side_effect = KeyboardInterrupt()
        monkeypatch.setattr(run, "ReconAgent", MagicMock(return_value=fake_agent))

        rc = run.main()

        assert rc == 130

    def test_keyboard_interrupt_during_agent_ctor_exits_130(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 0)

        def ctor_raises(*_args, **_kwargs):
            raise KeyboardInterrupt()

        monkeypatch.setattr(run, "ReconAgent", ctor_raises)

        rc = run.main()

        assert rc == 130


class TestUnexpectedException:
    def test_exception_during_agent_run_exits_1_and_writes_stderr(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 0)

        fake_agent = MagicMock()
        fake_agent.run.side_effect = RuntimeError("boom")
        monkeypatch.setattr(run, "ReconAgent", MagicMock(return_value=fake_agent))

        rc = run.main()

        assert rc == 1
        err = capsys.readouterr().err
        assert "RuntimeError" in err
        assert "boom" in err

    def test_exception_during_agent_ctor_exits_1_and_writes_stderr(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["run.py", "--config", "any.yaml"])
        _patch_from_yaml(monkeypatch, return_value=_stub_config())
        monkeypatch.setattr(run.os, "geteuid", lambda: 0)

        def ctor_raises(*_args, **_kwargs):
            raise RuntimeError("ctor boom")

        monkeypatch.setattr(run, "ReconAgent", ctor_raises)

        rc = run.main()

        assert rc == 1
        err = capsys.readouterr().err
        assert "RuntimeError" in err
        assert "ctor boom" in err
