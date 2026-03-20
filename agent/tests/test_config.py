"""Tests for config module — AgentConfig and StageConfig loading."""

from pathlib import Path

import pytest

from config import AgentConfig, StageConfig


class TestStageConfig:
    def test_defaults(self):
        sc = StageConfig()
        assert sc.temperature == 0.0
        assert sc.top_p == 1.0
        assert sc.top_k == 20
        assert sc.timeout_seconds == 120
        assert sc.max_retries == 2
        assert sc.think is False


class TestAgentConfigFromYaml:
    def test_load_default_yaml(self, tmp_path):
        yaml_content = """\
ollama_url: "http://192.168.1.182:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools:
  - "nmap"
pipeline_stages:
  - "host_discovery"
  - "port_scan"
  - "service_enum"
  - "os_fingerprint"
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
stage_configs:
  host_discovery:
    timeout_seconds: 60
  port_scan:
    timeout_seconds: 180
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = AgentConfig.from_yaml(config_file)

        assert cfg.ollama_url == "http://192.168.1.182:11434"
        assert cfg.model == "qwen3:8b"
        assert cfg.num_ctx == 8192
        assert cfg.target_subnet == "192.168.56.0/24"
        assert cfg.attacker_ip == "192.168.56.10"
        assert cfg.nmap_path == "/usr/bin/nmap"
        assert cfg.output_dir == "./output"
        assert cfg.allowed_tools == ["nmap"]
        assert cfg.pipeline_stages == [
            "host_discovery",
            "port_scan",
            "service_enum",
            "os_fingerprint",
        ]
        assert cfg.max_total_duration_seconds == 600

    def test_stage_config_merging(self, tmp_path):
        """Per-stage overrides merge with default_stage."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery", "port_scan"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
stage_configs:
  host_discovery:
    timeout_seconds: 60
  port_scan:
    timeout_seconds: 180
    max_retries: 3
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = AgentConfig.from_yaml(config_file)

        # host_discovery overrides timeout, inherits everything else from default
        hd = cfg.stage_configs["host_discovery"]
        assert hd.timeout_seconds == 60
        assert hd.temperature == 0.0
        assert hd.max_retries == 2

        # port_scan overrides timeout and max_retries
        ps = cfg.stage_configs["port_scan"]
        assert ps.timeout_seconds == 180
        assert ps.max_retries == 3
        assert ps.temperature == 0.0

    def test_stages_without_overrides_get_defaults(self, tmp_path):
        """Stages listed in pipeline but not in stage_configs get default_stage."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery", "port_scan", "service_enum"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
stage_configs:
  host_discovery:
    timeout_seconds: 60
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = AgentConfig.from_yaml(config_file)

        # service_enum has no override — gets full defaults
        se = cfg.stage_configs["service_enum"]
        assert se.timeout_seconds == 120
        assert se.temperature == 0.0

    def test_interpretation_params(self, tmp_path):
        """Interpretation temperature/top_p/top_k are flattened into AgentConfig."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = AgentConfig.from_yaml(config_file)

        assert cfg.interpretation_temperature == 0.7
        assert cfg.interpretation_top_p == 0.8
        assert cfg.interpretation_top_k == 20

    def test_log_file_derived_from_output_dir(self, tmp_path):
        """log_file should be derived as output_dir/agent.log.jsonl."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./my_output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        cfg = AgentConfig.from_yaml(config_file)

        assert cfg.log_file == "./my_output/agent.log.jsonl"

    def test_ollama_url_env_override(self, tmp_path, monkeypatch):
        """OLLAMA_URL env var overrides yaml ollama_url."""
        yaml_content = """\
ollama_url: "http://192.168.1.182:11434"
model: "qwen3:8b"
num_ctx: 8192
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        monkeypatch.setenv("OLLAMA_URL", "http://10.0.0.5:11434")
        cfg = AgentConfig.from_yaml(config_file)

        assert cfg.ollama_url == "http://10.0.0.5:11434"

    def test_missing_required_field_raises(self, tmp_path):
        """Missing a required field (e.g. target_subnet) should raise ValueError."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
output_dir: "./output"
allowed_tools: ["nmap"]
pipeline_stages: ["host_discovery"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  top_p: 1.0
  top_k: 20
  timeout_seconds: 120
  max_retries: 2
  think: false
interpretation:
  temperature: 0.7
  top_p: 0.8
  top_k: 20
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="target_subnet"):
            AgentConfig.from_yaml(config_file)

    def test_all_required_fields_missing_lists_them(self, tmp_path):
        """Missing multiple required fields should name all of them."""
        yaml_content = """\
output_dir: "./output"
pipeline_stages: ["host_discovery"]
max_total_duration_seconds: 600
default_stage:
  temperature: 0.0
  timeout_seconds: 120
  max_retries: 2
interpretation:
  temperature: 0.7
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError) as exc_info:
            AgentConfig.from_yaml(config_file)
        msg = str(exc_info.value)
        assert "ollama_url" in msg
        assert "model" in msg
        assert "target_subnet" in msg
        assert "attacker_ip" in msg
        assert "nmap_path" in msg

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            AgentConfig.from_yaml(Path("/nonexistent/config.yaml"))

    def test_load_real_default_yaml(self):
        """Smoke test: load the actual default.yaml from the repo."""
        default_yaml = Path(__file__).parent.parent / "config" / "default.yaml"
        if not default_yaml.exists():
            pytest.skip("default.yaml not found")

        cfg = AgentConfig.from_yaml(default_yaml)

        assert cfg.target_subnet == "192.168.56.0/24"
        assert cfg.model == "qwen3:8b"
        assert len(cfg.pipeline_stages) == 4
        assert "host_discovery" in cfg.stage_configs

    def test_empty_yaml_raises(self, tmp_path):
        """Empty YAML file should raise ValueError, not TypeError."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        with pytest.raises(ValueError, match="YAML mapping"):
            AgentConfig.from_yaml(config_file)

    def test_required_field_null_raises(self, tmp_path):
        """Required field set to null should raise ValueError."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
target_subnet: null
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="target_subnet"):
            AgentConfig.from_yaml(config_file)

    def test_invalid_default_stage_key_raises(self, tmp_path):
        """Unknown key in default_stage should raise ValueError."""
        yaml_content = """\
ollama_url: "http://localhost:11434"
model: "qwen3:8b"
target_subnet: "192.168.56.0/24"
attacker_ip: "192.168.56.10"
nmap_path: "/usr/bin/nmap"
default_stage:
  bogus_key: 42
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml_content)

        with pytest.raises(ValueError, match="default_stage"):
            AgentConfig.from_yaml(config_file)
