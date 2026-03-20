"""Configuration loading for the Dark Agents reconnaissance agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_DEFAULT_STAGES = [
    "host_discovery",
    "port_scan",
    "service_enum",
    "os_fingerprint",
]

# Fields that must be explicitly set in the YAML config. No safe defaults exist
# for these — a wrong subnet scans the wrong network, a wrong attacker_ip
# means the agent scans itself, etc.
_REQUIRED_FIELDS = ["ollama_url", "model", "target_subnet", "attacker_ip", "nmap_path"]


@dataclass
class StageConfig:
    temperature: float = 0.0
    top_p: float = 1.0
    top_k: int = 20
    timeout_seconds: int = 120
    max_retries: int = 2
    think: bool = False


@dataclass
class AgentConfig:
    # Required fields — no safe defaults. Must be set explicitly in YAML or constructor.
    ollama_url: str
    model: str
    target_subnet: str
    attacker_ip: str
    nmap_path: str
    # Optional fields — safe to default
    num_ctx: int = 8192
    allowed_tools: list[str] = field(default_factory=lambda: ["nmap"])
    pipeline_stages: list[str] = field(default_factory=lambda: list(_DEFAULT_STAGES))
    stage_configs: dict[str, StageConfig] = field(default_factory=dict)
    interpretation_temperature: float = 0.7
    interpretation_top_p: float = 0.8
    interpretation_top_k: int = 20
    output_dir: str = "./output"
    log_file: str = "./output/agent.log.jsonl"
    max_total_duration_seconds: int = 600

    @classmethod
    def from_yaml(cls, path: Path) -> AgentConfig:
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError(
                f"Config file {path} must contain a YAML mapping, got {type(raw).__name__}"
            )

        # Fail fast if critical fields are missing — prevents silent misconfiguration
        missing = [f for f in _REQUIRED_FIELDS if f not in raw]
        if missing:
            raise ValueError(
                f"Missing required config fields: {', '.join(missing)}. "
                f"All of {_REQUIRED_FIELDS} must be set in {path}"
            )

        # Reject required fields that are present but null
        null_fields = [f for f in _REQUIRED_FIELDS if raw.get(f) is None]
        if null_fields:
            raise ValueError(
                f"Required config fields set to null: {', '.join(null_fields)}. "
                f"All of {_REQUIRED_FIELDS} must have non-null values in {path}"
            )

        # Build default StageConfig from default_stage section
        default_stage_raw = raw.get("default_stage", {})
        try:
            default_stage = StageConfig(**default_stage_raw)
        except TypeError as exc:
            raise ValueError(f"Invalid keys in 'default_stage' section: {exc}") from exc

        # Merge per-stage overrides with defaults
        stage_overrides = raw.get("stage_configs", {})
        pipeline_stages = raw.get("pipeline_stages", list(_DEFAULT_STAGES))
        stage_configs: dict[str, StageConfig] = {}
        for stage in pipeline_stages:
            overrides = stage_overrides.get(stage, {})
            merged = StageConfig(
                temperature=overrides.get("temperature", default_stage.temperature),
                top_p=overrides.get("top_p", default_stage.top_p),
                top_k=overrides.get("top_k", default_stage.top_k),
                timeout_seconds=overrides.get("timeout_seconds", default_stage.timeout_seconds),
                max_retries=overrides.get("max_retries", default_stage.max_retries),
                think=overrides.get("think", default_stage.think),
            )
            stage_configs[stage] = merged

        # Flatten interpretation params
        interp = raw.get("interpretation", {})

        # Derive log_file from output_dir
        output_dir = raw.get("output_dir", "./output")
        log_file = f"{output_dir}/agent.log.jsonl"

        # OLLAMA_URL env var overrides YAML value
        ollama_url = os.environ.get("OLLAMA_URL", raw["ollama_url"])

        return cls(
            # Required fields — guaranteed present after the missing-field guard above
            ollama_url=ollama_url,
            model=raw["model"],
            target_subnet=raw["target_subnet"],
            attacker_ip=raw["attacker_ip"],
            nmap_path=raw["nmap_path"],
            # Optional fields — safe to default
            num_ctx=raw.get("num_ctx", 8192),
            allowed_tools=raw.get("allowed_tools", ["nmap"]),
            pipeline_stages=pipeline_stages,
            stage_configs=stage_configs,
            interpretation_temperature=interp.get("temperature", 0.7),
            interpretation_top_p=interp.get("top_p", 0.8),
            interpretation_top_k=interp.get("top_k", 20),
            output_dir=output_dir,
            log_file=log_file,
            max_total_duration_seconds=raw.get("max_total_duration_seconds", 600),
        )
