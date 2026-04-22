#!/usr/bin/env python3
"""Dark Agents — Entry point for the reconnaissance agent."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from agent import ReconAgent  # noqa: E402
from config import AgentConfig  # noqa: E402


def _print_dry_run_summary(cfg: AgentConfig) -> None:
    print("Dry-run: configuration summary")
    print(f"  target_subnet:              {cfg.target_subnet}")
    print(f"  attacker_ip:                {cfg.attacker_ip}")
    print(f"  ollama_url:                 {cfg.ollama_url}")
    print(f"  model:                      {cfg.model}")
    print(f"  pipeline_stages:            {', '.join(cfg.pipeline_stages)}")
    print(f"  max_total_duration_seconds: {cfg.max_total_duration_seconds}")
    print(f"  output_dir:                 {cfg.output_dir}")
    print(f"  log_file:                   {cfg.log_file}")
    print(f"  nmap_path:                  {cfg.nmap_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dark Agents: Autonomous MITRE ATT&CK reconnaissance agent"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/default.yaml"),
        help="Path to YAML configuration file (default: config/default.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and print pipeline plan without executing scans",
    )
    args = parser.parse_args()

    try:
        config = AgentConfig.from_yaml(args.config)
    except Exception as exc:
        print(f"Error loading config {args.config}: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        _print_dry_run_summary(config)
        return 0

    if os.geteuid() != 0:
        print(
            "Error: root privileges required for nmap SYN scans. "
            "Re-run with sudo, or use --dry-run to validate config without scanning.",
            file=sys.stderr,
        )
        return 1

    try:
        agent = ReconAgent(config)
        report_path = agent.run()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"Error during agent run: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
