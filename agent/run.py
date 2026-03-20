#!/usr/bin/env python3
"""Dark Agents — Entry point for the reconnaissance agent."""

import argparse
import sys
from pathlib import Path


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

    if not args.config.exists():
        print(f"Error: Config file not found: {args.config}", file=sys.stderr)
        return 1

    # Implementation will wire up config loading, agent initialization, and pipeline execution.
    print(f"Config: {args.config}")
    print("Agent not yet implemented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
