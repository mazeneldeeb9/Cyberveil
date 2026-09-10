from __future__ import annotations

import argparse
import json
import sys
from uuid import uuid4

from cyberveil.collectors import ReplayScenario, available_scenarios
from cyberveil.collectors.replay import replay_samples


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberveil",
        description="CYBERVEIL safe behavior-monitoring academic demonstrator",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("gui", help="Launch the desktop application")
    replay = subparsers.add_parser("replay", help="Preview a deterministic safe telemetry replay")
    replay.add_argument("--scenario", choices=available_scenarios(), default="suspicious-burst")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "gui"
    if command == "gui":
        from cyberveil.ui.app import run

        return run()
    if command == "replay":
        session_id = str(uuid4())
        batches = list(replay_samples(ReplayScenario(args.scenario), session_id))
        print(
            json.dumps(
                {
                    "session_id": session_id,
                    "scenario": args.scenario,
                    "batches": len(batches),
                    "samples": sum(len(batch) for batch in batches),
                    "safe_generated_telemetry": True,
                },
                indent=2,
            )
        )
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
