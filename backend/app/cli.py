"""CLI entry point for the scheduler service.

Usage:
    python -m app.cli scheduler [--provider-id N]
"""
from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv
from pathlib import Path


def _load_env() -> None:
    env_candidates = [
        Path(__file__).resolve().parents[2] / ".env",
        Path(__file__).resolve().parents[1] / ".env",
    ]
    for env_path in env_candidates:
        if env_path.exists():
            load_dotenv(env_path, override=False)


def cmd_scheduler(provider_id: int | None = None) -> None:
    from app.db.database import SessionLocal
    from app.services.scheduler_service import run_scheduled_scans

    db = SessionLocal()
    try:
        scan_ids = run_scheduled_scans(db, provider_id=provider_id, trigger_type="scheduled")
        if scan_ids:
            print(f"Scheduler completed: {len(scan_ids)} scan(s) created: {scan_ids}")
        else:
            print("Scheduler completed: no scans created.")
    finally:
        db.close()


def main() -> None:
    _load_env()
    parser = argparse.ArgumentParser(description="Cloud Security Scheduler CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scheduler_parser = subparsers.add_parser("scheduler", help="Run scheduled scans")
    scheduler_parser.add_argument("--provider-id", type=int, default=None, help="Specific provider ID (scan all if omitted)")

    args = parser.parse_args()

    if args.command == "scheduler":
        cmd_scheduler(provider_id=args.provider_id)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
