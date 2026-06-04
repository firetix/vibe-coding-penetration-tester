#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import logging

# Keep output stable/clean; Flask app imports may configure verbose loggers.
logging.disable(logging.CRITICAL)


def _routes_for_app(app_name: str) -> List[Dict[str, Any]]:
    # Ensure repo root is on sys.path even when invoked as `python scripts/...`.
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    if app_name == "web_api":
        from web_api import create_app

        app = create_app()
    elif app_name == "web_ui":
        import web_ui

        app = web_ui.app
    else:
        raise ValueError(f"Unknown app: {app_name}")

    routes: List[Dict[str, Any]] = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        methods = sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}])
        routes.append({"rule": rule.rule, "methods": methods})

    routes.sort(key=lambda r: (r["rule"], ",".join(r["methods"])))
    return routes


def _write_snapshot(path: Path, routes: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(routes, indent=2, sort_keys=True) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate route snapshot JSON files under tests/contract/."
    )
    parser.add_argument(
        "--app",
        choices=("web_api", "web_ui", "both"),
        default="both",
        help="Which app snapshots to regenerate (default: both).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    contract_dir = repo_root / "tests" / "contract"

    if args.app in ("web_api", "both"):
        _write_snapshot(
            contract_dir / "routes_web_api.snapshot.json",
            _routes_for_app("web_api"),
        )

    if args.app in ("web_ui", "both"):
        _write_snapshot(
            contract_dir / "routes_web_ui.snapshot.json",
            _routes_for_app("web_ui"),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
