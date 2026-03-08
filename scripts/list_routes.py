#!/usr/bin/env python3

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import logging

# Keep output stable/clean; Flask app imports may configure verbose loggers.
logging.disable(logging.CRITICAL)


@dataclass(frozen=True)
class RouteRow:
    rule: str
    methods: List[str]
    endpoint: str


def _iter_routes(app) -> Iterable[RouteRow]:
    for rule in app.url_map.iter_rules():
        # Ignore Flask's built-in static endpoint; we explicitly serve static via our own routes.
        if rule.endpoint == "static":
            continue
        methods = sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}])
        yield RouteRow(rule=rule.rule, methods=methods, endpoint=rule.endpoint)


def _sorted_routes(routes: Iterable[RouteRow]) -> List[RouteRow]:
    return sorted(
        list(routes),
        key=lambda r: (r.rule, ",".join(r.methods), r.endpoint),
    )


def _load_app(app_name: str):
    # Ensure repo root is on sys.path even when invoked as `python scripts/...`.
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    if app_name == "web_api":
        from web_api import create_app

        return create_app()
    if app_name == "web_ui":
        import web_ui

        return web_ui.app
    raise ValueError(f"Unknown app: {app_name}")


def _routes_payload(app_name: str) -> Dict[str, Any]:
    app = _load_app(app_name)
    rows = _sorted_routes(_iter_routes(app))
    return {
        "app": app_name,
        "count": len(rows),
        "routes": [
            {
                "methods": r.methods,
                "rule": r.rule,
                "endpoint": r.endpoint,
            }
            for r in rows
        ],
    }


def _print_text(payload: Dict[str, Any]) -> None:
    print(f"{payload['app']} routes: {payload['count']}")
    for r in payload["routes"]:
        methods = ",".join(r["methods"])
        print(f"{methods:<10} {r['rule']:<35} -> {r['endpoint']}")


def _print_markdown(payload: Dict[str, Any]) -> None:
    print(f"## `{payload['app']}` routes ({payload['count']})\n")
    print("| Methods | Path | Endpoint |")
    print("|---|---|---|")
    for r in payload["routes"]:
        methods = ", ".join(r["methods"])
        print(f"| `{methods}` | `{r['rule']}` | `{r['endpoint']}` |")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="List Flask routes for web_api/web_ui.")
    parser.add_argument(
        "--app",
        choices=("web_api", "web_ui", "both"),
        default="both",
        help="Which app to inspect (default: both).",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    args = parser.parse_args(argv)

    apps = ["web_api", "web_ui"] if args.app == "both" else [args.app]
    payloads = [_routes_payload(a) for a in apps]

    if args.format == "json":
        print(json.dumps(payloads if len(payloads) > 1 else payloads[0], indent=2))
        return 0

    for idx, payload in enumerate(payloads):
        if args.format == "markdown":
            _print_markdown(payload)
            if idx != len(payloads) - 1:
                print()
            continue

        # text
        _print_text(payload)
        if idx != len(payloads) - 1:
            print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
