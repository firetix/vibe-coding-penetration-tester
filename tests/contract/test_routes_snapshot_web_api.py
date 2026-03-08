import json
from pathlib import Path
from typing import Any, Dict, List


def _extract_routes() -> List[Dict[str, Any]]:
    from web_api import create_app

    app = create_app()
    routes: List[Dict[str, Any]] = []
    for rule in app.url_map.iter_rules():
        # Ignore Flask built-in static endpoint; we explicitly serve static via our own routes.
        if rule.endpoint == "static":
            continue
        methods = sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}])
        routes.append({"rule": rule.rule, "methods": methods})

    routes.sort(key=lambda r: (r["rule"], ",".join(r["methods"])))
    return routes


def test_web_api_routes_match_snapshot():
    snapshot_path = Path(__file__).resolve().parent / "routes_web_api.snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    assert snapshot == _extract_routes()

