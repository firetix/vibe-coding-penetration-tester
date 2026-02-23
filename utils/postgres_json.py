import json
from typing import Any


def coerce_json_value(value: Any, default: Any) -> Any:
    """Normalize DB JSON/JSONB values to Python objects with a safe default."""
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", errors="ignore")
        except Exception:
            return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    return default
