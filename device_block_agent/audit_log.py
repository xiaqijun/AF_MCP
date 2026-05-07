import json
import os
from datetime import datetime, timezone
from typing import Any

from .app_config import DEFAULT_LOG_FILE


SENSITIVE_KEYS = {"password", "token", "cftoken", "sharekey"}


def resolve_log_file(log_file: str | None = None) -> str:
    return (log_file or os.getenv("LOG_FILE") or DEFAULT_LOG_FILE).strip()


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("***" if key.lower() in SENSITIVE_KEYS else _redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def append_audit_log(event_type: str, details: dict[str, Any], *, log_file: str | None = None) -> str:
    path = resolve_log_file(log_file)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "eventType": event_type,
        "details": _redact(details),
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return path