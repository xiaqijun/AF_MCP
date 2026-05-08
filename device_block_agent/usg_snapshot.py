from __future__ import annotations

import datetime
import glob
import json
import os
import secrets
from typing import Any


def _default_dir() -> str:
    directory = os.environ.get("USG_ACTION_DIR", "").strip()
    if directory:
        os.makedirs(directory, exist_ok=True)
        return directory
    base = os.path.expanduser("~")
    directory = os.path.join(base, ".device-block-agent", "usg-actions")
    os.makedirs(directory, exist_ok=True)
    return directory


def new_action_id() -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    random_suffix = secrets.token_hex(3)
    return f"act-{timestamp}-{random_suffix}"


def save(action: dict[str, Any]) -> str:
    directory = _default_dir()
    path = os.path.join(directory, f"{action['action_id']}.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(action, handle, ensure_ascii=False, indent=2)
    return path


def load(action_id: str) -> dict[str, Any] | None:
    directory = _default_dir()
    path = os.path.join(directory, f"{action_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def update(action_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    action = load(action_id)
    if action is None:
        return None
    action.update(patch)
    save(action)
    return action


def list_recent(limit: int = 20, ip: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    directory = _default_dir()
    files = sorted(
        glob.glob(os.path.join(directory, "act-*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    results: list[dict[str, Any]] = []
    for path in files:
        try:
            with open(path, encoding="utf-8") as handle:
                action = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if ip and action.get("ip") != ip:
            continue
        if status and action.get("status") != status:
            continue
        results.append(action)
        if len(results) >= limit:
            break
    return results


def now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")