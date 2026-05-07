import ipaddress
import json
import os
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from .app_config import ALWAYS_CONFIRM_ACTIONS, BATCH_CONFIRM_ACTIONS, DEFAULT_CONFIRM_MODE, DEFAULT_CONFIRM_MODE_FILE, DEFAULT_WHITELIST_CONFIG_FILE, DEFAULT_WHITELIST_FILE, WRITE_ACTIONS


class GuardrailError(Exception):
    pass


@dataclass(slots=True)
class WhitelistMatch:
    target: str
    rule: str
    reason: str


def resolve_confirm_mode_file() -> str:
    return (os.getenv("CONFIRM_MODE_FILE") or DEFAULT_CONFIRM_MODE_FILE).strip()


def resolve_whitelist_config_file() -> str:
    return (os.getenv("WHITELIST_CONFIG_FILE") or DEFAULT_WHITELIST_CONFIG_FILE).strip()


def _load_persisted_confirm_mode() -> str | None:
    file_path = resolve_confirm_mode_file()
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("confirmMode")
    if not isinstance(value, str):
        return None
    normalized_value = value.strip().lower()
    if normalized_value not in {"auto", "manual"}:
        return None
    return normalized_value


def persist_confirm_mode(confirm_mode: str) -> dict[str, Any]:
    normalized_mode = _normalize_confirm_mode(confirm_mode)
    file_path = resolve_confirm_mode_file()
    if not file_path:
        raise GuardrailError("未配置 confirm_mode 持久化文件路径")
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = {
        "confirmMode": normalized_mode,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return payload


def _load_persisted_whitelist_file() -> str | None:
    file_path = resolve_whitelist_config_file()
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("whitelistFile")
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def persist_whitelist_file(whitelist_file: str) -> dict[str, Any]:
    normalized_file = whitelist_file.strip()
    if not normalized_file:
        raise GuardrailError("whitelist_file 不能为空")
    file_path = resolve_whitelist_config_file()
    if not file_path:
        raise GuardrailError("未配置 whitelist 持久化文件路径")
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = {
        "whitelistFile": normalized_file,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return payload


def _normalize_confirm_mode(value: str) -> str:
    normalized_value = value.strip().lower()
    if normalized_value not in {"auto", "manual"}:
        raise GuardrailError("confirm_mode 仅支持 auto 或 manual")
    return normalized_value


def resolve_confirm_mode(confirm_mode: str | None = None) -> str:
    if confirm_mode is not None:
        return _normalize_confirm_mode(confirm_mode)
    persisted_mode = _load_persisted_confirm_mode()
    if persisted_mode is not None:
        return persisted_mode
    env_mode = os.getenv("CONFIRM_MODE")
    if env_mode:
        return _normalize_confirm_mode(env_mode)
    return DEFAULT_CONFIRM_MODE


def resolve_whitelist_file(whitelist_file: str | None = None) -> str:
    explicit_file = whitelist_file.strip() if isinstance(whitelist_file, str) else ""
    if explicit_file:
        return explicit_file
    persisted_file = _load_persisted_whitelist_file()
    if persisted_file:
        return persisted_file
    return (os.getenv("WHITELIST_FILE") or DEFAULT_WHITELIST_FILE).strip()


def _load_raw_rules(whitelist_file: str | None = None) -> list[dict[str, Any]]:
    file_path = resolve_whitelist_file(whitelist_file)
    if not file_path or not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        raise GuardrailError("白名单文件格式错误，必须包含 rules 数组")
    return [rule for rule in rules if isinstance(rule, dict)]


def _normalize_targets(targets: list[str]) -> list[ipaddress._BaseAddress]:
    normalized: list[ipaddress._BaseAddress] = []
    for target in targets:
        candidate = target.strip()
        if not candidate:
            continue
        try:
            normalized.append(ipaddress.ip_address(candidate))
        except ValueError as error:
            raise GuardrailError(f"非法 IP 地址: {candidate}") from error
    return normalized


def check_whitelist(targets: list[str], whitelist_file: str | None = None) -> dict[str, Any]:
    parsed_targets = _normalize_targets(targets)
    rules = _load_raw_rules(whitelist_file)
    matches: list[WhitelistMatch] = []

    for rule in rules:
        value = str(rule.get("value", "")).strip()
        reason = str(rule.get("reason", "未命名规则")).strip() or "未命名规则"
        if not value:
            continue

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise GuardrailError(f"白名单规则格式错误: {value}") from error

        for target in parsed_targets:
            if target in network:
                matches.append(WhitelistMatch(target=str(target), rule=value, reason=reason))

    return {
        "allowed": len(matches) == 0,
        "matches": [
            {
                "target": match.target,
                "rule": match.rule,
                "reason": match.reason,
            }
            for match in matches
        ],
        "checkedTargets": [str(target) for target in parsed_targets],
        "whitelistFile": resolve_whitelist_file(whitelist_file),
    }


def check_confirmation(
    action: str,
    *,
    confirm: bool = False,
    confirm_mode: str | None = None,
    target_count: int = 0,
) -> dict[str, Any]:
    mode = resolve_confirm_mode(confirm_mode)
    normalized_action = action.strip()
    requires_confirm = False
    reason = ""

    if normalized_action in WRITE_ACTIONS and mode == "manual":
        requires_confirm = True
        reason = "当前处于 manual 模式，所有写操作都必须显式确认"
    elif normalized_action in ALWAYS_CONFIRM_ACTIONS:
        requires_confirm = True
        reason = "清空类操作必须显式确认"
    elif normalized_action in BATCH_CONFIRM_ACTIONS and mode == "auto":
        requires_confirm = True
        reason = "当前处于 auto 模式，高风险写操作必须显式确认"

    if requires_confirm and not confirm:
        return {
            "allowed": False,
            "confirmRequired": True,
            "confirmMode": mode,
            "reason": reason,
        }

    return {
        "allowed": True,
        "confirmRequired": requires_confirm,
        "confirmMode": mode,
        "reason": reason,
    }


def describe_guardrails() -> dict[str, Any]:
    whitelist_file = resolve_whitelist_file()
    rules = _load_raw_rules(whitelist_file)
    confirm_mode_file = resolve_confirm_mode_file()
    persisted_mode = _load_persisted_confirm_mode()
    whitelist_config_file = resolve_whitelist_config_file()
    persisted_whitelist_file = _load_persisted_whitelist_file()
    return {
        "confirmMode": resolve_confirm_mode(),
        "confirmModeSource": "persisted" if persisted_mode else ("environment" if os.getenv("CONFIRM_MODE") else "default"),
        "confirmModeFile": confirm_mode_file,
        "confirmModeFileExists": os.path.exists(confirm_mode_file),
        "whitelistFile": whitelist_file,
        "whitelistSource": "persisted" if persisted_whitelist_file else ("environment" if os.getenv("WHITELIST_FILE") else "default"),
        "whitelistConfigFile": whitelist_config_file,
        "whitelistConfigFileExists": os.path.exists(whitelist_config_file),
        "whitelistFileExists": os.path.exists(whitelist_file),
        "whitelistRuleCount": len(rules),
        "writeActions": sorted(WRITE_ACTIONS),
        "alwaysConfirmActions": sorted(ALWAYS_CONFIRM_ACTIONS),
        "batchConfirmActions": sorted(BATCH_CONFIRM_ACTIONS),
    }