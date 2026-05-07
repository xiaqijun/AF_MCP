import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Any

from .app_config import ALWAYS_CONFIRM_ACTIONS, BATCH_CONFIRM_ACTIONS, DEFAULT_CONFIRM_MODE, DEFAULT_WHITELIST_FILE


class GuardrailError(Exception):
    pass


@dataclass(slots=True)
class WhitelistMatch:
    target: str
    rule: str
    reason: str


def resolve_confirm_mode(confirm_mode: str | None = None) -> str:
    value = (confirm_mode or os.getenv("CONFIRM_MODE") or DEFAULT_CONFIRM_MODE).strip().lower()
    if value not in {"auto", "manual"}:
        raise GuardrailError("confirm_mode 仅支持 auto 或 manual")
    return value


def resolve_whitelist_file(whitelist_file: str | None = None) -> str:
    return (whitelist_file or os.getenv("WHITELIST_FILE") or DEFAULT_WHITELIST_FILE).strip()


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

    if normalized_action in ALWAYS_CONFIRM_ACTIONS:
        requires_confirm = True
        reason = "清空类操作必须显式确认"
    elif normalized_action in BATCH_CONFIRM_ACTIONS and mode == "manual":
        requires_confirm = True
        reason = "当前处于 manual 模式，批量高风险操作必须显式确认"
    elif normalized_action in BATCH_CONFIRM_ACTIONS and target_count > 10:
        requires_confirm = True
        reason = "批量目标超过 10 条，必须显式确认"

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
    return {
        "confirmMode": resolve_confirm_mode(),
        "whitelistFile": whitelist_file,
        "whitelistFileExists": os.path.exists(whitelist_file),
        "whitelistRuleCount": len(rules),
        "alwaysConfirmActions": sorted(ALWAYS_CONFIRM_ACTIONS),
        "batchConfirmActions": sorted(BATCH_CONFIRM_ACTIONS),
    }