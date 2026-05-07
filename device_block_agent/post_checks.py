from typing import Any

from .af_client import AFClientError, get_block_time, get_block_total_count, list_business_blocks, list_temp_blocks


def _extract_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    for key in ("rows", "items", "records", "list", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    for value in payload.values():
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return value
    return []


def _record_ips(record: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("srcIP", "dstIP", "blockAddr"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            values.add(value.strip())
    return values


def _build_check(name: str, status: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "details": details,
    }


def _summarize_status(checks: list[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "failed" in statuses:
        return "failed"
    if statuses == {"passed"}:
        return "passed"
    return "inconclusive"


def evaluate_recheck(
    action: str,
    snapshot: dict[str, Any],
    *,
    baseline_snapshot: dict[str, Any] | None = None,
    expected_targets: list[str] | None = None,
    expected_block_time: str | None = None,
    expected_brute_block_time: str | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    expected_target_set = {target.strip() for target in (expected_targets or []) if target.strip()}

    if action == "block_add_business":
        business_list = snapshot.get("businessList") or {}
        records = _extract_records(business_list)
        matched_targets = sorted(
            target for target in expected_target_set if any(target in _record_ips(record) for record in records)
        )
        missing_targets = sorted(expected_target_set - set(matched_targets))
        status = "passed" if expected_target_set and not missing_targets else "failed"
        checks.append(
            _build_check(
                "business_targets_present",
                status,
                {"expectedTargets": sorted(expected_target_set), "matchedTargets": matched_targets, "missingTargets": missing_targets},
            )
        )

    elif action == "block_delete_business":
        business_list = snapshot.get("businessList") or {}
        records = _extract_records(business_list)
        remaining_targets = sorted(
            target for target in expected_target_set if any(target in _record_ips(record) for record in records)
        )
        checks.append(
            _build_check(
                "business_targets_absent",
                "passed" if not remaining_targets else "failed",
                {"expectedRemovedTargets": sorted(expected_target_set), "remainingTargets": remaining_targets},
            )
        )

    elif action == "block_delete_temp":
        temp_list = snapshot.get("tempList") or {}
        records = _extract_records(temp_list)
        remaining_targets = sorted(
            target for target in expected_target_set if any(target in _record_ips(record) for record in records)
        )
        checks.append(
            _build_check(
                "temp_targets_absent",
                "passed" if not remaining_targets else "failed",
                {"expectedRemovedTargets": sorted(expected_target_set), "remainingTargets": remaining_targets},
            )
        )

    elif action == "block_clear_business":
        business_list = snapshot.get("businessList") or {}
        records = _extract_records(business_list)
        checks.append(
            _build_check(
                "business_list_empty",
                "passed" if not records else "failed",
                {"remainingCount": len(records)},
            )
        )

    elif action == "block_clear_temp":
        temp_list = snapshot.get("tempList") or {}
        records = _extract_records(temp_list)
        checks.append(
            _build_check(
                "temp_list_empty",
                "passed" if not records else "failed",
                {"remainingCount": len(records)},
            )
        )

    elif action == "block_set_block_time":
        block_time = snapshot.get("blockTime") or {}
        if expected_block_time is not None:
            checks.append(
                _build_check(
                    "block_time_matches",
                    "passed" if block_time.get("blockTime") == expected_block_time else "failed",
                    {"expected": expected_block_time, "actual": block_time.get("blockTime")},
                )
            )
        if expected_brute_block_time is not None:
            checks.append(
                _build_check(
                    "brute_block_time_matches",
                    "passed" if block_time.get("bruteBlockTime") == expected_brute_block_time else "failed",
                    {"expected": expected_brute_block_time, "actual": block_time.get("bruteBlockTime")},
                )
            )

    elif action == "block_clear_attackers":
        baseline_total_count = (baseline_snapshot or {}).get("totalCount") or {}
        total_count = snapshot.get("totalCount") or {}
        baseline_count_value = baseline_total_count.get("cnt")
        count_value = total_count.get("cnt")
        if baseline_count_value is None:
            status = "inconclusive"
        elif count_value == 0 and baseline_count_value >= 0:
            status = "passed"
        elif isinstance(baseline_count_value, int) and isinstance(count_value, int) and count_value < baseline_count_value:
            status = "passed"
        else:
            status = "failed"
        checks.append(
            _build_check(
                "attacker_total_count_delta",
                status,
                {
                    "baselineCount": baseline_count_value,
                    "actualCount": count_value,
                    "note": "blocktotalcnt 是总量指标，当前通过前后基线变化做有限回检。",
                },
            )
        )

    if not checks:
        checks.append(
            _build_check(
                "generic_snapshot_only",
                "inconclusive",
                {"note": "当前动作没有专用回检规则，已返回基础快照。"},
            )
        )

    return {
        "success": snapshot.get("success", True),
        "status": _summarize_status(checks),
        "action": action,
        "checks": checks,
        "snapshot": snapshot,
    }


def build_recheck_snapshot(
    host: str,
    namespace: str,
    *,
    verify_tls: bool = True,
    include_lists: bool = False,
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"success": True}
    try:
        snapshot["totalCount"] = get_block_total_count(host, namespace, verify_tls=verify_tls)
    except AFClientError as error:
        snapshot["success"] = False
        snapshot["totalCountError"] = str(error)

    try:
        snapshot["blockTime"] = get_block_time(host, namespace, verify_tls=verify_tls)
    except AFClientError as error:
        snapshot["success"] = False
        snapshot["blockTimeError"] = str(error)

    if include_lists:
        try:
            snapshot["businessList"] = list_business_blocks(host, namespace, verify_tls=verify_tls)
        except AFClientError as error:
            snapshot["success"] = False
            snapshot["businessListError"] = str(error)
        try:
            snapshot["tempList"] = list_temp_blocks(host, namespace, verify_tls=verify_tls)
        except AFClientError as error:
            snapshot["success"] = False
            snapshot["tempListError"] = str(error)

    return snapshot


def build_action_recheck(
    action: str,
    host: str,
    namespace: str,
    *,
    verify_tls: bool = True,
    baseline_snapshot: dict[str, Any] | None = None,
    expected_targets: list[str] | None = None,
    expected_block_time: str | None = None,
    expected_brute_block_time: str | None = None,
) -> dict[str, Any]:
    snapshot = build_recheck_snapshot(host, namespace, verify_tls=verify_tls)

    if action == "block_add_business":
        business_list = list_business_blocks(host, namespace, verify_tls=verify_tls)
        snapshot["businessList"] = business_list

    elif action == "block_delete_business":
        business_list = list_business_blocks(host, namespace, verify_tls=verify_tls)
        snapshot["businessList"] = business_list

    elif action == "block_delete_temp":
        temp_list = list_temp_blocks(host, namespace, verify_tls=verify_tls)
        snapshot["tempList"] = temp_list

    elif action == "block_clear_business":
        business_list = list_business_blocks(host, namespace, verify_tls=verify_tls)
        snapshot["businessList"] = business_list

    elif action == "block_clear_temp":
        temp_list = list_temp_blocks(host, namespace, verify_tls=verify_tls)
        snapshot["tempList"] = temp_list
    return evaluate_recheck(
        action,
        snapshot,
        baseline_snapshot=baseline_snapshot,
        expected_targets=expected_targets,
        expected_block_time=expected_block_time,
        expected_brute_block_time=expected_brute_block_time,
    )