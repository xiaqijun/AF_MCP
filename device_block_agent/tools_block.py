from typing import Any

from .account_config import resolve_connection_settings, validate_connection_settings
from .audit_log import append_audit_log
from .af_client import (
    AFClientError,
    add_attacker_blocks,
    add_business_blocks,
    add_exception_blocks,
    clear_attackers,
    clear_business_blocks,
    clear_temp_blocks,
    delete_attacker_blocks,
    delete_business_blocks,
    delete_exception_blocks,
    delete_temp_blocks,
    get_block_time,
    get_block_total_count,
    list_attacker_blocks,
    list_business_blocks,
    list_exception_blocks,
    list_temp_blocks,
    set_block_time,
    update_exception_block,
    update_exception_blocks,
)
from .post_checks import build_action_recheck
from .risk_controls import GuardrailError, check_confirmation, check_whitelist


def _error_result(error: AFClientError) -> dict[str, Any]:
    return {
        "success": False,
        "message": str(error),
        "code": error.code,
        "data": error.data,
    }


def _guardrail_error_result(error: GuardrailError) -> dict[str, Any]:
    return {
        "success": False,
        "message": str(error),
        "code": "guardrail_error",
        "data": None,
    }


def _config_error_result(error: ValueError) -> dict[str, Any]:
    return {
        "success": False,
        "message": str(error),
        "code": "config_error",
        "data": None,
    }


def _log_and_return(action: str, context: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    append_audit_log(action, {**context, "result": result, "success": result.get("success", True)})
    return result


def _extract_target_ips(records: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for record in records:
        for field in ("srcIP", "dstIP", "blockAddr"):
            value = record.get(field)
            if isinstance(value, str) and value.strip():
                targets.append(value.strip())
    return targets


def _extract_attacker_target_ips(payload: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    for field in ("srcIP", "dstIP"):
        value = payload.get(field)
        if isinstance(value, list):
            targets.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    return targets


def _count_attacker_targets(payload: dict[str, Any]) -> int:
    total = 0
    for field in ("srcIP", "dstIP", "dns", "url"):
        value = payload.get(field)
        if isinstance(value, list):
            total += len([item for item in value if isinstance(item, str) and str(item).strip()])
    return total


def _blocked_by_whitelist(
    *,
    targets: list[str],
    whitelist_file: str | None,
) -> dict[str, Any] | None:
    if not targets:
        return None
    whitelist_check = check_whitelist(targets, whitelist_file=whitelist_file)
    if whitelist_check["allowed"]:
        return None
    return {
        "success": False,
        "message": "白名单命中，已阻断执行",
        "code": "whitelist_blocked",
        "data": whitelist_check,
    }


def _blocked_by_confirmation(
    *,
    action: str,
    confirm: bool,
    confirm_mode: str | None,
    target_count: int,
) -> dict[str, Any] | None:
    confirmation = check_confirmation(
        action,
        confirm=confirm,
        confirm_mode=confirm_mode,
        target_count=target_count,
    )
    if confirmation["allowed"]:
        return None
    return {
        "success": False,
        "message": confirmation["reason"] or "需要人工确认",
        "code": "confirmation_required",
        "data": confirmation,
    }


def register_block_query_tools(mcp: Any) -> None:
    @mcp.tool(
        name="block_list_exceptions",
        description="查询例外封锁配置列表。",
    )
    def block_list_exceptions(
        host: str | None = None,
        namespace: str | None = None,
        start: int | None = None,
        length: int | None = None,
        search: str | None = None,
        select: str | None = None,
        sortby: str | None = None,
        order: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return list_exception_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                start=start,
                length=length,
                search=search,
                select=select,
                sortby=sortby,
                order=order,
                verify_tls=settings["verify_tls"],
            )
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_add_exceptions",
        description="批量新增例外封锁配置。",
    )
    def block_add_exceptions(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result_data = add_exception_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                records=records,
                verify_tls=settings["verify_tls"],
            )
            return _log_and_return("block_add_exceptions", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_add_exceptions", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_add_exceptions", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_delete_exceptions",
        description="批量删除例外封锁配置。",
    )
    def block_delete_exceptions(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result_data = delete_exception_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                records=records,
                verify_tls=settings["verify_tls"],
            )
            return _log_and_return("block_delete_exceptions", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_delete_exceptions", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_delete_exceptions", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_update_exceptions",
        description="批量修改例外封锁配置。",
    )
    def block_update_exceptions(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        key: str | None = None,
        where: str | None = None,
        dest: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result_data = update_exception_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                records=records,
                key=key,
                where=where,
                dest=dest,
                verify_tls=settings["verify_tls"],
            )
            return _log_and_return("block_update_exceptions", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_update_exceptions", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_update_exceptions", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_update_exception",
        description="修改单项例外封锁配置。",
    )
    def block_update_exception(
        record: dict[str, Any],
        host: str | None = None,
        namespace: str | None = None,
        key: str | None = None,
        ip_name: str | None = None,
        where: str | None = None,
        dest: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result_data = update_exception_block(
                host=settings["host"],
                namespace=settings["namespace"],
                record=record,
                key=key,
                ip_name=ip_name,
                where=where,
                dest=dest,
                verify_tls=settings["verify_tls"],
            )
            return _log_and_return("block_update_exception", {"host": settings["host"], "namespace": settings["namespace"], "record": record}, result_data)
        except ValueError as error:
            return _log_and_return("block_update_exception", {"host": host, "namespace": namespace, "record": record}, _config_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_update_exception", {"host": host, "namespace": namespace, "record": record}, _error_result(error))

    @mcp.tool(
        name="block_list_attackers",
        description="查询封锁攻击者 IP 列表。",
    )
    def block_list_attackers(
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        start: int | None = None,
        length: int | None = None,
        search: str | None = None,
        sortby: str | None = None,
        order: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return list_attacker_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                start=start,
                length=length,
                search=search,
                sortby=sortby,
                order=order,
                verify_tls=settings["verify_tls"],
            )
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_list_temp",
        description="查询临时封锁 IP 列表。",
    )
    def block_list_temp(
        host: str | None = None,
        namespace: str | None = None,
        start: int | None = None,
        length: int | None = None,
        search: str | None = None,
        sortby: str | None = None,
        order: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return list_temp_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                start=start,
                length=length,
                search=search,
                sortby=sortby,
                order=order,
                verify_tls=settings["verify_tls"],
            )
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_list_business",
        description="查询业务封锁 IP 列表。",
    )
    def block_list_business(
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        start: int | None = None,
        length: int | None = None,
        search: str | None = None,
        sortby: str | None = None,
        order: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return list_business_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                start=start,
                length=length,
                search=search,
                sortby=sortby,
                order=order,
                verify_tls=settings["verify_tls"],
            )
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_get_total_count",
        description="获取当前命名空间下的封锁总条数。",
    )
    def block_get_total_count(
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return get_block_total_count(host=settings["host"], namespace=settings["namespace"], verify_tls=settings["verify_tls"])
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_get_block_time",
        description="获取自动封锁攻击者时间配置。",
    )
    def block_get_block_time(
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            return get_block_time(host=settings["host"], namespace=settings["namespace"], verify_tls=settings["verify_tls"])
        except ValueError as error:
            return _config_error_result(error)
        except AFClientError as error:
            return _error_result(error)

    @mcp.tool(
        name="block_add_attackers",
        description="批量新增封锁攻击者，并在执行前进行白名单和人工确认校验。",
    )
    def block_add_attackers(
        payload: dict[str, Any],
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        aifw_type: str | None = None,
        override: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            whitelist_block = _blocked_by_whitelist(targets=_extract_attacker_target_ips(payload), whitelist_file=whitelist_file)
            if whitelist_block:
                return _log_and_return("block_add_attackers", {"host": settings["host"], "namespace": settings["namespace"], "payload": payload}, whitelist_block)
            confirmation_block = _blocked_by_confirmation(
                action="block_add_attackers",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=_count_attacker_targets(payload),
            )
            if confirmation_block:
                return _log_and_return("block_add_attackers", {"host": settings["host"], "namespace": settings["namespace"], "payload": payload}, confirmation_block)
            result_data = add_attacker_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                payload=payload,
                creator=creator,
                aifw_type=aifw_type,
                override=override,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_add_attackers",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_targets=_extract_attacker_target_ips(payload),
                )
            return _log_and_return("block_add_attackers", {"host": settings["host"], "namespace": settings["namespace"], "payload": payload}, result_data)
        except ValueError as error:
            return _log_and_return("block_add_attackers", {"host": host, "namespace": namespace, "payload": payload}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_add_attackers", {"host": host, "namespace": namespace, "payload": payload}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_add_attackers", {"host": host, "namespace": namespace, "payload": payload}, _error_result(error))

    @mcp.tool(
        name="block_delete_attackers",
        description="批量删除封锁攻击者，并在执行前进行白名单和人工确认校验。",
    )
    def block_delete_attackers(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            whitelist_block = _blocked_by_whitelist(targets=_extract_target_ips(records), whitelist_file=whitelist_file)
            if whitelist_block:
                return _log_and_return("block_delete_attackers", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, whitelist_block)
            confirmation_block = _blocked_by_confirmation(
                action="block_delete_attackers",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=len(records),
            )
            if confirmation_block:
                return _log_and_return("block_delete_attackers", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, confirmation_block)
            result_data = delete_attacker_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                records=records,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_delete_attackers",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_targets=_extract_target_ips(records),
                )
            return _log_and_return("block_delete_attackers", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_delete_attackers", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_delete_attackers", {"host": host, "namespace": namespace, "records": records}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_delete_attackers", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_add_business",
        description="新增业务封锁 IP，并在执行前进行白名单和人工确认校验。",
    )
    def block_add_business(
        src_ips: list[str],
        host: str | None = None,
        namespace: str | None = None,
        block_time: str | None = None,
        creator: str | None = None,
        aifw_type: str | None = None,
        override: str | None = None,
        result: list[dict[str, Any]] | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            whitelist_block = _blocked_by_whitelist(targets=src_ips, whitelist_file=whitelist_file)
            if whitelist_block:
                return _log_and_return("block_add_business", {"host": settings["host"], "namespace": settings["namespace"], "srcIPs": src_ips}, whitelist_block)
            confirmation_block = _blocked_by_confirmation(
                action="block_add_business",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=len(src_ips),
            )
            if confirmation_block:
                return _log_and_return("block_add_business", {"host": settings["host"], "namespace": settings["namespace"], "srcIPs": src_ips}, confirmation_block)
            result_data = add_business_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                src_ips=src_ips,
                block_time=block_time,
                creator=creator,
                aifw_type=aifw_type,
                override=override,
                result_items=result,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_add_business",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_targets=src_ips,
                )
            return _log_and_return("block_add_business", {"host": settings["host"], "namespace": settings["namespace"], "srcIPs": src_ips}, result_data)
        except ValueError as error:
            return _log_and_return("block_add_business", {"host": host, "namespace": namespace, "srcIPs": src_ips}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_add_business", {"host": host, "namespace": namespace, "srcIPs": src_ips}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_add_business", {"host": host, "namespace": namespace, "srcIPs": src_ips}, _error_result(error))

    @mcp.tool(
        name="block_delete_temp",
        description="按条件删除临时封锁 IP，并在执行前进行白名单和人工确认校验。",
    )
    def block_delete_temp(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            whitelist_block = _blocked_by_whitelist(
                targets=_extract_target_ips(records),
                whitelist_file=whitelist_file,
            )
            if whitelist_block:
                return _log_and_return("block_delete_temp", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, whitelist_block)
            confirmation_block = _blocked_by_confirmation(
                action="block_delete_temp",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=len(records),
            )
            if confirmation_block:
                return _log_and_return("block_delete_temp", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, confirmation_block)
            result_data = delete_temp_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                records=records,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_delete_temp",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_targets=_extract_target_ips(records),
                )
            return _log_and_return("block_delete_temp", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_delete_temp", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_delete_temp", {"host": host, "namespace": namespace, "records": records}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_delete_temp", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_delete_business",
        description="按条件删除业务封锁 IP，并在执行前进行白名单和人工确认校验。",
    )
    def block_delete_business(
        records: list[dict[str, Any]],
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            whitelist_block = _blocked_by_whitelist(
                targets=_extract_target_ips(records),
                whitelist_file=whitelist_file,
            )
            if whitelist_block:
                return _log_and_return("block_delete_business", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, whitelist_block)
            confirmation_block = _blocked_by_confirmation(
                action="block_delete_business",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=len(records),
            )
            if confirmation_block:
                return _log_and_return("block_delete_business", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, confirmation_block)
            result_data = delete_business_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                records=records,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_delete_business",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_targets=_extract_target_ips(records),
                )
            return _log_and_return("block_delete_business", {"host": settings["host"], "namespace": settings["namespace"], "records": records}, result_data)
        except ValueError as error:
            return _log_and_return("block_delete_business", {"host": host, "namespace": namespace, "records": records}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_delete_business", {"host": host, "namespace": namespace, "records": records}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_delete_business", {"host": host, "namespace": namespace, "records": records}, _error_result(error))

    @mcp.tool(
        name="block_clear_attackers",
        description="清空封锁攻击者记录，并强制要求显式确认。",
    )
    def block_clear_attackers(
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            confirmation_block = _blocked_by_confirmation(
                action="block_clear_attackers",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=0,
            )
            if confirmation_block:
                return _log_and_return("block_clear_attackers", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, confirmation_block)
            baseline_snapshot = {
                "success": True,
                "totalCount": get_block_total_count(host=settings["host"], namespace=settings["namespace"], verify_tls=settings["verify_tls"]),
            }
            result_data = clear_attackers(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_clear_attackers",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    baseline_snapshot=baseline_snapshot,
                )
            return _log_and_return("block_clear_attackers", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, result_data)
        except ValueError as error:
            return _log_and_return("block_clear_attackers", {"host": host, "namespace": namespace, "creator": creator}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_clear_attackers", {"host": host, "namespace": namespace, "creator": creator}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_clear_attackers", {"host": host, "namespace": namespace, "creator": creator}, _error_result(error))

    @mcp.tool(
        name="block_clear_temp",
        description="清空临时封锁 IP，并强制要求显式确认。",
    )
    def block_clear_temp(
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            confirmation_block = _blocked_by_confirmation(
                action="block_clear_temp",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=0,
            )
            if confirmation_block:
                return _log_and_return("block_clear_temp", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, confirmation_block)
            result_data = clear_temp_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_clear_temp",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                )
            return _log_and_return("block_clear_temp", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, result_data)
        except ValueError as error:
            return _log_and_return("block_clear_temp", {"host": host, "namespace": namespace, "creator": creator}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_clear_temp", {"host": host, "namespace": namespace, "creator": creator}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_clear_temp", {"host": host, "namespace": namespace, "creator": creator}, _error_result(error))

    @mcp.tool(
        name="block_clear_business",
        description="清空业务封锁 IP，并强制要求显式确认。",
    )
    def block_clear_business(
        host: str | None = None,
        namespace: str | None = None,
        creator: str | None = None,
        confirm: bool = False,
        confirm_mode: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            confirmation_block = _blocked_by_confirmation(
                action="block_clear_business",
                confirm=confirm,
                confirm_mode=confirm_mode,
                target_count=0,
            )
            if confirmation_block:
                return _log_and_return("block_clear_business", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, confirmation_block)
            result_data = clear_business_blocks(
                host=settings["host"],
                namespace=settings["namespace"],
                creator=creator,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_clear_business",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                )
            return _log_and_return("block_clear_business", {"host": settings["host"], "namespace": settings["namespace"], "creator": creator}, result_data)
        except ValueError as error:
            return _log_and_return("block_clear_business", {"host": host, "namespace": namespace, "creator": creator}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_clear_business", {"host": host, "namespace": namespace, "creator": creator}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_clear_business", {"host": host, "namespace": namespace, "creator": creator}, _error_result(error))

    @mcp.tool(
        name="block_set_block_time",
        description="修改自动封锁攻击者时间配置。",
    )
    def block_set_block_time(
        host: str | None = None,
        namespace: str | None = None,
        block_time: str | None = None,
        brute_block_time: str | None = None,
        include_recheck: bool = True,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result_data = set_block_time(
                host=settings["host"],
                namespace=settings["namespace"],
                block_time=block_time,
                brute_block_time=brute_block_time,
                verify_tls=settings["verify_tls"],
            )
            if include_recheck:
                result_data["recheck"] = build_action_recheck(
                    "block_set_block_time",
                    settings["host"],
                    settings["namespace"],
                    verify_tls=settings["verify_tls"],
                    expected_block_time=block_time,
                    expected_brute_block_time=brute_block_time,
                )
            return _log_and_return("block_set_block_time", {"host": settings["host"], "namespace": settings["namespace"]}, result_data)
        except ValueError as error:
            return _log_and_return("block_set_block_time", {"host": host, "namespace": namespace}, _config_error_result(error))
        except GuardrailError as error:
            return _log_and_return("block_set_block_time", {"host": host, "namespace": namespace}, _guardrail_error_result(error))
        except AFClientError as error:
            return _log_and_return("block_set_block_time", {"host": host, "namespace": namespace}, _error_result(error))