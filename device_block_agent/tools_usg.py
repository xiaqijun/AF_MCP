from __future__ import annotations

import base64
import datetime
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from .account_config import resolve_usg_connection_settings, validate_usg_connection_settings
from .audit_log import append_audit_log
from .risk_controls import check_confirmation, check_whitelist, resolve_confirm_mode, resolve_whitelist_file
from .usg_whitelist import auto_load_default as _wl_auto_load, get_engine as _get_wl_engine
from . import usg_snapshot as _snap


_WL_AUTOLOAD_PATH = _wl_auto_load()


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name, default)
    candidate = str(value).strip()
    if candidate.startswith("${") and candidate.endswith("}"):
        return default
    return candidate


def _parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _resolve_usg_settings(
    *,
    usg_host: str | None = None,
    usg_port: str | None = None,
    usg_username: str | None = None,
    usg_password: str | None = None,
    usg_verify_ssl: bool | str | None = None,
) -> dict[str, Any]:
    return resolve_usg_connection_settings(
        host=usg_host,
        port=usg_port,
        username=usg_username,
        password=usg_password,
        verify_ssl=usg_verify_ssl,
    )


def _validate_usg_settings(settings: dict[str, Any]) -> None:
    validate_usg_connection_settings(settings)


def _base_url(settings: dict[str, Any]) -> str:
    scheme = "http" if settings.get("verify_ssl") is False else "https"
    return f"{scheme}://{settings['host']}:{settings['port']}/restconf/data"


def _json_headers(settings: dict[str, Any]) -> dict[str, str]:
    token = base64.b64encode(f"{settings['username']}:{settings['password']}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/yang-data+json",
        "Accept": "application/yang-data+json",
    }


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _request(settings: dict[str, Any], method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    _validate_usg_settings(settings)
    url = _base_url(settings) + path
    data = json.dumps(body).encode() if body else None
    request = urllib.request.Request(url, data=data, headers=_json_headers(settings), method=method)
    try:
        with urllib.request.urlopen(request, context=_ssl_context(settings["verify_ssl"]), timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        body_text = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {error.code} {error.reason}: {body_text[:300]}") from error


def _config_error_result(error: ValueError) -> dict[str, Any]:
    return {
        "success": False,
        "code": "config_error",
        "message": str(error),
        "nextStep": "USG 不需要像 AF 那样先登录，但必须先配置 usg_host、usg_username、usg_password。",
    }


def _preview_result(settings: dict[str, Any], method: str, path: str, body: dict[str, Any], description: str) -> dict[str, Any]:
    return {
        "preview": True,
        "description": description,
        "method": method,
        "url": _base_url(settings) + path,
        "body": body,
        "instruction": "确认无误后，以 confirmed=True 调用对应 apply 工具执行变更。",
    }


def _whitelist_check_or_block(
    ip_address: str,
    *,
    asn: int | None = None,
    domain: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any] | None:
    engine = _get_wl_engine()
    result = engine.check(ip_address, asn=asn, domain=domain, tags=tags)
    if not result.hit:
        return None
    if result.action == "block":
        return {
            "success": False,
            "error": "WHITELIST_BLOCKED",
            "message": f"IP {ip_address} 命中白名单 {result.layer}，已拒绝封禁操作",
            "detail": result.to_dict(),
        }
    return None


def _shared_whitelist_check_or_block(ip_address: str, whitelist_file: str | None = None) -> dict[str, Any] | None:
    shared_whitelist = check_whitelist([ip_address], whitelist_file=whitelist_file)
    if shared_whitelist["allowed"]:
        return None
    return {
        "success": False,
        "error": "WHITELIST_BLOCKED",
        "message": "命中统一白名单，已阻断执行",
        "detail": shared_whitelist,
    }


def _confirmation_block(
    *,
    action: str,
    confirmed: bool,
    confirm_mode: str | None,
    target_count: int = 1,
) -> dict[str, Any] | None:
    confirmation = check_confirmation(
        action,
        confirm=confirmed,
        confirm_mode=confirm_mode,
        target_count=target_count,
    )
    if confirmation["allowed"]:
        return None
    return {
        "success": False,
        "error": "CONFIRMATION_REQUIRED",
        "message": confirmation["reason"] or "需要人工确认",
        "detail": confirmation,
    }


def _extract_blacklist_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    for value in payload.values():
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _extract_blacklist_items(value)
            if nested:
                return nested
    return []


def _blacklist_contains_ip(payload: dict[str, Any], ip_address: str) -> bool:
    items = _extract_blacklist_items(payload)
    return any(item.get("ip") == ip_address for item in items)


def register_usg_tools(mcp: Any) -> None:
    @mcp.tool(name="usg_connection_status", description="查看当前 USG6000F 连接配置状态，不回显明文密码。")
    def usg_connection_status(
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_verify_ssl: bool | str | None = None,
    ) -> dict[str, Any]:
        settings = _resolve_usg_settings(
            usg_host=usg_host,
            usg_port=usg_port,
            usg_username=usg_username,
            usg_verify_ssl=usg_verify_ssl,
        )
        return {
            "success": True,
            "host": settings["host"],
            "port": settings["port"],
            "username": settings["username"],
            "passwordConfigured": bool(_resolve_usg_settings(usg_password=None)["password"]),
            "verifySsl": settings["verify_ssl"],
            "authMode": "basic-auth-per-request",
            "loginRequired": False,
            "message": "USG 通过 RESTCONF Basic Auth 按请求鉴权，不像 AF 那样维护单独登录会话。",
            "whitelistAutoLoaded": bool(_WL_AUTOLOAD_PATH),
            "whitelistPath": _WL_AUTOLOAD_PATH,
            "sharedWhitelistFile": resolve_whitelist_file(),
            "sharedConfirmMode": resolve_confirm_mode(),
        }

    @mcp.tool(name="usg_get_blacklist", description="查询 USG6000F 当前黑名单列表，可按 IP 过滤。")
    def usg_get_blacklist(
        ip_address: str | None = None,
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_password: str | None = None,
        usg_verify_ssl: bool | str | None = None,
    ) -> dict[str, Any]:
        try:
            settings = _resolve_usg_settings(
                usg_host=usg_host,
                usg_port=usg_port,
                usg_username=usg_username,
                usg_password=usg_password,
                usg_verify_ssl=usg_verify_ssl,
            )
            _validate_usg_settings(settings)
            data = _request(settings, "GET", "/huawei-blacklist:blacklist/blacklist-items/blacklist-item")
            items = _extract_blacklist_items(data)
            if ip_address:
                items = [item for item in items if item.get("ip") == ip_address]
            return {"success": True, "count": len(items), "items": items, "raw": data}
        except ValueError as error:
            return _config_error_result(error)
        except Exception as error:
            return {"success": False, "message": str(error)}

    @mcp.tool(name="usg_preview_blacklist_add", description="预览向 USG6000F 黑名单添加 IP 的标准化处置指令，不实际下发。")
    def usg_preview_blacklist_add(
        ip_address: str,
        expire_time: int = 0,
        description: str | None = None,
        asn: int | None = None,
        domain: str | None = None,
        asset_tags: list[str] | None = None,
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_password: str | None = None,
        usg_verify_ssl: bool | str | None = None,
        whitelist_file: str | None = None,
    ) -> dict[str, Any]:
        settings = _resolve_usg_settings(
            usg_host=usg_host,
            usg_port=usg_port,
            usg_username=usg_username,
            usg_password=usg_password,
            usg_verify_ssl=usg_verify_ssl,
        )
        try:
            _validate_usg_settings(settings)
        except ValueError as error:
            return _config_error_result(error)
        shared_block = _shared_whitelist_check_or_block(ip_address, whitelist_file=whitelist_file)
        if shared_block:
            return shared_block
        blocked = _whitelist_check_or_block(ip_address, asn=asn, domain=domain, tags=asset_tags)
        if blocked:
            return blocked
        item: dict[str, Any] = {"ip": ip_address}
        if expire_time:
            item["expire-time"] = expire_time
        if description:
            item["description"] = description
        result = _preview_result(
            settings,
            "POST",
            "/huawei-blacklist:blacklist/blacklist-items/blacklist-item",
            {"huawei-blacklist:blacklist-item": [item]},
            f"添加 USG 黑名单 IP [{ip_address}]，有效期：{expire_time or '永久'}",
        )
        result["shared_whitelist_check"] = check_whitelist([ip_address], whitelist_file=whitelist_file)
        result["whitelist_check"] = _get_wl_engine().check(ip_address, asn=asn, domain=domain, tags=asset_tags).to_dict()
        result["executeDevice"] = settings["host"]
        return result

    @mcp.tool(name="usg_apply_blacklist_add", description="向 USG6000F 实际下发黑名单封禁，需先预览并传 confirmed=true。")
    def usg_apply_blacklist_add(
        ip_address: str,
        expire_time: int = 0,
        description: str | None = None,
        asn: int | None = None,
        domain: str | None = None,
        asset_tags: list[str] | None = None,
        confirmed: bool = False,
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_password: str | None = None,
        usg_verify_ssl: bool | str | None = None,
        confirm_mode: str | None = None,
        whitelist_file: str | None = None,
    ) -> dict[str, Any]:
        confirmation_block = _confirmation_block(
            action="usg_apply_blacklist_add",
            confirmed=confirmed,
            confirm_mode=confirm_mode,
            target_count=1,
        )
        if confirmation_block:
            return confirmation_block
        shared_block = _shared_whitelist_check_or_block(ip_address, whitelist_file=whitelist_file)
        if shared_block:
            return shared_block
        blocked = _whitelist_check_or_block(ip_address, asn=asn, domain=domain, tags=asset_tags)
        if blocked:
            return blocked
        try:
            settings = _resolve_usg_settings(
                usg_host=usg_host,
                usg_port=usg_port,
                usg_username=usg_username,
                usg_password=usg_password,
                usg_verify_ssl=usg_verify_ssl,
            )
            _validate_usg_settings(settings)
            try:
                pre_state = _request(settings, "GET", "/huawei-blacklist:blacklist/blacklist-items/blacklist-item")
            except Exception:
                pre_state = {"_note": "快照获取失败，设备不可达；仍继续执行"}

            item: dict[str, Any] = {"ip": ip_address}
            if expire_time:
                item["expire-time"] = expire_time
            if description:
                item["description"] = description
            payload = {"huawei-blacklist:blacklist-item": [item]}
            try:
                result = _request(settings, "POST", "/huawei-blacklist:blacklist/blacklist-items/blacklist-item", payload)
                apply_status = "applied"
                error_message = None
            except Exception as error:
                result = {"error": str(error)}
                apply_status = "failed"
                error_message = str(error)

            post_state = None
            execution_check = None
            if apply_status == "applied":
                try:
                    post_state = _request(settings, "GET", "/huawei-blacklist:blacklist/blacklist-items/blacklist-item")
                    execution_check = {
                        "success": True,
                        "checkedBy": "usg_get_blacklist",
                        "targetPresent": _blacklist_contains_ip(post_state, ip_address),
                    }
                except Exception as error:
                    execution_check = {"success": False, "message": str(error)}

            action_id = _snap.new_action_id()
            shared_whitelist_check = check_whitelist([ip_address], whitelist_file=whitelist_file)
            whitelist_check = _get_wl_engine().check(ip_address, asn=asn, domain=domain, tags=asset_tags).to_dict()
            judge_id = description[5:].strip() if description and description.startswith("SOAR-") else None
            _snap.save({
                "action_id": action_id,
                "created_at": _snap.now_iso(),
                "action_type": "block",
                "ip": ip_address,
                "expire_time": expire_time,
                "description": description,
                "judge_id": judge_id or None,
                "asset_tags": asset_tags or [],
                "pre_state": pre_state,
                "post_state": post_state,
                "vendor_response": result,
                "shared_whitelist_check": shared_whitelist_check,
                "whitelist_check": whitelist_check,
                "status": apply_status,
                "error": error_message,
            })
            response = {
                "success": apply_status == "applied",
                "action_id": action_id,
                "result": result,
                "executionCheck": execution_check,
                "shared_whitelist_check": shared_whitelist_check,
                "whitelist_check": whitelist_check,
                "unblock_hint": f"如需回滚本次封禁，请调用 usg_preview_blacklist_unblock(action_id='{action_id}')",
            }
            append_audit_log("usg_apply_blacklist_add", {"success": response["success"], "ip": ip_address, "result": response})
            return response
        except ValueError as error:
            return _config_error_result(error)
        except Exception as error:
            return {"success": False, "message": str(error)}

    @mcp.tool(name="usg_whitelist_check", description="对指定 IP 执行 USG 五层白名单校验。")
    def usg_whitelist_check(
        ip_address: str,
        asn: int | None = None,
        domain: str | None = None,
        asset_tags: list[str] | None = None,
        whitelist_file: str | None = None,
    ) -> dict[str, Any]:
        result = _get_wl_engine().check(ip_address, asn=asn, domain=domain, tags=asset_tags)
        return {
            "success": True,
            "sharedWhitelist": check_whitelist([ip_address], whitelist_file=whitelist_file),
            "usgWhitelist": result.to_dict(),
        }

    @mcp.tool(name="usg_whitelist_reload", description="热加载或重新加载 USG YAML 白名单。")
    def usg_whitelist_reload(path: str | None = None) -> dict[str, Any]:
        engine = _get_wl_engine()
        try:
            if path:
                engine.load(path)
            else:
                engine.reload()
            return {"success": True, "summary": engine.summary()}
        except Exception as error:
            return {"success": False, "message": str(error)}

    @mcp.tool(name="usg_whitelist_list", description="查询当前加载的全部 USG 白名单条目。")
    def usg_whitelist_list() -> dict[str, Any]:
        engine = _get_wl_engine()
        if not engine.is_loaded():
            return {"success": False, "message": "白名单未加载"}
        return {"success": True, "items": engine.list_all()}

    @mcp.tool(name="usg_whitelist_stats", description="查看 USG 白名单引擎状态与命中统计。")
    def usg_whitelist_stats() -> dict[str, Any]:
        return {"success": True, "summary": _get_wl_engine().summary()}

    @mcp.tool(name="usg_preview_blacklist_unblock", description="按 action_id 预览 USG 黑名单解封操作。")
    def usg_preview_blacklist_unblock(action_id: str) -> dict[str, Any]:
        record = _snap.load(action_id)
        if record is None:
            return {"success": False, "message": f"找不到 action_id={action_id}"}
        if record.get("action_type") != "block":
            return {"success": False, "message": f"action_id={action_id} 类型不是 block，无法解封"}
        if record.get("status") == "unblocked":
            return {"success": False, "message": f"action_id={action_id} 已于 {record.get('unblocked_at')} 解封"}
        ip_address = record["ip"]
        settings = _resolve_usg_settings()
        try:
            _validate_usg_settings(settings)
        except ValueError as error:
            return _config_error_result(error)
        preview = _preview_result(settings, "DELETE", f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip_address}", {}, f"解封 USG 黑名单 IP [{ip_address}]")
        preview["originalAction"] = {
            "action_id": action_id,
            "ip": ip_address,
            "blocked_at": record.get("created_at"),
            "description": record.get("description"),
        }
        return preview

    @mcp.tool(name="usg_apply_blacklist_unblock", description="按 action_id 实际执行 USG 黑名单解封，需 confirmed=true。")
    def usg_apply_blacklist_unblock(
        action_id: str,
        reason: str = "",
        confirmed: bool = False,
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_password: str | None = None,
        usg_verify_ssl: bool | str | None = None,
        confirm_mode: str | None = None,
    ) -> dict[str, Any]:
        confirmation_block = _confirmation_block(
            action="usg_apply_blacklist_unblock",
            confirmed=confirmed,
            confirm_mode=confirm_mode,
            target_count=1,
        )
        if confirmation_block:
            return confirmation_block
        record = _snap.load(action_id)
        if record is None:
            return {"success": False, "message": f"找不到 action_id={action_id}"}
        ip_address = record["ip"]
        settings = _resolve_usg_settings(
            usg_host=usg_host,
            usg_port=usg_port,
            usg_username=usg_username,
            usg_password=usg_password,
            usg_verify_ssl=usg_verify_ssl,
        )
        try:
            _validate_usg_settings(settings)
        except ValueError as error:
            return _config_error_result(error)
        try:
            result = _request(settings, "DELETE", f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip_address}")
            ok = True
        except Exception as error:
            result = {"error": str(error)}
            ok = False
        _snap.update(action_id, {
            "status": "unblocked" if ok else "unblock_failed",
            "unblocked_at": _snap.now_iso(),
            "unblock_reason": reason,
            "unblock_result": result,
        })
        unblock_action_id = _snap.new_action_id()
        _snap.save({
            "action_id": unblock_action_id,
            "created_at": _snap.now_iso(),
            "action_type": "unblock",
            "ip": ip_address,
            "target_action_id": action_id,
            "reason": reason,
            "vendor_response": result,
            "status": "applied" if ok else "failed",
        })
        response = {
            "success": ok,
            "unblock_action_id": unblock_action_id,
            "target_action_id": action_id,
            "ip": ip_address,
            "result": result,
        }
        append_audit_log("usg_apply_blacklist_unblock", {"success": ok, "action_id": action_id, "ip": ip_address, "result": response})
        return response

    @mcp.tool(name="usg_list_actions", description="查询最近的 USG 处置动作记录。")
    def usg_list_actions(limit: int = 20, ip: str | None = None, status: str | None = None) -> dict[str, Any]:
        items = _snap.list_recent(limit=limit, ip=ip, status=status)
        compact = [
            {key: value for key, value in item.items() if key not in {"pre_state", "post_state", "vendor_response", "unblock_result"}}
            for item in items
        ]
        return {"success": True, "count": len(compact), "items": compact}

    @mcp.tool(name="usg_get_action_detail", description="查询单个 USG 处置动作的完整详情。")
    def usg_get_action_detail(action_id: str) -> dict[str, Any]:
        record = _snap.load(action_id)
        if record is None:
            return {"success": False, "message": f"找不到 action_id={action_id}"}
        return {"success": True, "record": record}

    @mcp.tool(name="usg_unblock_recent", description="批量回滚最近 N 分钟内的 USG 自动封禁。")
    def usg_unblock_recent(
        window_min: int = 30,
        reason: str = "emergency_rollback",
        confirmed: bool = False,
        usg_host: str | None = None,
        usg_port: str | None = None,
        usg_username: str | None = None,
        usg_password: str | None = None,
        usg_verify_ssl: bool | str | None = None,
        confirm_mode: str | None = None,
    ) -> dict[str, Any]:
        confirmation_block = _confirmation_block(
            action="usg_unblock_recent",
            confirmed=confirmed,
            confirm_mode=confirm_mode,
            target_count=max(window_min, 1),
        )
        if confirmation_block:
            return confirmation_block
        cutoff = datetime.datetime.now() - datetime.timedelta(minutes=window_min)
        settings = _resolve_usg_settings(
            usg_host=usg_host,
            usg_port=usg_port,
            usg_username=usg_username,
            usg_password=usg_password,
            usg_verify_ssl=usg_verify_ssl,
        )
        try:
            _validate_usg_settings(settings)
        except ValueError as error:
            return _config_error_result(error)
        targets = []
        for action in _snap.list_recent(limit=500, status="applied"):
            if action.get("action_type") != "block":
                continue
            try:
                created_at = datetime.datetime.fromisoformat(action["created_at"])
                if created_at.tzinfo is not None:
                    created_at = created_at.replace(tzinfo=None)
            except Exception:
                continue
            if created_at >= cutoff:
                targets.append(action)

        results = []
        for action in targets:
            ip_address = action["ip"]
            try:
                _request(settings, "DELETE", f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip_address}")
                ok = True
                error_message = None
            except Exception as error:
                ok = False
                error_message = str(error)
            _snap.update(action["action_id"], {
                "status": "unblocked" if ok else "unblock_failed",
                "unblocked_at": _snap.now_iso(),
                "unblock_reason": reason,
                "unblock_result": {"ok": True} if ok else {"error": error_message},
            })
            results.append({"action_id": action["action_id"], "ip": ip_address, "ok": ok, "error": error_message})

        success_count = sum(1 for item in results if item["ok"])
        response = {
            "success": True,
            "window_min": window_min,
            "total_targets": len(results),
            "successCount": success_count,
            "failedCount": len(results) - success_count,
            "items": results,
        }
        append_audit_log("usg_unblock_recent", {"success": True, "window_min": window_min, "result": response})
        return response