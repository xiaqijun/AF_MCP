import os
from typing import Any

from .account_config import clear_persisted_usg_connection_settings, get_account_defaults, persist_usg_connection_settings, resolve_connection_settings, resolve_login_settings, resolve_usg_account_file, resolve_usg_connection_settings, validate_connection_settings, validate_login_settings, validate_usg_connection_settings
from .af_client import AFClientError, keepalive, login, logout
from .app_config import DEFAULT_CONFIRM_MODE, DEFAULT_WHITELIST_FILE
from .audit_log import append_audit_log
from .risk_controls import GuardrailError, check_whitelist, describe_guardrails, get_confirm_mode_label, get_whitelist_rules, persist_confirm_mode, persist_whitelist_file, resolve_confirm_mode, resolve_confirm_mode_file, resolve_whitelist_config_file, resolve_whitelist_file


def _auth_error_result(action: str, error: AFClientError, context: dict[str, Any]) -> dict[str, Any]:
    append_audit_log(action, {**context, "success": False, "message": str(error), "code": error.code})
    return {
        "success": False,
        "message": str(error),
        "code": error.code,
        "data": error.data,
    }


def _config_error_result(action: str, error: ValueError, context: dict[str, Any]) -> dict[str, Any]:
    append_audit_log(action, {**context, "success": False, "message": str(error), "code": "config_error"})
    return {
        "success": False,
        "message": str(error),
        "code": "config_error",
        "data": None,
    }


def _guardrail_error_result(action: str, error: GuardrailError, context: dict[str, Any]) -> dict[str, Any]:
    append_audit_log(action, {**context, "success": False, "message": str(error), "code": "guardrail_error"})
    return {
        "success": False,
        "message": str(error),
        "code": "guardrail_error",
        "data": None,
    }


def register_auth_tools(mcp: Any) -> None:
    @mcp.tool(
        name="auth_login",
        description="登录 AF 设备并建立当前 host/namespace 的本地会话。",
    )
    def auth_login(
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_login_settings(
                host=host,
                namespace=namespace,
                username=username,
                password=password,
                verify_tls=verify_tls,
            )
            validate_login_settings(settings)
            result = login(
                host=settings["host"],
                namespace=settings["namespace"],
                username=settings["username"],
                password=settings["password"],
                verify_tls=settings["verify_tls"],
            )
            append_audit_log(
                "auth_login",
                {"host": settings["host"], "namespace": settings["namespace"], "username": settings["username"], "success": True, "result": result},
            )
            return result
        except ValueError as error:
            return _config_error_result("auth_login", error, {"host": host, "namespace": namespace, "username": username})
        except AFClientError as error:
            return _auth_error_result("auth_login", error, {"host": host, "namespace": namespace, "username": username})

    @mcp.tool(
        name="auth_keepalive",
        description="维持当前 host/namespace 的登录 token 不超时。",
    )
    def auth_keepalive(
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result = keepalive(host=settings["host"], namespace=settings["namespace"], verify_tls=settings["verify_tls"])
            append_audit_log("auth_keepalive", {"host": settings["host"], "namespace": settings["namespace"], "success": True, "result": result})
            return result
        except ValueError as error:
            return _config_error_result("auth_keepalive", error, {"host": host, "namespace": namespace})
        except AFClientError as error:
            return _auth_error_result("auth_keepalive", error, {"host": host, "namespace": namespace})

    @mcp.tool(
        name="auth_logout",
        description="注销当前 host/namespace 的本地会话与 AF 登录状态。",
    )
    def auth_logout(
        host: str | None = None,
        namespace: str | None = None,
        verify_tls: bool | None = None,
    ) -> dict[str, Any]:
        try:
            settings = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
            validate_connection_settings(settings)
            result = logout(host=settings["host"], namespace=settings["namespace"], verify_tls=settings["verify_tls"])
            append_audit_log("auth_logout", {"host": settings["host"], "namespace": settings["namespace"], "success": True, "result": result})
            return result
        except ValueError as error:
            return _config_error_result("auth_logout", error, {"host": host, "namespace": namespace})
        except AFClientError as error:
            return _auth_error_result("auth_logout", error, {"host": host, "namespace": namespace})

    @mcp.tool(
        name="account_config_status",
        description="返回当前账号默认配置状态，不回显明文密码。",
    )
    def account_config_status() -> dict[str, Any]:
        return get_account_defaults()

    @mcp.tool(
        name="set_usg_connection",
        description="通过聊天输入并持久化 USG6000F 连接账号；保存连接信息后，调用真实设备 API 前仍需先执行 usg_login。",
    )
    def set_usg_connection(
        usg_host: str,
        usg_username: str,
        usg_password: str,
        usg_port: str = "443",
        usg_verify_ssl: bool = False,
    ) -> dict[str, Any]:
        try:
            settings = resolve_usg_connection_settings(
                host=usg_host,
                port=usg_port,
                username=usg_username,
                password=usg_password,
                verify_ssl=usg_verify_ssl,
            )
            validate_usg_connection_settings(settings)
            os.environ["USG_HOST"] = settings["host"]
            os.environ["USG_PORT"] = settings["port"]
            os.environ["USG_USERNAME"] = settings["username"]
            os.environ["USG_PASSWORD"] = settings["password"]
            os.environ["USG_VERIFY_SSL"] = "true" if settings["verify_ssl"] else "false"
            persistence = persist_usg_connection_settings(
                host=settings["host"],
                port=settings["port"],
                username=settings["username"],
                password=settings["password"],
                verify_ssl=settings["verify_ssl"],
            )
            result = {
                "success": True,
                "host": settings["host"],
                "port": settings["port"],
                "username": settings["username"],
                "passwordConfigured": True,
                "verifySsl": settings["verify_ssl"],
                "authMode": "basic-auth-per-request",
                "loginRequired": True,
                "accountFile": resolve_usg_account_file(),
                "persisted": True,
                "message": "USG 连接账号已保存；调用真实设备 API 前，请先执行 usg_login 建立本地登录态。",
            }
            append_audit_log("set_usg_connection", {"success": True, "host": settings["host"], "username": settings["username"], "persisted": persistence, "result": result})
            return result
        except ValueError as error:
            return _config_error_result("set_usg_connection", error, {"usg_host": usg_host, "usg_username": usg_username, "usg_port": usg_port})

    @mcp.tool(
        name="clear_usg_connection",
        description="清空通过聊天保存的 USG 连接账号，后续需重新调用 set_usg_connection。",
    )
    def clear_usg_connection() -> dict[str, Any]:
        cleared = clear_persisted_usg_connection_settings()
        for env_name in ("USG_HOST", "USG_PORT", "USG_USERNAME", "USG_PASSWORD", "USG_VERIFY_SSL"):
            os.environ.pop(env_name, None)
        result = {
            "success": True,
            "cleared": True,
            "existed": cleared["existed"],
            "accountFile": cleared["accountFile"],
            "message": "USG 聊天配置已清空，后续如需执行 USG 工具，请重新调用 set_usg_connection。",
        }
        append_audit_log("clear_usg_connection", {"success": True, "result": result})
        return result

    @mcp.tool(
        name="get_confirm_mode",
        description="返回当前有效的确认模式，用于判断高风险写操作按 手动 还是 自动 处理。",
    )
    def get_confirm_mode() -> dict[str, Any]:
        mode = resolve_confirm_mode()
        return {
            "success": True,
            "confirmMode": mode,
            "confirmModeLabel": get_confirm_mode_label(mode),
            "source": "persisted" if os.path.exists(resolve_confirm_mode_file()) else ("environment" if os.getenv("CONFIRM_MODE") else "default"),
            "confirmModeFile": resolve_confirm_mode_file(),
            "persisted": os.path.exists(resolve_confirm_mode_file()),
            "defaultConfirmMode": DEFAULT_CONFIRM_MODE,
            "defaultConfirmModeLabel": get_confirm_mode_label(DEFAULT_CONFIRM_MODE),
        }

    @mcp.tool(
        name="set_confirm_mode",
        description="设置当前进程内全局确认模式，可切换为 手动 或 自动。",
    )
    def set_confirm_mode(mode: str) -> dict[str, Any]:
        try:
            normalized_mode = resolve_confirm_mode(mode)
            os.environ["CONFIRM_MODE"] = normalized_mode
            persistence = persist_confirm_mode(normalized_mode)
            result = {
                "success": True,
                "confirmMode": normalized_mode,
                "confirmModeLabel": get_confirm_mode_label(normalized_mode),
                "persisted": True,
                "confirmModeFile": resolve_confirm_mode_file(),
                "updatedAt": persistence["updatedAt"],
                "message": f"确认模式已切换为 {get_confirm_mode_label(normalized_mode)}",
            }
            append_audit_log("set_confirm_mode", {"success": True, "confirmMode": normalized_mode, "result": result})
            return result
        except GuardrailError as error:
            return _guardrail_error_result("set_confirm_mode", error, {"mode": mode})

    @mcp.tool(
        name="get_whitelist_config",
        description="返回当前有效的白名单文件配置与规则统计。",
    )
    def get_whitelist_config() -> dict[str, Any]:
        whitelist_file = resolve_whitelist_file()
        guardrails = describe_guardrails()
        return {
            "success": True,
            "whitelistFile": whitelist_file,
            "source": "persisted" if os.path.exists(resolve_whitelist_config_file()) else ("environment" if os.getenv("WHITELIST_FILE") else "default"),
            "whitelistConfigFile": resolve_whitelist_config_file(),
            "persisted": os.path.exists(resolve_whitelist_config_file()),
            "exists": guardrails["whitelistFileExists"],
            "defaultWhitelistFile": DEFAULT_WHITELIST_FILE,
            "ruleCount": guardrails["whitelistRuleCount"],
        }

    @mcp.tool(
        name="get_whitelist_rules",
        description="返回当前生效白名单文件的完整规则配置。",
    )
    def get_whitelist_rules_tool(whitelist_file: str | None = None) -> dict[str, Any]:
        try:
            result = get_whitelist_rules(whitelist_file)
            return {
                "success": True,
                "whitelistFile": result["whitelistFile"],
                "exists": result["exists"],
                "ruleCount": result["ruleCount"],
                "rules": result["rules"],
            }
        except GuardrailError as error:
            return _guardrail_error_result("get_whitelist_rules", error, {"whitelist_file": whitelist_file})

    @mcp.tool(
        name="set_whitelist_file",
        description="设置当前全局白名单文件路径，并持久化到本地配置文件。",
    )
    def set_whitelist_file(whitelist_file: str) -> dict[str, Any]:
        try:
            normalized_file = whitelist_file.strip()
            if not normalized_file:
                raise GuardrailError("whitelist_file 不能为空")
            os.environ["WHITELIST_FILE"] = normalized_file
            persistence = persist_whitelist_file(normalized_file)
            result = {
                "success": True,
                "whitelistFile": normalized_file,
                "persisted": True,
                "exists": os.path.exists(normalized_file),
                "whitelistConfigFile": resolve_whitelist_config_file(),
                "updatedAt": persistence["updatedAt"],
                "message": f"白名单文件已切换为 {normalized_file}",
            }
            append_audit_log("set_whitelist_file", {"success": True, "whitelistFile": normalized_file, "result": result})
            return result
        except GuardrailError as error:
            return _guardrail_error_result("set_whitelist_file", error, {"whitelist_file": whitelist_file})

    @mcp.tool(
        name="check_whitelist_targets",
        description="检查一组目标是否命中当前白名单规则。",
    )
    def check_whitelist_targets(targets: list[str], whitelist_file: str | None = None) -> dict[str, Any]:
        try:
            result = check_whitelist(targets, whitelist_file=whitelist_file)
            return {
                "success": True,
                "allowed": result["allowed"],
                "matches": result["matches"],
                "checkedTargets": result["checkedTargets"],
                "whitelistFile": result["whitelistFile"],
            }
        except GuardrailError as error:
            return _guardrail_error_result("check_whitelist_targets", error, {"targets": targets, "whitelist_file": whitelist_file})