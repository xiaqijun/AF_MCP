from typing import Any

from .account_config import get_account_defaults, resolve_connection_settings, resolve_login_settings, validate_connection_settings, validate_login_settings
from .af_client import AFClientError, keepalive, login, logout
from .audit_log import append_audit_log


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