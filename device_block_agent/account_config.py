import os
from typing import Any


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _parse_bool(value: str | bool | None, default: bool = True) -> bool:
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


def get_account_defaults() -> dict[str, Any]:
    return {
        "host": _env("AF_HOST"),
        "namespace": _env("AF_NAMESPACE", "public") or "public",
        "username": _env("AF_USERNAME"),
        "passwordConfigured": bool(_env("AF_PASSWORD")),
        "verifyTls": _parse_bool(_env("AF_VERIFY_TLS", "true"), True),
    }


def resolve_connection_settings(
    *,
    host: str | None = None,
    namespace: str | None = None,
    verify_tls: bool | None = None,
) -> dict[str, Any]:
    resolved_host = host.strip() if isinstance(host, str) else ""
    resolved_namespace = namespace.strip() if isinstance(namespace, str) else ""
    return {
        "host": resolved_host or _env("AF_HOST"),
        "namespace": resolved_namespace or _env("AF_NAMESPACE", "public") or "public",
        "verify_tls": _parse_bool(verify_tls, _parse_bool(_env("AF_VERIFY_TLS", "true"), True)),
    }


def resolve_login_settings(
    *,
    host: str | None = None,
    namespace: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool | None = None,
) -> dict[str, Any]:
    connection = resolve_connection_settings(host=host, namespace=namespace, verify_tls=verify_tls)
    resolved_username = username.strip() if isinstance(username, str) else ""
    resolved_password = password if isinstance(password, str) else None
    return {
        **connection,
        "username": resolved_username or _env("AF_USERNAME"),
        "password": resolved_password if resolved_password not in (None, "") else _env("AF_PASSWORD"),
    }


def validate_connection_settings(settings: dict[str, Any]) -> None:
    if not settings.get("host"):
        raise ValueError("缺少 host，请在工具参数中传入 host 或配置 AF_HOST")


def validate_login_settings(settings: dict[str, Any]) -> None:
    validate_connection_settings(settings)
    if not settings.get("username"):
        raise ValueError("缺少 username，请在工具参数中传入 username 或配置 AF_USERNAME")
    if not settings.get("password"):
        raise ValueError("缺少 password，请在工具参数中传入 password 或配置 AF_PASSWORD")