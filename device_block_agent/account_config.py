import json
import os
from typing import Any

from .app_config import DEFAULT_USG_ACCOUNT_FILE


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


def resolve_usg_account_file() -> str:
    return (os.getenv("USG_ACCOUNT_FILE") or DEFAULT_USG_ACCOUNT_FILE).strip()


def _load_persisted_usg_account() -> dict[str, Any]:
    file_path = resolve_usg_account_file()
    if not file_path or not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def persist_usg_connection_settings(
    *,
    host: str,
    port: str,
    username: str,
    password: str,
    verify_ssl: bool,
) -> dict[str, Any]:
    file_path = resolve_usg_account_file()
    if not file_path:
        raise ValueError("未配置 USG 账号持久化文件路径")
    directory = os.path.dirname(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = {
        "host": host.strip(),
        "port": port.strip() or "443",
        "username": username.strip(),
        "password": password,
        "verifySsl": bool(verify_ssl),
    }
    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return payload


def clear_persisted_usg_connection_settings() -> dict[str, Any]:
    file_path = resolve_usg_account_file()
    existed = bool(file_path and os.path.exists(file_path))
    if existed:
        os.remove(file_path)
    return {
        "accountFile": file_path,
        "existed": existed,
        "cleared": True,
    }


def resolve_usg_connection_settings(
    *,
    host: str | None = None,
    port: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_ssl: bool | str | None = None,
) -> dict[str, Any]:
    persisted = _load_persisted_usg_account()
    resolved_host = host.strip() if isinstance(host, str) else ""
    resolved_port = port.strip() if isinstance(port, str) else ""
    resolved_username = username.strip() if isinstance(username, str) else ""
    resolved_password = password if isinstance(password, str) else None
    env_host = _env("USG_HOST")
    env_port = _env("USG_PORT", "443") or "443"
    env_username = _env("USG_USERNAME")
    env_password = _env("USG_PASSWORD")
    has_explicit = any([resolved_host, resolved_port, resolved_username, resolved_password not in (None, "")])
    has_persisted = bool(persisted)
    has_environment = any([env_host, env_username, env_password])
    return {
        "host": resolved_host or str(persisted.get("host") or "").strip() or env_host,
        "port": resolved_port or str(persisted.get("port") or "").strip() or env_port,
        "username": resolved_username or str(persisted.get("username") or "").strip() or env_username,
        "password": resolved_password if resolved_password not in (None, "") else (str(persisted.get("password") or "") or env_password),
        "verify_ssl": _parse_bool(
            verify_ssl,
            _parse_bool(persisted.get("verifySsl"), _parse_bool(_env("USG_VERIFY_SSL", "false"), False)),
        ),
        "source": "explicit" if has_explicit else ("persisted" if has_persisted else ("environment" if has_environment else "none")),
        "accountFile": resolve_usg_account_file(),
    }


def validate_usg_connection_settings(settings: dict[str, Any]) -> None:
    if not settings.get("host"):
        raise ValueError("缺少 usg_host，请在工具参数中传入 usg_host、在聊天中调用 set_usg_connection，或配置 USG_HOST")
    if not settings.get("username"):
        raise ValueError("缺少 usg_username，请在工具参数中传入 usg_username、在聊天中调用 set_usg_connection，或配置 USG_USERNAME")
    if not settings.get("password"):
        raise ValueError("缺少 usg_password，请在工具参数中传入 usg_password、在聊天中调用 set_usg_connection，或配置 USG_PASSWORD")


def get_account_defaults() -> dict[str, Any]:
    usg_settings = resolve_usg_connection_settings()
    return {
        "host": _env("AF_HOST"),
        "namespace": _env("AF_NAMESPACE", "public") or "public",
        "username": _env("AF_USERNAME"),
        "passwordConfigured": bool(_env("AF_PASSWORD")),
        "verifyTls": _parse_bool(_env("AF_VERIFY_TLS", "true"), True),
        "af": {
            "host": _env("AF_HOST"),
            "namespace": _env("AF_NAMESPACE", "public") or "public",
            "username": _env("AF_USERNAME"),
            "passwordConfigured": bool(_env("AF_PASSWORD")),
            "verifyTls": _parse_bool(_env("AF_VERIFY_TLS", "true"), True),
        },
        "usg": {
            "host": usg_settings["host"],
            "port": usg_settings["port"],
            "username": usg_settings["username"],
            "passwordConfigured": bool(usg_settings["password"]),
            "verifySsl": usg_settings["verify_ssl"],
            "authMode": "basic-auth-per-request",
            "loginRequired": False,
            "source": usg_settings["source"],
            "accountFile": usg_settings["accountFile"],
        },
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