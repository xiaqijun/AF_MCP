import json
import os
import ssl
import threading
import time
from dataclasses import asdict
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_NAMESPACE = "public"
DEFAULT_SESSION_FILE = "data/sessions.json"
DEFAULT_SESSION_TIMEOUT_SECONDS = 600
DEFAULT_SESSION_REFRESH_WINDOW_SECONDS = 120


class AFClientError(Exception):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


@dataclass(slots=True)
class AFSession:
    host: str
    namespace: str
    username: str
    token: str
    cftoken: str | None
    role: str | None
    auth_result: Any = None
    passwd_status: Any = None
    last_active_at: float | None = None
    expires_at: float | None = None


class AFSessionStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str], AFSession] = {}
        self._session_file = os.getenv("SESSION_FILE", DEFAULT_SESSION_FILE).strip() or DEFAULT_SESSION_FILE
        self._load()

    def _load(self) -> None:
        if not self._session_file or not os.path.exists(self._session_file):
            return
        try:
            with open(self._session_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, list):
            return
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                session = AFSession(**item)
            except TypeError:
                continue
            self._sessions[(session.host, session.namespace)] = session

    def _save(self) -> None:
        if not self._session_file:
            return
        directory = os.path.dirname(self._session_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = [asdict(session) for session in self._sessions.values()]
        with open(self._session_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)

    def set(self, session: AFSession) -> None:
        with self._lock:
            self._sessions[(session.host, session.namespace)] = session
            self._save()

    def touch(self, host: str, namespace: str) -> AFSession | None:
        with self._lock:
            session = self._sessions.get((host, namespace))
            if session is None:
                return None
            now = time.time()
            session.last_active_at = now
            session.expires_at = now + get_session_timeout_seconds()
            self._save()
            return session

    def get(self, host: str, namespace: str) -> AFSession | None:
        with self._lock:
            return self._sessions.get((host, namespace))

    def pop(self, host: str, namespace: str) -> AFSession | None:
        with self._lock:
            session = self._sessions.pop((host, namespace), None)
            self._save()
            return session

    def describe(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessionFile": self._session_file,
                "persistedSessionCount": len(self._sessions),
                "persistenceEnabled": bool(self._session_file),
                "sessionKeys": [f"{host}|{namespace}" for host, namespace in sorted(self._sessions.keys())],
            }


session_store = AFSessionStore()


def describe_session_store() -> dict[str, Any]:
    return {
        **session_store.describe(),
        "sessionTimeoutSeconds": get_session_timeout_seconds(),
        "sessionRefreshWindowSeconds": get_session_refresh_window_seconds(),
    }


def get_session_timeout_seconds() -> int:
    raw_value = os.getenv("SESSION_TIMEOUT_SECONDS", str(DEFAULT_SESSION_TIMEOUT_SECONDS)).strip()
    try:
        value = int(raw_value)
    except ValueError as error:
        raise AFClientError("SESSION_TIMEOUT_SECONDS 必须是整数") from error
    return max(60, value)


def get_session_refresh_window_seconds() -> int:
    raw_value = os.getenv("SESSION_REFRESH_WINDOW_SECONDS", str(DEFAULT_SESSION_REFRESH_WINDOW_SECONDS)).strip()
    try:
        value = int(raw_value)
    except ValueError as error:
        raise AFClientError("SESSION_REFRESH_WINDOW_SECONDS 必须是整数") from error
    timeout = get_session_timeout_seconds()
    return max(30, min(value, timeout - 1))


def _mark_session_active(session: AFSession) -> AFSession:
    updated = session_store.touch(session.host, session.namespace)
    return updated or session


def _is_session_expired(session: AFSession) -> bool:
    expires_at = session.expires_at
    if expires_at is None:
        return False
    return time.time() >= expires_at


def _refresh_session_if_needed(session: AFSession, *, verify_tls: bool) -> AFSession:
    expires_at = session.expires_at
    if expires_at is None:
        return _mark_session_active(session)
    remaining_seconds = expires_at - time.time()
    if remaining_seconds > get_session_refresh_window_seconds():
        return session
    _keepalive_session(session, verify_tls=verify_tls)
    refreshed_session = session_store.get(session.host, session.namespace)
    if refreshed_session is None:
        raise AFClientError("会话自动保活后未能继续获取本地会话")
    return refreshed_session


def _keepalive_session(session: AFSession, *, verify_tls: bool) -> dict[str, Any]:
    url = build_url(session.host, session.namespace, "/api/v1/namespaces/@namespace/keepalive")
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result


def normalize_host(host: str) -> str:
    candidate = host.strip().rstrip("/")
    if not candidate:
        raise AFClientError("host 不能为空")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return f"https://{candidate}"


def normalize_namespace(namespace: str | None) -> str:
    if namespace and namespace.strip():
        return namespace.strip()
    return DEFAULT_NAMESPACE


def build_url(host: str, namespace: str, path: str, query: dict[str, Any] | None = None) -> str:
    base = normalize_host(host)
    actual_namespace = normalize_namespace(namespace)
    actual_path = path.replace("@namespace", actual_namespace)
    if query:
        filtered = {key: value for key, value in query.items() if value is not None}
        return f"{base}{actual_path}?{urlencode(filtered, doseq=True)}"
    return f"{base}{actual_path}"


def _build_ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    if verify_tls:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _build_headers(token: str | None = None, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Cookie"] = f"token={token}"
    if extra_headers:
        headers.update(extra_headers)
    return headers


def request_json(
    method: str,
    url: str,
    *,
    payload: Any = None,
    token: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    data: bytes | None = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    request = Request(
        url=url,
        data=data,
        headers=_build_headers(token=token),
        method=method.upper(),
    )

    try:
        with urlopen(request, context=_build_ssl_context(verify_tls), timeout=30) as response:
            body = response.read().decode("utf-8")
    except HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        raise AFClientError(f"AF 接口返回 HTTP {error.code}: {details}") from error
    except URLError as error:
        raise AFClientError(f"AF 连接失败: {error.reason}") from error

    try:
        result = json.loads(body) if body else {}
    except json.JSONDecodeError as error:
        raise AFClientError(f"AF 返回了非 JSON 响应: {body}") from error

    if isinstance(result, dict) and result.get("code") not in (None, 0):
        raise AFClientError(
            result.get("message") or "AF 接口调用失败",
            code=result.get("code"),
            data=result.get("data"),
        )
    if not isinstance(result, dict):
        raise AFClientError("AF 响应格式异常")
    return result


def login(
    host: str,
    namespace: str,
    username: str,
    password: str,
    *,
    verify_tls: bool = True,
) -> dict[str, Any]:
    url = build_url(host, namespace, "/api/v1/namespaces/@namespace/login")
    result = request_json(
        "POST",
        url,
        payload={"name": username, "password": password},
        verify_tls=verify_tls,
    )
    data = result.get("data") or {}
    login_result = data.get("loginResult") or {}
    token = login_result.get("token")
    if not token:
        raise AFClientError("登录成功但未返回 token", data=data)

    session_store.set(
        AFSession(
            host=normalize_host(host),
            namespace=normalize_namespace(namespace),
            username=data.get("name") or username,
            token=token,
            cftoken=data.get("cftoken"),
            role=data.get("role"),
            auth_result=data.get("authResult"),
            passwd_status=data.get("passwdStatus"),
            last_active_at=time.time(),
            expires_at=time.time() + get_session_timeout_seconds(),
        )
    )
    return {
        "token": token,
        "cftoken": data.get("cftoken"),
        "role": data.get("role"),
        "namespace": data.get("namespace") or normalize_namespace(namespace),
        "authResult": data.get("authResult"),
        "passwdStatus": data.get("passwdStatus"),
        "name": data.get("name") or username,
    }


def get_active_session(
    host: str,
    namespace: str,
    *,
    verify_tls: bool = True,
    auto_refresh: bool = False,
    allow_expired: bool = False,
) -> AFSession:
    session = session_store.get(normalize_host(host), normalize_namespace(namespace))
    if session is None:
        raise AFClientError("当前 host/namespace 没有可用登录会话，请先调用 auth_login")
    if _is_session_expired(session):
        if not allow_expired:
            session_store.pop(session.host, session.namespace)
            raise AFClientError("本地会话已过期，请重新调用 auth_login")
        return session
    if auto_refresh:
        return _refresh_session_if_needed(session, verify_tls=verify_tls)
    return session


def keepalive(host: str, namespace: str, *, verify_tls: bool = True) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=False)
    result = _keepalive_session(session, verify_tls=verify_tls)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
    }


def logout(host: str, namespace: str, *, verify_tls: bool = True) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=False, allow_expired=True)
    url = build_url(session.host, session.namespace, "/api/v1/namespaces/@namespace/logout")
    result = request_json(
        "POST",
        url,
        payload={"loginResult": {"token": session.token}},
        token=session.token,
        verify_tls=verify_tls,
    )
    session_store.pop(session.host, session.namespace)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
    }


def _query_params(
    *,
    start: int | None = None,
    length: int | None = None,
    search: str | None = None,
    sortby: str | None = None,
    order: str | None = None,
    creator: str | None = None,
    select: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if creator:
        params["creator"] = creator
    if start is not None:
        params["_start"] = start
    if length is not None:
        params["_length"] = length
    if search:
        params["_search"] = search
    if select:
        params["_select"] = select
    if sortby:
        params["_sortby"] = sortby
    if order:
        params["_order"] = order
    return params


def list_temp_blocks(
    host: str,
    namespace: str,
    *,
    start: int | None = None,
    length: int | None = None,
    search: str | None = None,
    sortby: str | None = None,
    order: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/wrapper/blockip",
        query=_query_params(start=start, length=length, search=search, sortby=sortby, order=order),
    )
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def list_business_blocks(
    host: str,
    namespace: str,
    *,
    creator: str | None = None,
    start: int | None = None,
    length: int | None = None,
    search: str | None = None,
    sortby: str | None = None,
    order: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/bizblockip",
        query=_query_params(
            creator=creator,
            start=start,
            length=length,
            search=search,
            sortby=sortby,
            order=order,
        ),
    )
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def get_block_total_count(host: str, namespace: str, *, verify_tls: bool = True) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(session.host, session.namespace, "/api/v1/namespaces/@namespace/blocktotalcnt")
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def get_block_time(host: str, namespace: str, *, verify_tls: bool = True) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(session.host, session.namespace, "/api/v1/namespaces/@namespace/blockiptime")
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def add_business_blocks(
    host: str,
    namespace: str,
    *,
    src_ips: list[str],
    block_time: str | None = None,
    creator: str | None = None,
    aifw_type: str | None = None,
    override: str | None = None,
    result_items: list[dict[str, Any]] | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    query = {
        "creator": creator,
        "aifwType": aifw_type,
        "override": override,
    }
    payload: dict[str, Any] = {"srcIP": src_ips}
    if block_time:
        payload["blockTime"] = block_time
    if result_items is not None:
        payload["result"] = result_items
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/bizblockip",
        query=query,
    )
    result = request_json("POST", url, payload=payload, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "request": payload,
    }


def delete_temp_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/wrapper/blockip",
        query={"_method": "delete"},
    )
    result = request_json("POST", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }


def delete_business_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    creator: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/bizblockip",
        query={"_method": "delete", "creator": creator},
    )
    result = request_json("POST", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }


def clear_attackers(
    host: str,
    namespace: str,
    *,
    creator: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/blockipclear",
        query={"creator": creator},
    )
    result = request_json("DELETE", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
    }


def clear_temp_blocks(
    host: str,
    namespace: str,
    *,
    creator: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/wrapper/blockipclear",
        query={"creator": creator},
    )
    result = request_json("DELETE", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
    }


def clear_business_blocks(
    host: str,
    namespace: str,
    *,
    creator: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/blockbizipclear",
        query={"creator": creator},
    )
    result = request_json("DELETE", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
    }


def set_block_time(
    host: str,
    namespace: str,
    *,
    block_time: str | None = None,
    brute_block_time: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    if not block_time and not brute_block_time:
        raise AFClientError("block_time 和 brute_block_time 至少需要提供一个")
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    payload: dict[str, Any] = {}
    if block_time:
        payload["blockTime"] = block_time
    if brute_block_time:
        payload["bruteBlockTime"] = brute_block_time
    url = build_url(session.host, session.namespace, "/api/v1/namespaces/@namespace/blockiptime")
    result = request_json("PATCH", url, payload=payload, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "request": payload,
    }


def list_exception_blocks(
    host: str,
    namespace: str,
    *,
    start: int | None = None,
    length: int | None = None,
    search: str | None = None,
    select: str | None = None,
    sortby: str | None = None,
    order: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/blockip/excludeblockip",
        query=_query_params(start=start, length=length, search=search, select=select, sortby=sortby, order=order),
    )
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def add_exception_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/blockip/excludeblockips",
    )
    result = request_json("POST", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }


def delete_exception_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/blockip/excludeblockip",
        query={"_method": "delete"},
    )
    result = request_json("POST", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }


def update_exception_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    key: str | None = None,
    where: str | None = None,
    dest: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/blockip/excludeblockip",
        query={"_key": key, "_where": where, "_dest": dest},
    )
    result = request_json("PATCH", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }


def update_exception_block(
    host: str,
    namespace: str,
    *,
    record: dict[str, Any],
    key: str | None = None,
    ip_name: str | None = None,
    where: str | None = None,
    dest: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/blockip/excludeblockip",
        query={"_key": key, "ipName": ip_name, "_where": where, "_dest": dest},
    )
    result = request_json("PATCH", url, payload=record, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "request": record,
    }


def list_attacker_blocks(
    host: str,
    namespace: str,
    *,
    creator: str | None = None,
    start: int | None = None,
    length: int | None = None,
    search: str | None = None,
    sortby: str | None = None,
    order: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/v1/namespaces/@namespace/blockip",
        query=_query_params(creator=creator, start=start, length=length, search=search, sortby=sortby, order=order),
    )
    result = request_json("GET", url, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return result.get("data") or {}


def add_attacker_blocks(
    host: str,
    namespace: str,
    *,
    payload: dict[str, Any],
    creator: str | None = None,
    aifw_type: str | None = None,
    override: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/blockip",
        query={"creator": creator, "aifwType": aifw_type, "override": override},
    )
    result = request_json("POST", url, payload=payload, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "request": payload,
    }


def delete_attacker_blocks(
    host: str,
    namespace: str,
    *,
    records: list[dict[str, Any]],
    creator: str | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    session = get_active_session(host, namespace, verify_tls=verify_tls, auto_refresh=True)
    url = build_url(
        session.host,
        session.namespace,
        "/api/batch/v1/namespaces/@namespace/blockip",
        query={"_method": "delete", "creator": creator},
    )
    result = request_json("POST", url, payload=records, token=session.token, verify_tls=verify_tls)
    _mark_session_active(session)
    return {
        "success": True,
        "message": result.get("message", "成功"),
        "data": result.get("data"),
        "requestCount": len(records),
    }