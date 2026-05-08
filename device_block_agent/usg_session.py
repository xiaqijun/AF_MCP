import json
import os
import threading
import time
from dataclasses import asdict
from dataclasses import dataclass
from typing import Any

from .app_config import DEFAULT_USG_SESSION_FILE, DEFAULT_USG_SESSION_TIMEOUT_SECONDS


class USGAuthError(Exception):
    pass


@dataclass(slots=True)
class USGSession:
    host: str
    port: str
    username: str
    authenticated_at: float
    last_active_at: float
    expires_at: float


class USGSessionStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str, str], USGSession] = {}
        self._session_file = os.getenv("USG_SESSION_FILE", DEFAULT_USG_SESSION_FILE).strip() or DEFAULT_USG_SESSION_FILE
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
                session = USGSession(**item)
            except TypeError:
                continue
            self._sessions[(session.host, session.port, session.username)] = session

    def _save(self) -> None:
        if not self._session_file:
            return
        directory = os.path.dirname(self._session_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = [asdict(session) for session in self._sessions.values()]
        with open(self._session_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)

    def set(self, session: USGSession) -> None:
        with self._lock:
            self._sessions[(session.host, session.port, session.username)] = session
            self._save()

    def get(self, host: str, port: str, username: str) -> USGSession | None:
        with self._lock:
            return self._sessions.get((host, port, username))

    def touch(self, host: str, port: str, username: str) -> USGSession | None:
        with self._lock:
            session = self._sessions.get((host, port, username))
            if session is None:
                return None
            now = time.time()
            session.last_active_at = now
            session.expires_at = now + get_usg_session_timeout_seconds()
            self._save()
            return session

    def pop(self, host: str, port: str, username: str) -> USGSession | None:
        with self._lock:
            session = self._sessions.pop((host, port, username), None)
            self._save()
            return session

    def describe(self, host: str, port: str, username: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get((host, port, username))
            expired = bool(session and time.time() >= session.expires_at)
            return {
                "sessionFile": self._session_file,
                "persistenceEnabled": bool(self._session_file),
                "loggedIn": bool(session) and not expired,
                "expired": expired,
                "sessionKey": f"{host}|{port}|{username}" if host and username else "",
            }


session_store = USGSessionStore()


def get_usg_session_timeout_seconds() -> int:
    raw_value = os.getenv("USG_SESSION_TIMEOUT_SECONDS", str(DEFAULT_USG_SESSION_TIMEOUT_SECONDS)).strip()
    try:
        value = int(raw_value)
    except ValueError as error:
        raise USGAuthError("USG_SESSION_TIMEOUT_SECONDS 必须是整数") from error
    return max(60, value)


def create_usg_session(host: str, port: str, username: str) -> USGSession:
    now = time.time()
    session = USGSession(
        host=host,
        port=port,
        username=username,
        authenticated_at=now,
        last_active_at=now,
        expires_at=now + get_usg_session_timeout_seconds(),
    )
    session_store.set(session)
    return session


def get_active_usg_session(host: str, port: str, username: str) -> USGSession:
    session = session_store.get(host, port, username)
    if session is None:
        raise USGAuthError("当前 USG 连接没有可用登录态，请先调用 usg_login")
    if time.time() >= session.expires_at:
        session_store.pop(host, port, username)
        raise USGAuthError("当前 USG 登录态已过期，请重新调用 usg_login")
    return session


def touch_usg_session(host: str, port: str, username: str) -> USGSession | None:
    return session_store.touch(host, port, username)


def clear_usg_session(host: str, port: str, username: str) -> USGSession | None:
    return session_store.pop(host, port, username)


def describe_usg_session(host: str, port: str, username: str) -> dict[str, Any]:
    return {
        **session_store.describe(host, port, username),
        "sessionTimeoutSeconds": get_usg_session_timeout_seconds(),
    }