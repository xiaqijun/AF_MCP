"""
USG6000F 处置动作快照与一键解封

覆盖招标指标：
  - 处置日志记录（action 持久化，可审计）
  - 误封事件 5 分钟内一键解封（合同 10% 罚则应急）

存储：
  每个 action 序列化为 JSON 文件，放在
    ${USG_ACTION_DIR} 或 ~/.usg6000f-mcp/actions/
  文件名：{action_id}.json

action 记录结构：
  {
    "action_id":   "act-20260420-143012-abc123",
    "created_at":  "2026-04-20T14:30:12+08:00",
    "action_type": "block" | "unblock",
    "ip":          "1.2.3.4",
    "expire_time": 3600,
    "description": "SOAR-jdg-xxxxxx",
    "judge_id":    "jdg-xxx",             # 研判单号（可选）
    "pre_state":   { <blacklist 执行前的相关项> },
    "vendor_response": { ... },           # 设备返回
    "status":      "applied" | "unblocked" | "failed",
    "unblocked_at": "..."
  }
"""

from __future__ import annotations

import datetime
import glob
import json
import os
import secrets
from typing import Any


def _default_dir() -> str:
    d = os.environ.get("USG_ACTION_DIR", "").strip()
    if d:
        return d
    base = os.path.expanduser("~")
    d = os.path.join(base, ".usg6000f-mcp", "actions")
    os.makedirs(d, exist_ok=True)
    return d


def new_action_id() -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(3)
    return f"act-{ts}-{rand}"


def save(action: dict[str, Any]) -> str:
    """落盘一个 action 记录，返回存储路径。"""
    d = _default_dir()
    p = os.path.join(d, f"{action['action_id']}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(action, f, ensure_ascii=False, indent=2)
    return p


def load(action_id: str) -> dict[str, Any] | None:
    d = _default_dir()
    p = os.path.join(d, f"{action_id}.json")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def update(action_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
    """读-修改-写。"""
    a = load(action_id)
    if a is None:
        return None
    a.update(patch)
    save(a)
    return a


def list_recent(limit: int = 20, ip: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    d = _default_dir()
    files = sorted(
        glob.glob(os.path.join(d, "act-*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    out: list[dict[str, Any]] = []
    for p in files:
        try:
            with open(p, encoding="utf-8") as f:
                a = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if ip and a.get("ip") != ip:
            continue
        if status and a.get("status") != status:
            continue
        out.append(a)
        if len(out) >= limit:
            break
    return out


def now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")
