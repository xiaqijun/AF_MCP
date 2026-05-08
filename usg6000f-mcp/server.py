#!/usr/bin/env python3
"""
华为 HiSecEngine USG6000F 防火墙 MCP Server
协议: RESTCONF (RFC 8040) + YANG
固件: V600R023C00
"""

import argparse
import base64
import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP

# 白名单引擎（五层强校验）
from whitelist import get_engine as _get_wl_engine, auto_load_default as _wl_auto_load

# 动作快照（误封应急 + 审计）
import snapshot as _snap

# ── 配置（优先命令行参数，其次环境变量） ──────────────────────────────────────

_parser = argparse.ArgumentParser(description="华为 USG6000F MCP Server")
_parser.add_argument("--host", default=None)
_parser.add_argument("--port", default=None)
_parser.add_argument("--username", default=None)
_parser.add_argument("--password", default=None)
_parser.add_argument("--verify-ssl", default=None)
_args, _ = _parser.parse_known_args()


def _is_valid(v: str | None) -> bool:
    return bool(v) and not (v.startswith("${") and v.endswith("}"))


USG_HOST     = _args.host     if _is_valid(_args.host)     else os.environ.get("USG_HOST", "")
USG_PORT     = _args.port     if _is_valid(_args.port)     else os.environ.get("USG_PORT", "443")
USG_USERNAME = _args.username if _is_valid(_args.username) else os.environ.get("USG_USERNAME", "")
USG_PASSWORD = _args.password if _is_valid(_args.password) else os.environ.get("USG_PASSWORD", "")
_VERIFY_RAW  = _args.verify_ssl if _is_valid(_args.verify_ssl) else os.environ.get("USG_VERIFY_SSL", "false")
USG_VERIFY_SSL = _VERIFY_RAW.lower() not in ("false", "0", "no")

BASE_URL = f"https://{USG_HOST}:{USG_PORT}/restconf/data"

# Basic Auth header
_AUTH_HEADER = "Basic " + base64.b64encode(
    f"{USG_USERNAME}:{USG_PASSWORD}".encode()
).decode()

# SSL context
_SSL_CTX = ssl.create_default_context()
if not USG_VERIFY_SSL:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

_JSON_HEADERS = {
    "Authorization": _AUTH_HEADER,
    "Content-Type": "application/yang-data+json",
    "Accept": "application/yang-data+json",
}

# ── HTTP 工具 ─────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None) -> dict:
    """发起 RESTCONF 请求，返回解析后的 JSON（或空 dict）。"""
    url = BASE_URL + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=_JSON_HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, context=_SSL_CTX, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {body_text[:300]}")


def _get(path: str) -> dict:
    return _request("GET", path)


def _put(path: str, body: dict) -> dict:
    return _request("PUT", path, body)


def _post(path: str, body: dict) -> dict:
    return _request("POST", path, body)


def _patch(path: str, body: dict) -> dict:
    return _request("PATCH", path, body)


# ── 预览/提交 辅助 ────────────────────────────────────────────────────────────

def _preview_result(method: str, path: str, body: dict, description: str) -> str:
    """生成预览结果（不发送请求）。"""
    return json.dumps({
        "preview": True,
        "description": description,
        "method": method,
        "url": BASE_URL + path,
        "body": body,
        "instruction": "确认无误后，以 confirmed=True 调用对应 apply_* 工具执行变更。",
    }, ensure_ascii=False, indent=2)


# ── MCP Server ────────────────────────────────────────────────────────────────

mcp = FastMCP("usg6000f")

# 启动时尝试自动加载白名单（可选：不存在则 skip）
_WL_AUTOLOAD_PATH = _wl_auto_load()
if _WL_AUTOLOAD_PATH:
    print(f"[usg6000f] whitelist loaded from {_WL_AUTOLOAD_PATH}", file=sys.stderr)


# ── 白名单校验（封禁前强拦截） ────────────────────────────────────────────────

def _whitelist_check_or_block(
    ip_address: str,
    *,
    asn: int | None = None,
    domain: str | None = None,
    tags: list[str] | None = None,
) -> str | None:
    """
    白名单强校验：命中则返回 JSON 字符串（调用方直接 return），
    未命中则返回 None，调用方继续正常流程。
    """
    engine = _get_wl_engine()
    result = engine.check(ip_address, asn=asn, domain=domain, tags=tags)
    if not result.hit:
        return None
    # action == "block" 视为硬拒绝；warn 视为软警告（继续但附 warning）
    if result.action == "block":
        return json.dumps({
            "error": "WHITELIST_BLOCKED",
            "message": f"IP {ip_address} 命中白名单 {result.layer}，已拒绝封禁操作",
            "detail": result.to_dict(),
        }, ensure_ascii=False, indent=2)
    return None  # warn 不阻断（但后面工具会在 result 里附 warning）


# ── 读操作 ────────────────────────────────────────────────────────────────────

@mcp.tool()
def get_security_policies(policy_name: str | None = None) -> str:
    """
    查询安全策略列表。

    Args:
        policy_name: 策略名称精确匹配过滤；为空时返回全部策略
    """
    path = "/huawei-security-policy:security-policies/security-policy"
    if policy_name:
        path += f"={policy_name}"
    data = _get(path)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_nat_rules(
    instance_name: str = "default",
    nat_type: str = "source",
) -> str:
    """
    查询 NAT 规则。

    Args:
        instance_name: NAT 实例名称（默认 "default"）
        nat_type:      NAT 类型，"source"（源NAT）或 "destination"（目的NAT）
    """
    if nat_type == "source":
        path = f"/huawei-nat:nat/nat-instances/nat-instance={instance_name}/nat-policies"
    else:
        path = f"/huawei-nat:nat/nat-instances/nat-instance={instance_name}/static-mappings"
    data = _get(path)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_acl_rules(acl_number: str | None = None) -> str:
    """
    查询 ACL 列表及规则。

    Args:
        acl_number: ACL 编号（如 "3000"）；为空时返回全部 ACL
    """
    path = "/huawei-acl:acl/acl-groups/acl-group"
    if acl_number:
        path += f"={acl_number}"
    data = _get(path)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_interfaces(interface_name: str | None = None) -> str:
    """
    查询接口信息，包含接口状态、IP 地址、描述等。

    Args:
        interface_name: 接口名称（如 "GigabitEthernet0/0/0"）；为空时返回全部接口
    """
    path = "/huawei-ifm:ifm/interfaces/interface"
    if interface_name:
        path += f"={interface_name}"
    data = _get(path)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_static_routes(dest_prefix: str | None = None) -> str:
    """
    查询 IPv4 静态路由表。

    Args:
        dest_prefix: 目的网段（如 "10.0.0.0/8"）；为空时返回全部静态路由
    """
    path = "/huawei-ip-route-static:ipv4-unicast-routing/ipv4-routes/ipv4-route"
    if dest_prefix:
        # URL encode the slash in prefix
        encoded = dest_prefix.replace("/", "%2F")
        path += f"={encoded}"
    data = _get(path)
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_sessions(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    max_count: int = 100,
) -> str:
    """
    查询当前会话表（连接状态）。

    Args:
        src_ip:    按源 IP 过滤
        dst_ip:    按目的 IP 过滤
        max_count: 最大返回条数（默认 100）
    """
    path = "/huawei-session:session/sessions"
    data = _get(path)
    # 客户端侧过滤
    sessions = data.get("session", [])
    if src_ip:
        sessions = [s for s in sessions if s.get("src-ip") == src_ip]
    if dst_ip:
        sessions = [s for s in sessions if s.get("dst-ip") == dst_ip]
    return json.dumps({
        "total": len(sessions),
        "sessions": sessions[:max_count],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def get_ipsec_tunnels() -> str:
    """查询 IPSec VPN 隧道状态列表。"""
    data = _get("/huawei-ipsec:ipsec/ipsec-sas")
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def get_blacklist() -> str:
    """查询 IP 黑名单列表。"""
    data = _get("/huawei-blacklist:blacklist/blacklist-items/blacklist-item")
    return json.dumps(data, ensure_ascii=False, indent=2)


# ── 安全策略 写操作 ───────────────────────────────────────────────────────────

@mcp.tool()
def preview_security_policy(
    name: str,
    action: str,
    src_zone: str,
    dst_zone: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    service: str | None = None,
    description: str | None = None,
    operation: str = "create",
) -> str:
    """
    预览新增或修改安全策略（不实际下发）。

    Args:
        name:        策略名称
        action:      动作，"permit" 或 "deny"
        src_zone:    源安全区域（如 "untrust"）
        dst_zone:    目的安全区域（如 "trust"）
        src_ip:      源 IP 或网段（如 "192.168.1.0/24"），可选
        dst_ip:      目的 IP 或网段，可选
        service:     服务/协议（如 "HTTP"、"HTTPS"），可选
        description: 策略描述，可选
        operation:   "create"（新建）或 "update"（修改）
    """
    policy: dict[str, Any] = {
        "name": name,
        "action": action,
        "src-zone": [src_zone],
        "dst-zone": [dst_zone],
    }
    if src_ip:
        policy["src-ip"] = [{"address": src_ip}]
    if dst_ip:
        policy["dst-ip"] = [{"address": dst_ip}]
    if service:
        policy["service"] = [{"name": service}]
    if description:
        policy["description"] = description

    body = {"huawei-security-policy:security-policy": [policy]}
    method = "POST" if operation == "create" else "PUT"
    path = "/huawei-security-policy:security-policies/security-policy"
    if operation == "update":
        path += f"={name}"

    desc = f"{'新建' if operation == 'create' else '修改'}安全策略 [{name}]: {src_zone}→{dst_zone} {action}"
    return _preview_result(method, path, body, desc)


@mcp.tool()
def apply_security_policy(
    name: str,
    action: str,
    src_zone: str,
    dst_zone: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    service: str | None = None,
    description: str | None = None,
    operation: str = "create",
    confirmed: bool = False,
) -> str:
    """
    提交安全策略变更。必须先调用 preview_security_policy 确认内容，
    然后以 confirmed=True 调用本工具。

    Args:
        name, action, src_zone, dst_zone, src_ip, dst_ip, service, description, operation:
            与 preview_security_policy 相同
        confirmed: 必须设为 True 才会实际执行
    """
    if not confirmed:
        return json.dumps({
            "error": "未确认，操作已取消。请先调用 preview_security_policy 查看变更内容，确认无误后以 confirmed=True 重新调用。"
        }, ensure_ascii=False)

    policy: dict[str, Any] = {
        "name": name,
        "action": action,
        "src-zone": [src_zone],
        "dst-zone": [dst_zone],
    }
    if src_ip:
        policy["src-ip"] = [{"address": src_ip}]
    if dst_ip:
        policy["dst-ip"] = [{"address": dst_ip}]
    if service:
        policy["service"] = [{"name": service}]
    if description:
        policy["description"] = description

    body = {"huawei-security-policy:security-policy": [policy]}
    path = "/huawei-security-policy:security-policies/security-policy"

    if operation == "create":
        result = _post(path, body)
    else:
        result = _put(path + f"={name}", body)

    return json.dumps({"success": True, "result": result}, ensure_ascii=False, indent=2)


# ── NAT 写操作 ────────────────────────────────────────────────────────────────

@mcp.tool()
def preview_nat_rule(
    instance_name: str,
    rule_name: str,
    src_ip: str,
    out_interface: str,
    nat_mode: str = "pat",
    address_pool: str | None = None,
) -> str:
    """
    预览新增源 NAT 规则（不实际下发）。

    Args:
        instance_name: NAT 实例名称（如 "default"）
        rule_name:     NAT 策略名称
        src_ip:        匹配的源 IP 段（如 "192.168.0.0/16"）
        out_interface: 出接口名称（如 "GigabitEthernet0/0/0"）
        nat_mode:      NAT 模式，"pat"（端口复用）或 "no-pat"（一对一）
        address_pool:  地址池名称（no-pat 模式需要）
    """
    rule: dict[str, Any] = {
        "name": rule_name,
        "src-ip": [{"address": src_ip}],
        "out-interface": out_interface,
        "action": {"pat": {}} if nat_mode == "pat" else {"no-pat": {"pool-name": address_pool}},
    }
    body = {"huawei-nat:nat-policy": [rule]}
    path = f"/huawei-nat:nat/nat-instances/nat-instance={instance_name}/nat-policies"
    desc = f"新增 NAT 策略 [{rule_name}]: {src_ip} → {out_interface} ({nat_mode})"
    return _preview_result("POST", path, body, desc)


@mcp.tool()
def apply_nat_rule(
    instance_name: str,
    rule_name: str,
    src_ip: str,
    out_interface: str,
    nat_mode: str = "pat",
    address_pool: str | None = None,
    confirmed: bool = False,
) -> str:
    """
    提交 NAT 规则变更。需先调用 preview_nat_rule，确认后以 confirmed=True 调用。

    Args: 与 preview_nat_rule 相同，加 confirmed=True
    """
    if not confirmed:
        return json.dumps({
            "error": "未确认，操作已取消。请先调用 preview_nat_rule 查看变更内容。"
        }, ensure_ascii=False)

    rule: dict[str, Any] = {
        "name": rule_name,
        "src-ip": [{"address": src_ip}],
        "out-interface": out_interface,
        "action": {"pat": {}} if nat_mode == "pat" else {"no-pat": {"pool-name": address_pool}},
    }
    body = {"huawei-nat:nat-policy": [rule]}
    path = f"/huawei-nat:nat/nat-instances/nat-instance={instance_name}/nat-policies"
    result = _post(path, body)
    return json.dumps({"success": True, "result": result}, ensure_ascii=False, indent=2)


# ── 黑名单 写操作 ─────────────────────────────────────────────────────────────

@mcp.tool()
def preview_blacklist_add(
    ip_address: str,
    expire_time: int = 0,
    description: str | None = None,
    asn: int | None = None,
    domain: str | None = None,
    asset_tags: list[str] | None = None,
) -> str:
    """
    预览向黑名单添加 IP（不实际下发）。前置执行五层白名单强校验。

    Args:
        ip_address:   要封锁的 IP 地址（如 "1.2.3.4"）
        expire_time:  过期时间（秒），0 表示永久
        description:  备注，可选（建议传 judge_id）
        asn:          源 IP 所属 ASN（可选，用于 L2 ASN 白名单校验）
        domain:       源 IP 的 PTR 反查域名（可选，用于 L3 Domain 校验）
        asset_tags:   目标资产标签（可选，用于 L4 Tag 校验，如 ["core_business"]）
    """
    # ── 白名单强校验（硬拦截） ──
    wl_block = _whitelist_check_or_block(
        ip_address, asn=asn, domain=domain, tags=asset_tags,
    )
    if wl_block:
        return wl_block

    item: dict[str, Any] = {"ip": ip_address}
    if expire_time:
        item["expire-time"] = expire_time
    if description:
        item["description"] = description

    body = {"huawei-blacklist:blacklist-item": [item]}
    path = "/huawei-blacklist:blacklist/blacklist-items/blacklist-item"
    expire_str = f"{expire_time}s" if expire_time else "永久"
    desc = f"添加黑名单 IP [{ip_address}]，有效期：{expire_str}"

    # 附带白名单校验的 PASSED 证据（用于审计）
    wl_engine = _get_wl_engine()
    wl_result = wl_engine.check(ip_address, asn=asn, domain=domain, tags=asset_tags)

    preview_raw = _preview_result("POST", path, body, desc)
    # 塞入 whitelist_check 证据
    preview_obj = json.loads(preview_raw)
    preview_obj["whitelist_check"] = wl_result.to_dict()
    return json.dumps(preview_obj, ensure_ascii=False, indent=2)


@mcp.tool()
def apply_blacklist_add(
    ip_address: str,
    expire_time: int = 0,
    description: str | None = None,
    asn: int | None = None,
    domain: str | None = None,
    asset_tags: list[str] | None = None,
    confirmed: bool = False,
) -> str:
    """
    提交黑名单 IP 添加。需先调用 preview_blacklist_add，确认后以 confirmed=True 调用。

    Args: 与 preview_blacklist_add 相同，加 confirmed=True
    """
    if not confirmed:
        return json.dumps({
            "error": "未确认，操作已取消。请先调用 preview_blacklist_add 查看变更内容。"
        }, ensure_ascii=False)

    # ── 白名单强校验（再校验一次，防止 preview 和 apply 之间白名单变化） ──
    wl_block = _whitelist_check_or_block(
        ip_address, asn=asn, domain=domain, tags=asset_tags,
    )
    if wl_block:
        return wl_block

    item: dict[str, Any] = {"ip": ip_address}
    if expire_time:
        item["expire-time"] = expire_time
    if description:
        item["description"] = description

    # 执行前拉当前黑名单做 pre_state 快照（用于 unblock 还原）
    try:
        pre_state_raw = _get("/huawei-blacklist:blacklist/blacklist-items/blacklist-item")
    except Exception:
        pre_state_raw = {"_note": "快照获取失败，设备不可达；仍继续执行"}

    body = {"huawei-blacklist:blacklist-item": [item]}
    path = "/huawei-blacklist:blacklist/blacklist-items/blacklist-item"

    try:
        result = _post(path, body)
        apply_status = "applied"
        err_info: str | None = None
    except Exception as exc:
        result = {"error": f"{type(exc).__name__}: {exc}"}
        apply_status = "failed"
        err_info = str(exc)

    wl_engine = _get_wl_engine()
    wl_result = wl_engine.check(ip_address, asn=asn, domain=domain, tags=asset_tags)

    # 提取 judge_id（若 description 以 SOAR- 开头，视为 judge 来源）
    judge_id: str | None = None
    if description and description.startswith("SOAR-"):
        judge_id = description[5:].strip() or None

    # 落盘 action 快照
    action_id = _snap.new_action_id()
    action_rec = {
        "action_id":   action_id,
        "created_at":  _snap.now_iso(),
        "action_type": "block",
        "ip":          ip_address,
        "expire_time": expire_time,
        "description": description,
        "judge_id":    judge_id,
        "asset_tags":  asset_tags or [],
        "pre_state":   pre_state_raw,
        "vendor_response": result,
        "whitelist_check": wl_result.to_dict(),
        "status":      apply_status,
        "error":       err_info,
    }
    _snap.save(action_rec)

    return json.dumps({
        "success": apply_status == "applied",
        "action_id": action_id,
        "result": result,
        "whitelist_check": wl_result.to_dict(),
        "unblock_hint": f"如需回滚本次封禁，请调用 preview_blacklist_unblock(action_id='{action_id}')",
    }, ensure_ascii=False, indent=2)


# ── 白名单管理工具 ────────────────────────────────────────────────────────────

@mcp.tool()
def whitelist_check(
    ip_address: str,
    asn: int | None = None,
    domain: str | None = None,
    asset_tags: list[str] | None = None,
) -> str:
    """
    对给定 IP 做五层白名单校验（仅查询，不修改任何状态）。用于人工核对或研判智能体自检。

    Args:
        ip_address: 要校验的 IP
        asn:        IP 所属 ASN（可选）
        domain:     IP 的 PTR 反查域名（可选）
        asset_tags: 目标资产标签（可选）

    Returns:
        命中结果 JSON：{hit, layer, rule_id, comment, action, checked_layers}
    """
    engine = _get_wl_engine()
    if not engine.is_loaded():
        return json.dumps({
            "error": "白名单未加载",
            "hint": "调用 whitelist_reload(path) 或将 whitelist.yaml 放置于插件目录",
        }, ensure_ascii=False)
    r = engine.check(ip_address, asn=asn, domain=domain, tags=asset_tags)
    return json.dumps(r.to_dict(), ensure_ascii=False, indent=2)


@mcp.tool()
def whitelist_reload(path: str | None = None) -> str:
    """
    热加载/重新加载白名单 YAML。

    Args:
        path: 白名单 YAML 文件完整路径；不传则从上次加载的路径重载
    """
    engine = _get_wl_engine()
    try:
        if path:
            engine.load(path)
        else:
            engine.reload()
        return json.dumps({
            "success": True,
            "summary": engine.summary(),
        }, ensure_ascii=False, indent=2)
    except Exception as exc:
        return json.dumps({
            "success": False,
            "error": f"{type(exc).__name__}: {exc}",
        }, ensure_ascii=False)


@mcp.tool()
def whitelist_list() -> str:
    """查询当前已加载的全部白名单条目（五层）。"""
    engine = _get_wl_engine()
    if not engine.is_loaded():
        return json.dumps({"error": "白名单未加载"}, ensure_ascii=False)
    return json.dumps(engine.list_all(), ensure_ascii=False, indent=2)


@mcp.tool()
def whitelist_stats() -> str:
    """查询白名单运行统计（命中数、命中率、按层分布）+ 引擎状态。"""
    engine = _get_wl_engine()
    return json.dumps(engine.summary(), ensure_ascii=False, indent=2)


# ── 一键解封 + 处置历史 ──────────────────────────────────────────────────────

@mcp.tool()
def preview_blacklist_unblock(action_id: str) -> str:
    """
    预览解封某一次封禁动作（按 action_id）。

    Args:
        action_id: apply_blacklist_add 返回的 action_id，格式 act-YYYYMMDD-HHMMSS-xxxxxx
    """
    rec = _snap.load(action_id)
    if rec is None:
        return json.dumps({"error": f"找不到 action_id={action_id}"}, ensure_ascii=False)
    if rec.get("action_type") != "block":
        return json.dumps({
            "error": f"action_id={action_id} 类型是 {rec.get('action_type')}，无法解封",
        }, ensure_ascii=False)
    if rec.get("status") == "unblocked":
        return json.dumps({
            "error": f"action_id={action_id} 已于 {rec.get('unblocked_at')} 解封，不可重复",
        }, ensure_ascii=False)

    ip = rec["ip"]
    path = f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip}"
    desc = f"解封 IP [{ip}]（还原 action_id={action_id} 的封禁）"
    preview_raw = _preview_result("DELETE", path, {}, desc)
    preview_obj = json.loads(preview_raw)
    preview_obj["original_action"] = {
        "action_id": action_id,
        "ip": ip,
        "blocked_at": rec.get("created_at"),
        "judge_id": rec.get("judge_id"),
        "description": rec.get("description"),
    }
    return json.dumps(preview_obj, ensure_ascii=False, indent=2)


@mcp.tool()
def apply_blacklist_unblock(
    action_id: str,
    reason: str = "",
    confirmed: bool = False,
) -> str:
    """
    【应急】解封某一次封禁动作（DELETE 设备黑名单项 + 更新 action 状态为 unblocked）。
    用于误封后一键回滚（合同 10% 罚则的应急出口）。

    Args:
        action_id: apply_blacklist_add 返回的 action_id
        reason:    解封原因（将写入历史记录，用于审计）
        confirmed: 必须 True，否则返回错误
    """
    if not confirmed:
        return json.dumps({
            "error": "未确认，操作已取消。请先调用 preview_blacklist_unblock 查看要解封的内容。",
        }, ensure_ascii=False)

    rec = _snap.load(action_id)
    if rec is None:
        return json.dumps({"error": f"找不到 action_id={action_id}"}, ensure_ascii=False)
    if rec.get("status") == "unblocked":
        return json.dumps({
            "error": f"action_id={action_id} 已解封",
            "unblocked_at": rec.get("unblocked_at"),
        }, ensure_ascii=False)

    ip = rec["ip"]
    path = f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip}"
    try:
        result = _request("DELETE", path)
        ok = True
    except Exception as exc:
        result = {"error": f"{type(exc).__name__}: {exc}"}
        ok = False

    # 更新原记录
    _snap.update(action_id, {
        "status": "unblocked" if ok else "unblock_failed",
        "unblocked_at": _snap.now_iso(),
        "unblock_reason": reason,
        "unblock_result": result,
    })
    # 另记一条 unblock action
    unblock_action_id = _snap.new_action_id()
    _snap.save({
        "action_id":   unblock_action_id,
        "created_at":  _snap.now_iso(),
        "action_type": "unblock",
        "ip":          ip,
        "target_action_id": action_id,
        "reason":      reason,
        "vendor_response": result,
        "status":      "applied" if ok else "failed",
    })

    return json.dumps({
        "success": ok,
        "unblock_action_id": unblock_action_id,
        "target_action_id": action_id,
        "ip": ip,
        "result": result,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def list_actions(
    limit: int = 20,
    ip: str | None = None,
    status: str | None = None,
) -> str:
    """
    查询最近的处置动作记录（支持按 IP 或状态过滤）。

    Args:
        limit:  最多返回条数（默认 20）
        ip:     按目标 IP 过滤
        status: 按状态过滤：applied / unblocked / failed / unblock_failed
    """
    items = _snap.list_recent(limit=limit, ip=ip, status=status)
    return json.dumps({
        "count": len(items),
        "items": [
            {
                k: v for k, v in it.items()
                if k not in ("pre_state", "vendor_response", "unblock_result")  # 精简
            } for it in items
        ],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def get_action_detail(action_id: str) -> str:
    """查询单个 action 的完整详情（含 pre_state 快照 + 设备响应 + 审计链）。"""
    rec = _snap.load(action_id)
    if rec is None:
        return json.dumps({"error": f"找不到 action_id={action_id}"}, ensure_ascii=False)
    return json.dumps(rec, ensure_ascii=False, indent=2)


@mcp.tool()
def unblock_recent(window_min: int = 30, reason: str = "emergency_rollback") -> str:
    """
    【紧急批量回退】一键解封最近 N 分钟内的所有自动封禁（对应合同 10% 罚则的最快应急路径）。

    Args:
        window_min: 时间窗口（分钟）
        reason:     统一的解封原因
    """
    cutoff = datetime.datetime.now() - datetime.timedelta(minutes=window_min)
    all_actions = _snap.list_recent(limit=500, status="applied")
    targets = []
    for a in all_actions:
        if a.get("action_type") != "block":
            continue
        try:
            created = datetime.datetime.fromisoformat(a["created_at"])
            # 去掉时区便于比较（粗略）
            if created.tzinfo is not None:
                created = created.replace(tzinfo=None)
        except Exception:
            continue
        if created >= cutoff:
            targets.append(a)

    results = []
    for a in targets:
        ip = a["ip"]
        path = f"/huawei-blacklist:blacklist/blacklist-items/blacklist-item={ip}"
        try:
            _request("DELETE", path)
            ok = True
            err: str | None = None
        except Exception as exc:
            ok = False
            err = f"{type(exc).__name__}: {exc}"
        _snap.update(a["action_id"], {
            "status": "unblocked" if ok else "unblock_failed",
            "unblocked_at": _snap.now_iso(),
            "unblock_reason": reason,
            "unblock_result": {"error": err} if err else {"ok": True},
        })
        results.append({
            "action_id": a["action_id"],
            "ip": ip,
            "ok": ok,
            "error": err,
        })

    succ = sum(1 for r in results if r["ok"])
    return json.dumps({
        "window_min": window_min,
        "total_targets": len(results),
        "success": succ,
        "failed": len(results) - succ,
        "items": results,
    }, ensure_ascii=False, indent=2)


# ── 静态路由 写操作 ───────────────────────────────────────────────────────────

@mcp.tool()
def preview_static_route(
    dest_ip: str,
    prefix_length: int,
    next_hop: str,
    preference: int = 60,
    description: str | None = None,
    operation: str = "create",
) -> str:
    """
    预览静态路由新增或修改（不实际下发）。

    Args:
        dest_ip:       目的网络地址（如 "10.10.0.0"）
        prefix_length: 子网掩码长度（如 24）
        next_hop:      下一跳 IP（如 "192.168.1.1"）
        preference:    路由优先级（默认 60）
        description:   路由描述，可选
        operation:     "create"（新建）或 "update"（修改）
    """
    route: dict[str, Any] = {
        "dest-ip-addr": dest_ip,
        "prefix-length": prefix_length,
        "nexthop-ip-addr": next_hop,
        "preference": preference,
    }
    if description:
        route["description"] = description

    prefix = f"{dest_ip}/{prefix_length}"
    body = {"huawei-ip-route-static:ipv4-route": [route]}
    method = "POST" if operation == "create" else "PUT"
    path = "/huawei-ip-route-static:ipv4-unicast-routing/ipv4-routes/ipv4-route"
    if operation == "update":
        encoded = prefix.replace("/", "%2F")
        path += f"={encoded}"

    desc = f"{'新建' if operation == 'create' else '修改'}静态路由 {prefix} → {next_hop}"
    return _preview_result(method, path, body, desc)


@mcp.tool()
def apply_static_route(
    dest_ip: str,
    prefix_length: int,
    next_hop: str,
    preference: int = 60,
    description: str | None = None,
    operation: str = "create",
    confirmed: bool = False,
) -> str:
    """
    提交静态路由变更。需先调用 preview_static_route，确认后以 confirmed=True 调用。

    Args: 与 preview_static_route 相同，加 confirmed=True
    """
    if not confirmed:
        return json.dumps({
            "error": "未确认，操作已取消。请先调用 preview_static_route 查看变更内容。"
        }, ensure_ascii=False)

    route: dict[str, Any] = {
        "dest-ip-addr": dest_ip,
        "prefix-length": prefix_length,
        "nexthop-ip-addr": next_hop,
        "preference": preference,
    }
    if description:
        route["description"] = description

    prefix = f"{dest_ip}/{prefix_length}"
    body = {"huawei-ip-route-static:ipv4-route": [route]}
    path = "/huawei-ip-route-static:ipv4-unicast-routing/ipv4-routes/ipv4-route"

    if operation == "create":
        result = _post(path, body)
    else:
        encoded = prefix.replace("/", "%2F")
        result = _put(path + f"={encoded}", body)

    return json.dumps({"success": True, "result": result}, ensure_ascii=False, indent=2)


# ── 启动入口 ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio
    import contextlib
    import logging
    from collections.abc import AsyncIterator

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import Mount

    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    async def _serve() -> None:
        session_manager = StreamableHTTPSessionManager(
            app=mcp._mcp_server, json_response=True
        )

        async def handle(scope, receive, send):
            await session_manager.handle_request(scope, receive, send)

        @contextlib.asynccontextmanager
        async def lifespan(app) -> AsyncIterator[None]:
            async with session_manager.run():
                yield

        starlette_app = CORSMiddleware(
            Starlette(
                debug=False,
                routes=[Mount("/mcp", app=handle)],
                lifespan=lifespan,
            ),
            allow_origins=["*"],
            allow_methods=["GET", "POST", "DELETE"],
            expose_headers=["Mcp-Session-Id"],
        )

        config = uvicorn.Config(
            starlette_app,
            host="127.0.0.1",
            port=0,
            log_config=None,
            access_log=False,
        )
        server = uvicorn.Server(config)
        original_startup = server.startup

        async def patched_startup(sockets=None):
            await original_startup(sockets)
            for srv in server.servers:
                for sock in srv.sockets:
                    print(
                        json.dumps({"type": "http_start", "port": sock.getsockname()[1]}),
                        flush=True,
                    )
                    return

        server.startup = patched_startup
        await server.serve()

    asyncio.run(_serve())
