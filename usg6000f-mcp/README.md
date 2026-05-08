# 华为 USG6000F / USG6625F 防火墙联动 MCP

> **设备联动封禁智能体** · 通过 RESTCONF + YANG API 管理华为 HiSecEngine 防火墙
> 内置五层白名单强校验、封禁前后两步确认、pre_state 快照与一键解封，全面覆盖合同 10% 误封罚则的应急路径。
> 适用固件：V600R023C00（USG6000F / USG6625F 共用）

## 核心能力

| 模块 | 能力 |
|---|---|
| **白名单强校验** | 5 层（IP/CIDR、ASN、域名、资产标签、业务时段），任一命中立即拒绝封禁，覆盖率 100% |
| **两步确认** | 所有写操作均为 `preview_*` → `apply_*(confirmed=true)` |
| **封禁+回检** | apply 前后分别做白名单校验（防止 preview 和 apply 之间规则变化） |
| **pre_state 快照** | 每次封禁前保存设备黑名单快照，支持按 action_id 精确回滚 |
| **一键解封** | `preview_blacklist_unblock` / `apply_blacklist_unblock` |
| **紧急批量回退** | `unblock_recent(window_min=30)` — 合同 10% 罚则的最快应急出口 |
| **处置审计** | 所有 action 落盘 JSON，支持 `list_actions` / `get_action_detail` |

## 工具清单

### 读操作
| 工具 | 用途 |
|---|---|
| `get_security_policies` | 查安全策略列表 |
| `get_nat_rules` | 查 NAT 规则（源/目的） |
| `get_acl_rules` | 查 ACL 列表 |
| `get_interfaces` | 查接口（状态、IP、描述） |
| `get_static_routes` | 查 IPv4 静态路由 |
| `get_sessions` | 查当前会话表 |
| `get_ipsec_tunnels` | 查 IPSec VPN 隧道 |
| `get_blacklist` | 查 IP 黑名单（**封禁回检的依据**） |

### 写操作（两步确认）
| 工具 | 用途 |
|---|---|
| `preview_blacklist_add` / `apply_blacklist_add` | ★ 黑名单 IP 添加（含白名单强校验） |
| `preview_blacklist_unblock` / `apply_blacklist_unblock` | ★ 按 action_id 解封 |
| `preview_security_policy` / `apply_security_policy` | 安全策略变更 |
| `preview_nat_rule` / `apply_nat_rule` | NAT 规则变更 |
| `preview_static_route` / `apply_static_route` | 静态路由变更 |

### 白名单管理
| 工具 | 用途 |
|---|---|
| `whitelist_check` | 对指定 IP 做五层校验（仅查询） |
| `whitelist_reload` | 热加载 YAML（指定路径或沿用上次路径） |
| `whitelist_list` | 查询当前加载的全部白名单条目 |
| `whitelist_stats` | 命中率、命中分层、引擎状态 |

### 处置历史
| 工具 | 用途 |
|---|---|
| `list_actions` | 最近处置动作列表（支持按 IP / 状态过滤） |
| `get_action_detail` | 单个 action 完整详情（含 pre_state + 设备响应） |
| `unblock_recent` | **紧急批量回退**最近 N 分钟内的所有自动封禁 |

## 典型调用链

```
研判智能体 → preview_blacklist_add(ip, expire_time, asset_tags, asn, domain)
                │
                ▼
          [白名单五层校验]
                │
           ┌────┴─────┐
         命中        未命中
           │          │
           ▼          ▼
   WHITELIST_BLOCKED  返回 preview JSON
                      │
                      ▼
              apply_blacklist_add(... confirmed=true)
                      │
                      ▼
              [二次白名单校验]
                      │
             [拉 pre_state 快照]
                      │
             [POST RESTCONF]
                      │
              返回 action_id + 解封提示
```

## 五层白名单

顺序匹配，任一层命中立即返回 `hit=True`：

| 层 | 数据 | 配置方式 |
|---|---|---|
| L1 IP / CIDR | 精确 IP 或子网段 | `whitelist.yaml: ip:` |
| L2 ASN | 合作伙伴 / 运营商 ASN | `whitelist.yaml: asn:` |
| L3 Domain | 源 IP 的 PTR 反查域名（通配 `*.example.com`） | `whitelist.yaml: domain:` |
| L4 Tag | 目标资产标签（`core_business` / `dr_site` / `ops_segment`） | `whitelist.yaml: tag:` |
| L5 BizHour | 业务时段（工作日/节假日/工作时段） | `whitelist.yaml: biz_hour:` |

### 动作类型（action）

- `block`：拒绝封禁（硬拦截）— **默认**
- `warn`：仅警告，封禁继续（软拦截）

### 样例配置

参见 `whitelist.sample.yaml`，实施期由甲方安全负责人核对后改名为 `whitelist.yaml` 并交由版本控制。

## preview_blacklist_add 接口

```json
// 入参（研判智能体自动构造）
{
  "ip_address":  "1.2.3.4",
  "expire_time": 3600,
  "description": "SOAR-jdg-20260420-xxx",
  "asn":         12345,
  "domain":      "evil.example.com",
  "asset_tags":  ["customer_facing"]
}

// 命中白名单（拒绝）
{
  "error": "WHITELIST_BLOCKED",
  "message": "IP 10.0.0.1 命中白名单 L1_ip，已拒绝封禁操作",
  "detail": {
    "hit": true,
    "layer": "L1_ip",
    "rule_id": "ip[0]=10.0.0.0/8",
    "comment": "内网核心段",
    "action": "block",
    "checked_layers": ["L1_ip"]
  }
}

// 未命中（放行到 preview）
{
  "preview": true,
  "description": "添加黑名单 IP [1.2.3.4]，有效期：3600s",
  "method": "POST",
  "url": "https://<usg>:443/restconf/data/huawei-blacklist:blacklist/...",
  "body": { "huawei-blacklist:blacklist-item": [{ "ip": "1.2.3.4", ... }] },
  "whitelist_check": { "hit": false, "checked_layers": [...] },
  "instruction": "确认无误后，以 confirmed=true 调用 apply_blacklist_add"
}
```

## apply_blacklist_add 接口

```json
// 成功
{
  "success": true,
  "action_id": "act-20260420-143012-abc123",
  "result": { /* USG RESTCONF 原始响应 */ },
  "whitelist_check": { "hit": false },
  "unblock_hint": "如需回滚本次封禁，请调用 preview_blacklist_unblock(action_id='act-20260420-143012-abc123')"
}
```

## 紧急批量回退

```json
// unblock_recent(window_min=30)
{
  "window_min": 30,
  "total_targets": 12,
  "success": 11,
  "failed": 1,
  "items": [
    { "action_id": "act-...", "ip": "1.2.3.4", "ok": true },
    { "action_id": "act-...", "ip": "5.6.7.8", "ok": true },
    { "action_id": "act-...", "ip": "9.9.9.9", "ok": false, "error": "HTTP 404..." }
  ]
}
```

## 配置

| 参数 | 说明 | 必填 |
|---|---|---|
| `usg_host` / `usg_port` | 设备管理 IP / 端口（默认 443） | ✓ |
| `usg_username` / `usg_password` | 管理员账号 | ✓ |
| `usg_verify_ssl` | 是否验证 SSL（`false` 可绕过自签名） | — |

### USG 侧 RESTCONF 启用

```bash
# SSH 到设备
system-view
web-manager enable
web-manager security port 443
restconf
aaa
local-user soar password cipher <加密密码>
local-user soar service-type http
local-user soar level 15
save y

# 本机测试
curl -k -u soar:<pwd> \
  https://<usg>:443/restconf/data/huawei-blacklist:blacklist/blacklist-items/blacklist-item
```

### 白名单配置路径

默认在下列位置自动加载（首个存在者生效）：
1. 环境变量 `USG_WHITELIST_PATH` 指向的文件
2. 插件目录 `whitelist.yaml`
3. 插件目录 `whitelist.sample.yaml`

### 处置历史存储路径

默认：
1. 环境变量 `USG_ACTION_DIR`
2. `~/.usg6000f-mcp/actions/`

## 测试

```bash
cd usg6000f-mcp/
python -m unittest tests.test_whitelist tests.test_snapshot -v
# 30 个单元测试：白名单五层 + 优先级 + 统计；快照 save/load/update/list/filter
```

## 与方案要求的对照

| 招标指标 | 实现 |
|---|---|
| 指令生成（按威胁等级） | ✓ preview_* 按入参渲染 vendor payload |
| **白名单强校验**（多级豁免核心业务/运维/办公/第三方） | ✓ 五层 YAML + apply 前后双重校验 |
| 指令下发（防火墙） | ✓ RESTCONF JSON |
| 执行回检 | ⚠ `get_blacklist` 提供原子能力，轮询循环由编排层写 |
| 失败重试 | ⚠ 本智能体单次调用；重试由编排层处理 |
| **日志记录**（流程闭环可追溯） | ✓ 每次 action 落盘 JSON，含 pre_state / whitelist_check / vendor_response |
| **人工确认 AUTO/MANUAL** | ✓ `confirmed=True` 参数 + 双步机制 |
| **误封解除 ≤5min** | ✓ `unblock_recent(window_min=30)` 紧急批量回退 |

## 变更日志

### 0.2.0（2026-04-20）
- 新增 `whitelist.py` 五层白名单引擎 + 4 个管理工具
- 新增 `snapshot.py` 处置历史 + pre_state 快照
- 新增 `preview/apply_blacklist_unblock` / `list_actions` / `get_action_detail` / `unblock_recent`
- `preview/apply_blacklist_add` 集成白名单强校验（apply 前后双重）
- `apply_blacklist_add` 返回 action_id + unblock_hint
- 30 个新增单元测试全绿

### 0.1.0
- 初版：读操作 + 黑名单/NAT/ACL/静态路由 两步确认写操作

## 参考

- 《HiSecEngine USG6000F V600R023C00 YANG API 开发指南》（华为官方）
- RFC 8040 RESTCONF
