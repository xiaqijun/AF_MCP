# 设备联动封禁智能体

这是一个基于 FastMCP 最新版本构建的 AiPy 扩展脚手架，用于后续接入 AF 设备联动封禁能力。

## 项目结构

- `device_block_agent/`：核心 Python 源码与 MCP 工具实现。
- `docs/`：API 整理文档、方案文档与原始 PDF。
- `assets/`：图标等静态资源。
- `examples/`：白名单样例和参考素材。
- 根目录：保留 `main.py`、`manifest.json`、`requirements.txt`、`README.md` 等项目入口文件。

## 当前状态

- 已接入 FastMCP 3.2.4。
- 已提供 Streamable HTTP MCP 服务入口，默认暴露路径为 `/mcp`。
- 已提供 AiPy 要求的 `addition-system-instruction` prompt。
- 已提供 `auth_login`、`auth_keepalive`、`auth_logout` 三个认证工具。
- 已提供 `block_list_temp`、`block_list_business`、`block_get_total_count`、`block_get_block_time` 四个只读查询工具。
- 已提供白名单规则加载与人工确认判定模块，可供后续写操作工具直接复用。
- 已提供 `block_add_business`、`block_delete_temp`、`block_delete_business`、`block_clear_attackers`、`block_clear_temp`、`block_clear_business`、`block_set_block_time` 七个写操作工具。
- 已提供本地 JSONL 审计日志与按操作类型细化的回检结果。
- 已支持通过本地 JSON 文件持久化登录会话，用于跨进程复用登录态。
- 已支持本地会话超时判断与临近过期自动 keepalive。
- 已支持默认 AF 账号与连接配置，认证和封禁工具可直接复用。
- 已提供最小工具 `agent_info`，用于验证 AiPy 到 MCP 服务的发现链路。
- 已接入首版业务级回检策略，`block_clear_attackers` 已升级为前后基线对比判定。

## 本地运行

1. 安装依赖：`pip install -r requirements.txt`
2. 启动服务：`python main.py`
3. 服务启动后会在标准输出打印随机端口号。

## 风控配置

1. `examples/whitelist.sample.json` 提供本地白名单示例。
2. `confirm_mode` 支持 `manual` 和 `auto` 两种模式。
3. `WHITELIST_FILE` 和 `CONFIRM_MODE` 可通过 `manifest.json` 的 `user_config` 注入运行环境。
4. 清空类操作始终要求显式确认；批量新增、批量删除在 `manual` 模式下要求显式确认。
5. `LOG_FILE` 可用于指定本地 JSONL 审计日志路径。
6. `SESSION_FILE` 可用于指定本地 JSON 会话持久化路径。
7. `SESSION_TIMEOUT_SECONDS` 和 `SESSION_REFRESH_WINDOW_SECONDS` 可用于控制本地会话超时与自动保活窗口。

## 账号配置

1. `af_host` 用于配置默认 AF 主机地址。
2. `af_namespace` 用于配置默认命名空间，默认 `public`。
3. `af_username` 和 `af_password` 用于配置默认登录账号。
4. `af_verify_tls` 用于配置默认 HTTPS 证书校验开关。
5. 配置完成后，`auth_login`、`auth_keepalive`、`auth_logout` 以及封禁相关工具都可直接复用这些默认值。

## 当前已实现工具

1. `agent_info`
2. `auth_login`
3. `auth_keepalive`
4. `auth_logout`
5. `account_config_status`
6. `block_list_temp`
7. `block_list_business`
8. `block_get_total_count`
9. `block_get_block_time`
10. `block_add_business`
11. `block_delete_temp`
12. `block_delete_business`
13. `block_clear_attackers`
14. `block_clear_temp`
15. `block_clear_business`
16. `block_set_block_time`

## 下一步实现

1. 如需生产落地，再补日志轮转和敏感字段分级脱敏。
2. 如需更强回检能力，再补基于业务记录 ID 或操作结果对象的精确比对。
3. 如需长期运行，再补 token 失效后的自动重新认证策略。
