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
- 已提供 `auth_login`、`auth_keepalive`、`auth_logout`、`get_confirm_mode`、`set_confirm_mode` 五个认证与风控配置工具。
- 已提供例外封锁查询与维护工具，以及封锁攻击者、临时封锁、业务封锁、封锁总量、自动封锁时间等查询工具。
- 已提供白名单规则加载与人工确认判定模块，可供后续写操作工具直接复用。
- 已提供封锁攻击者、业务封锁、临时封锁、例外封锁和自动封锁时间相关写操作工具。
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

## API 测试平台

仓库额外提供了一个基于 [docs/ip-ban-api.md](docs/ip-ban-api.md) 自动生成的本地 API 测试平台。

1. 启动测试平台：`python run_api_test_platform.py`
2. 浏览器打开：`http://127.0.0.1:8010`
3. 在页面中填写命名空间、请求头、Cookie 和请求参数。
4. 从左侧选择接口后，可直接修改 Query 参数和 JSON 请求体并生成模拟响应。

测试平台特性：

- 自动读取文档中的接口总览和详细说明。
- 自动展示方法、路径、参数表、请求示例和响应示例。
- 只在本地模拟响应，不访问真实 AF 设备。
- 会按文档中的响应示例和字段规则生成 mock 结果。
- 已覆盖例外封锁、封锁攻击者、临时封锁、业务封锁、登录/注销/保活等接口的文档驱动 mock 结构。

## 风控配置

1. `examples/whitelist.sample.json` 提供本地白名单示例。
2. `confirm_mode` 支持 `手动` 和 `自动` 两种模式，也兼容旧值 `manual` 和 `auto`。
3. `WHITELIST_FILE` 和 `CONFIRM_MODE` 可通过 `manifest.json` 的 `user_config` 注入运行环境。
4. 通过 `set_confirm_mode` 工具切换后，会写入本地 `CONFIRM_MODE_FILE`，默认路径为 `data/confirm-mode.json`。
5. 通过 `set_whitelist_file` 工具切换后，会写入本地白名单配置文件，默认路径为 `data/whitelist-config.json`。
6. 确认模式解析优先级为：工具显式参数 > 本地持久化配置 > 环境变量 `CONFIRM_MODE` > 默认值 `手动`。
7. 白名单文件解析优先级为：工具显式参数 > 本地持久化配置 > 环境变量 `WHITELIST_FILE` > 默认样例文件。
8. `手动` 模式下所有写操作都要求显式确认；`自动` 模式下仅高风险写操作要求显式确认。
9. `LOG_FILE` 可用于指定本地 JSONL 审计日志路径。
10. `SESSION_FILE` 可用于指定本地 JSON 会话持久化路径。
11. `SESSION_TIMEOUT_SECONDS` 和 `SESSION_REFRESH_WINDOW_SECONDS` 可用于控制本地会话超时与自动保活窗口。

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
6. `get_confirm_mode`
7. `set_confirm_mode`
8. `get_whitelist_config`
9. `get_whitelist_rules`
10. `set_whitelist_file`
11. `check_whitelist_targets`
12. `block_list_exceptions`
13. `block_add_exceptions`
14. `block_delete_exceptions`
15. `block_update_exceptions`
16. `block_update_exception`
17. `block_list_attackers`
18. `block_list_temp`
19. `block_list_business`
20. `block_get_total_count`
21. `block_get_block_time`
22. `block_add_attackers`
23. `block_delete_attackers`
24. `block_add_business`
25. `block_delete_temp`
26. `block_delete_business`
27. `block_clear_attackers`
28. `block_clear_temp`
29. `block_clear_business`
30. `block_set_block_time`

## 下一步实现

1. 如需生产落地，再补日志轮转和敏感字段分级脱敏。
2. 如需更强回检能力，再补基于业务记录 ID 或操作结果对象的精确比对。
3. 如需长期运行，再补 token 失效后的自动重新认证策略。
