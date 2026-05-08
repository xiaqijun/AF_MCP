# 设备联动封禁智能体

这是一个基于 FastMCP 最新版本构建的设备联动封禁智能体，当前在同一个 MCP 服务中同时接入 AF 与华为 USG6000F 两条处置链路。

重要约束：AF 和 USG6000F 属于两台不同设备，只是被统一收敛到同一个 MCP 服务中。配置、认证、协议和下发目标都必须按两台设备分别处理，不能把 AF_HOST 和 USG_HOST 视为同一个地址。

## 项目结构

- `device_block_agent/`：核心 Python 源码与 MCP 工具实现。
- `config/`：正式白名单与双设备配置参考。
- `docs/`：API 整理文档、方案文档与原始 PDF。
- `assets/`：图标等静态资源。
- `examples/`：白名单样例和参考素材。
- `usg6000f-mcp/`：原 USG 独立 MCP 参考实现，当前关键能力已合并进主 MCP。
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
- 已将 USG6000F 黑名单预览、下发、解封、五层白名单与动作快照并入同一 MCP 服务。
- AF 与 USG6000F 作为两台独立设备分别配置和下发，只共享 MCP 入口，不共享设备连接参数。
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
5. USG 连接账号不再通过 manifest 默认配置；应先在聊天中调用 `set_usg_connection` 录入 `usg_host`、`usg_port`、`usg_username`、`usg_password`、`usg_verify_ssl`。
6. 调用 USG 真实设备 API 前，必须先执行 `usg_login`；如需结束本地登录态，可执行 `usg_logout`。
7. `usg_whitelist_path` 用于指定 USG 五层白名单 YAML，默认是 [config/usg-whitelist.yaml](config/usg-whitelist.yaml)。
8. `usg_action_dir` 用于指定 USG 黑名单动作快照与回滚目录。
9. AF 与 USG 的配置是分开的：AF 工具可复用 manifest 中的 AF 默认值，USG 工具优先复用聊天中通过 `set_usg_connection` 保存的配置，但真实设备调用仍需先 `usg_login`。
10. 即使在同一条处置流程中同时使用 AF 和 USG，也应将其理解为“同一智能体协调两台设备”，而不是“同一台设备上的两类接口”。

## 设备边界

1. AF 工具只会访问 `af_host` 对应的 AF 设备接口。
2. USG 工具只会访问 `usg_host` 对应的 USG6000F RESTCONF 接口。
3. 当前仓库把两条能力合并进一个 MCP，是为了统一编排、统一风控和统一审计，不表示 AF 与 USG 是同一台设备。
4. 本地模拟测试平台可以在同一个进程里同时暴露 AF 和 USG mock 路由，但这只是联调便利，不代表生产拓扑。
5. 主 MCP 中 USG 不再从 manifest 读取默认连接账号，标准做法是在聊天中先调用 `set_usg_connection`。

## 当前已实现工具

1. `agent_info`
2. `auth_login`
3. `auth_keepalive`
4. `auth_logout`
5. `account_config_status`
6. `set_usg_connection`
7. `clear_usg_connection`
8. `get_confirm_mode`
9. `set_confirm_mode`
10. `get_whitelist_config`
11. `get_whitelist_rules`
12. `set_whitelist_file`
13. `check_whitelist_targets`
14. `block_list_exceptions`
15. `block_add_exceptions`
16. `block_delete_exceptions`
17. `block_update_exceptions`
18. `block_update_exception`
19. `block_list_attackers`
20. `block_list_temp`
21. `block_list_business`
22. `block_get_total_count`
23. `block_get_block_time`
24. `block_add_attackers`
25. `block_delete_attackers`
26. `block_add_business`
27. `block_delete_temp`
28. `block_delete_business`
29. `block_clear_attackers`
30. `block_clear_temp`
31. `block_clear_business`
32. `block_set_block_time`
33. `usg_connection_status`
34. `usg_login`
35. `usg_logout`
36. `usg_get_blacklist`
37. `usg_preview_blacklist_add`
38. `usg_apply_blacklist_add`
39. `usg_whitelist_check`
40. `usg_whitelist_reload`
41. `usg_whitelist_list`
42. `usg_whitelist_stats`
43. `usg_preview_blacklist_unblock`
44. `usg_apply_blacklist_unblock`
45. `usg_list_actions`
46. `usg_get_action_detail`
47. `usg_unblock_recent`

## 下一步实现

1. 如需生产落地，再补日志轮转和敏感字段分级脱敏。
2. 如需更强回检能力，再补基于业务记录 ID 或操作结果对象的精确比对。
3. 如需长期运行，再补 token 失效后的自动重新认证策略。
