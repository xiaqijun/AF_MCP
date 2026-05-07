APP_NAME = "设备联动封禁智能体"
APP_VERSION = "0.1.0"
MCP_HOST = "127.0.0.1"
MCP_PATH = "/mcp"
DEFAULT_CONFIRM_MODE = "manual"
DEFAULT_WHITELIST_FILE = "examples/whitelist.sample.json"
DEFAULT_LOG_FILE = "logs/device-block-agent.jsonl"
DEFAULT_SESSION_FILE = "data/sessions.json"
DEFAULT_SESSION_TIMEOUT_SECONDS = 600
DEFAULT_SESSION_REFRESH_WINDOW_SECONDS = 120

PLANNED_AUTH_TOOLS = [
    "auth_login",
    "auth_keepalive",
    "auth_logout",
]

PLANNED_BLOCK_TOOLS = [
    "block_list_temp",
    "block_list_business",
    "block_get_total_count",
    "block_get_block_time",
    "block_add_business",
    "block_delete_temp",
    "block_delete_business",
    "block_clear_attackers",
    "block_clear_temp",
    "block_clear_business",
    "block_set_block_time",
]

ALWAYS_CONFIRM_ACTIONS = {
    "block_clear_attackers",
    "block_clear_temp",
    "block_clear_business",
}

BATCH_CONFIRM_ACTIONS = {
    "block_add_business",
    "block_delete_temp",
    "block_delete_business",
}