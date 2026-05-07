APP_NAME = "设备联动封禁智能体"
APP_VERSION = "0.1.0"
MCP_HOST = "127.0.0.1"
MCP_PATH = "/mcp"
DEFAULT_CONFIRM_MODE = "manual"
DEFAULT_CONFIRM_MODE_FILE = "data/confirm-mode.json"
DEFAULT_WHITELIST_FILE = "examples/whitelist.sample.json"
DEFAULT_WHITELIST_CONFIG_FILE = "data/whitelist-config.json"
DEFAULT_LOG_FILE = "logs/device-block-agent.jsonl"
DEFAULT_SESSION_FILE = "data/sessions.json"
DEFAULT_SESSION_TIMEOUT_SECONDS = 600
DEFAULT_SESSION_REFRESH_WINDOW_SECONDS = 120

PLANNED_AUTH_TOOLS = [
    "auth_login",
    "auth_keepalive",
    "auth_logout",
    "get_confirm_mode",
    "set_confirm_mode",
    "get_whitelist_config",
    "set_whitelist_file",
    "check_whitelist_targets",
]

PLANNED_BLOCK_TOOLS = [
    "block_list_exceptions",
    "block_add_exceptions",
    "block_delete_exceptions",
    "block_update_exceptions",
    "block_update_exception",
    "block_list_attackers",
    "block_list_temp",
    "block_list_business",
    "block_get_total_count",
    "block_get_block_time",
    "block_add_attackers",
    "block_delete_attackers",
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

WRITE_ACTIONS = {
    "block_add_exceptions",
    "block_delete_exceptions",
    "block_update_exceptions",
    "block_update_exception",
    "block_add_attackers",
    "block_delete_attackers",
    "block_add_business",
    "block_delete_temp",
    "block_delete_business",
    "block_clear_attackers",
    "block_clear_temp",
    "block_clear_business",
    "block_set_block_time",
}

BATCH_CONFIRM_ACTIONS = {
    "block_add_attackers",
    "block_delete_attackers",
    "block_add_business",
    "block_delete_temp",
    "block_delete_business",
}