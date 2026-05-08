import os


APP_NAME = "设备联动封禁智能体"
APP_VERSION = "0.1.0"
MCP_HOST = "127.0.0.1"
MCP_PORT = int(os.getenv("MCP_PORT", "8008"))
MCP_PATH = "/mcp"
DEFAULT_CONFIRM_MODE = "manual"
DEFAULT_CONFIRM_MODE_FILE = "data/confirm-mode.json"
DEFAULT_WHITELIST_FILE = "examples/whitelist.sample.json"
DEFAULT_WHITELIST_CONFIG_FILE = "data/whitelist-config.json"
DEFAULT_USG_ACCOUNT_FILE = "data/usg-account.json"
DEFAULT_LOG_FILE = "logs/device-block-agent.jsonl"
DEFAULT_SESSION_FILE = "data/sessions.json"
DEFAULT_SESSION_TIMEOUT_SECONDS = 600
DEFAULT_SESSION_REFRESH_WINDOW_SECONDS = 120
DEFAULT_USG_WHITELIST_PATH = "config/usg-whitelist.yaml"

PLANNED_AUTH_TOOLS = [
    "auth_login",
    "auth_keepalive",
    "auth_logout",
    "set_usg_connection",
    "clear_usg_connection",
    "get_confirm_mode",
    "set_confirm_mode",
    "get_whitelist_config",
    "get_whitelist_rules",
    "set_whitelist_file",
    "check_whitelist_targets",
]

PLANNED_USG_TOOLS = [
    "usg_connection_status",
    "usg_get_blacklist",
    "usg_preview_blacklist_add",
    "usg_apply_blacklist_add",
    "usg_whitelist_check",
    "usg_whitelist_reload",
    "usg_whitelist_list",
    "usg_whitelist_stats",
    "usg_preview_blacklist_unblock",
    "usg_apply_blacklist_unblock",
    "usg_list_actions",
    "usg_get_action_detail",
    "usg_unblock_recent",
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
    "usg_apply_blacklist_add",
    "usg_apply_blacklist_unblock",
    "usg_unblock_recent",
}

BATCH_CONFIRM_ACTIONS = {
    "block_add_attackers",
    "block_delete_attackers",
    "block_add_business",
    "block_delete_temp",
    "block_delete_business",
    "usg_unblock_recent",
}

ALWAYS_CONFIRM_ACTIONS.update({
    "usg_unblock_recent",
})