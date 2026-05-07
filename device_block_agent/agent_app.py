from typing import Any

from fastmcp import FastMCP

from .account_config import get_account_defaults
from .app_config import APP_NAME, APP_VERSION, MCP_PATH, PLANNED_AUTH_TOOLS, PLANNED_BLOCK_TOOLS
from .risk_controls import describe_guardrails
from .tools_auth import register_auth_tools
from .tools_block import register_block_query_tools


mcp = FastMCP(
    APP_NAME,
    instructions=(
        "你是用于 AF 设备联动封禁场景的对话式运维助手。"
        "对话时先判断用户是在提问、查状态、排查问题、调整配置，还是要求执行封禁处置；能直接回答的先回答，只有在需要读取现场信息或执行变更时才调用工具。"
        "优先复用默认 AF 连接、命名空间与账号配置；若缺少登录态、连接参数或必要上下文，要明确指出缺什么，并给出下一步。"
        "你的回答应简洁、专业、可执行，重点说明对象、范围、数量、时间、风险、执行结果和是否需要用户确认。"
        "当前能力覆盖登录保活、确认模式查看与切换、例外封锁、封锁攻击者、临时封锁、业务封锁、封锁总量与自动封锁时间。"
        "凡是写操作，都必须遵守白名单校验、confirm_mode、显式确认和回检要求，不能为了对话流畅而绕过风控。"
    ),
)


@mcp.prompt(
    name="addition-system-instruction",
    description="向当前任务注入设备联动封禁智能体的补充系统提示词。",
)
def addition_system_instruction() -> str:
    return (
        "你正在使用设备联动封禁智能体，请以专业运维助手的方式工作。"
        "先识别用户意图：如果是在咨询概念、解释结果、比较方案、确认配置或排查原因，优先直接回答，不要为了调用工具而调用工具。"
        "如果需要调用工具，先用一句自然中文说明你将要检查什么或执行什么，再尽量复用默认 host、namespace、账号和已有会话；若登录态缺失、配置不完整或目标不明确，要直接指出阻塞点。"
        "查询类请求应输出清楚结论，重点突出对象、命名空间、数量、状态、时间范围、关键字段和异常信息；不要只原样转储返回结果。"
        "写操作类请求包括例外封锁增删改、封锁攻击者增删清空、临时封锁删除清空、业务封锁增删清空、自动封锁时间修改，以及确认模式切换。"
        "执行写操作前，必须先判断是否命中白名单，是否需要显式确认，是否存在高风险范围过大、清空类动作或信息不足的问题。"
        "对白名单目标、未授权目标、信息不完整目标、目标范围过大、清空类动作或需要人工确认但尚未确认的请求，不得直接执行。"
        "执行完成后，应明确说明：是否成功、影响了哪些对象、是否通过回检、还有哪些残余风险、用户下一步可以做什么。"
    )


@mcp.tool(
    name="agent_info",
    description="返回当前智能体脚手架状态、传输方式和已规划工具范围。",
)
def agent_info() -> dict[str, Any]:
    implemented_block_tools = PLANNED_BLOCK_TOOLS
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "mvp-implementation",
        "transport": "streamable-http",
        "path": MCP_PATH,
        "implemented_tools": ["agent_info", "account_config_status", *PLANNED_AUTH_TOOLS, *implemented_block_tools],
        "planned_auth_tools": PLANNED_AUTH_TOOLS,
        "planned_block_tools": PLANNED_BLOCK_TOOLS,
        "accountDefaults": get_account_defaults(),
        "guardrails": describe_guardrails(),
        "notes": [
            "当前版本已接入 AF 登录、保活、注销能力。",
            "当前版本已接入封禁查询、封禁新增、删除、清空和时间修改类工具。",
            "当前版本写操作已接入白名单与人工确认规则模块。",
            "当前版本已支持默认账号与连接配置复用。",
            "当前版本用于验证 AiPy 与 FastMCP 服务发现链路。",
        ],
    }


register_auth_tools(mcp)
register_block_query_tools(mcp)