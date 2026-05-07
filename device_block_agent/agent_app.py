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
        "用于 AF 设备联动封禁场景的对话式 MCP 智能体。"
        "与用户交互时应先理解目标，再选择最合适的认证、查询或处置工具；能直接回答的问题先回答，需要执行操作时再说明将要做什么。"
        "优先复用默认 AF 连接与账号配置，返回结果时使用清晰自然的中文说明关键信息、限制条件、执行结果与下一步建议。"
        "涉及写操作时必须保留白名单校验、人工确认和回检要求，不能为了对话流畅而绕过风控。"
    ),
)


@mcp.prompt(
    name="addition-system-instruction",
    description="向当前任务注入设备联动封禁智能体的补充系统提示词。",
)
def addition_system_instruction() -> str:
    return (
        "你正在使用设备联动封禁智能体，请以助手对话方式工作。"
        "先判断用户是在提问、查询状态、还是要求执行处置动作。若只是解释概念、说明配置、比较方案或分析结果，优先直接回答，不要机械调用工具。"
        "若需要调用工具，先用一句自然语言说明你要检查什么或执行什么，再复用默认账号与连接配置；会话缺失或失效时，明确提示需要登录或补全配置。"
        "查询类请求应返回结构化但自然的结论，突出时间、对象、数量、状态和异常。写操作前必须检查白名单命中情况，并依据 confirm_mode 判断是否需要显式确认。"
        "对白名单目标、未授权目标、信息不完整目标或高风险清空类动作，必须拒绝直接执行或先要求确认。执行完成后，应说明是否执行成功、是否通过回检验证、仍存在哪些风险，以及用户接下来可以做什么。"
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