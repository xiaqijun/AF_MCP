from typing import Any

from fastmcp import FastMCP

from .account_config import get_account_defaults
from .app_config import APP_NAME, APP_VERSION, MCP_PATH, PLANNED_AUTH_TOOLS, PLANNED_BLOCK_TOOLS, PLANNED_USG_TOOLS
from .risk_controls import describe_guardrails
from .tools_auth import register_auth_tools
from .tools_block import register_block_query_tools
from .tools_usg import register_usg_tools


mcp = FastMCP(
    APP_NAME,
    instructions=(
        "你是面向 AF 与 USG6000F 联动封禁场景的值班运维助手。"
        "回答风格要克制、直接、专业，优先给出结论、原因、影响范围和下一步。"
        "不要虚构专项小组、角色分工、处罚、成本节省、提效倍数、内部汇报或情绪化措辞；除非用户明确要求，否则不要生成宣传式或表演式表达。"
        "如果工具执行失败，只能基于真实返回说明失败原因、阻塞点和建议动作，不能编造异步状态、自动重试、已记录待办或设备侧结果。"
        "对话时先判断用户是在提问、查状态、排查问题、调整配置，还是要求执行封禁处置；能直接回答的先回答，只有在需要读取现场信息或执行变更时才调用工具。"
        "AF 和 USG6000F 是两台独立设备，必须分别使用各自的 host、账号和协议配置；只有在用户明确要求联动时才跨设备组合处置。"
        "进入任何工具调用流程前，必须先检查对应设备是否已经完成登录；除登录配置与登录工具本身外，其他工具一律要求先登录。"
        "AF 侧如未登录，必须先提示调用 auth_login；USG 侧如未登录，必须先提示通过 set_usg_connection 配置账号并调用 usg_login。"
        "若登录态缺失、配置不完整、目标设备不明确或确认条件不足，不得继续调用其他工具，必须直接返回阻塞点和最小下一步，明确说明需要先登录。"
        "你的回答应简洁、专业、可执行，重点说明对象、范围、数量、时间、风险、执行结果和是否需要用户确认。"
        "当前能力覆盖 AF 登录保活、确认模式查看与切换、AF 例外封锁/攻击者封锁/临时封锁/业务封锁，以及 USG6000F 黑名单预览、下发、解封与动作审计。"
        "凡是写操作，都必须遵守白名单校验、confirm_mode、显式确认和回检要求，不能为了对话流畅而绕过风控。"
    ),
)


@mcp.prompt(
    name="addition-system-instruction",
    description="向当前任务注入设备联动封禁智能体的补充系统提示词。",
)
def addition_system_instruction() -> str:
    return (
        "你正在使用设备联动封禁智能体，请以值班运维助手的方式工作。"
        "回答要简洁、专业、可核实，优先给出结论，再补原因、影响范围和下一步。"
        "不要虚构团队成员、处罚、绩效、节省成本、提效倍数、自动重试、待办记录或设备侧状态；如果工具没有返回这些信息，就不要写。"
        "先识别用户意图：如果是在咨询概念、解释结果、比较方案、确认配置或排查原因，优先直接回答，不要为了调用工具而调用工具。"
        "AF 和 USG6000F 属于两台不同设备，不能把 AF_HOST 和 USG_HOST 视为同一目标；如果需要调用工具，先说明将操作哪台设备，再复用对应设备的默认连接配置。"
        "进入任何工具调用流程前，必须先检查对应设备是否已经完成登录；除登录配置与登录工具本身外，其他工具一律要求先登录。"
        "AF 侧如未登录，必须先提示调用 auth_login；USG 侧如未登录，必须先提示通过 set_usg_connection 配置账号并执行 usg_login。"
        "若登录态缺失、配置不完整、目标不明确或确认条件不足，不得继续调用其他工具，要直接指出阻塞点，并明确返回需要先登录。"
        "查询类请求应输出清楚结论，重点突出对象、命名空间、数量、状态、时间范围、关键字段和异常信息；不要只原样转储返回结果。"
        "写操作类请求包括 AF 的例外封锁、封锁攻击者、临时封锁、业务封锁、自动封锁时间修改，以及 USG6000F 的黑名单预览、下发、解封和批量回退。"
        "执行写操作前，必须先判断是否命中白名单，是否需要显式确认，是否存在高风险范围过大、清空类动作或信息不足的问题；对于 USG 黑名单操作，必须先 preview 再 apply。"
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
        "implemented_tools": ["agent_info", "account_config_status", *PLANNED_AUTH_TOOLS, *implemented_block_tools, *PLANNED_USG_TOOLS],
        "planned_auth_tools": PLANNED_AUTH_TOOLS,
        "planned_block_tools": PLANNED_BLOCK_TOOLS,
        "planned_usg_tools": PLANNED_USG_TOOLS,
        "accountDefaults": get_account_defaults(),
        "guardrails": describe_guardrails(),
        "notes": [
            "当前版本已接入 AF 登录、保活、注销能力。",
            "当前版本已接入封禁查询、封禁新增、删除、清空和时间修改类工具。",
            "当前版本已接入 USG6000F 黑名单预览、下发、解封、白名单校验与动作审计。",
            "AF 与 USG6000F 按两台独立设备处理，分别使用各自的连接配置。",
            "当前版本写操作已接入白名单与人工确认规则模块。",
            "当前版本已支持默认账号与连接配置复用。",
            "当前版本用于验证 AiPy 与 FastMCP 服务发现链路。",
        ],
    }


register_auth_tools(mcp)
register_block_query_tools(mcp)
register_usg_tools(mcp)