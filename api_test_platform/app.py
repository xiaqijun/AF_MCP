from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "ip-ban-api.md"


@dataclass(slots=True)
class ApiParameter:
    name: str
    location: str
    required: bool
    description: str


@dataclass(slots=True)
class ApiEndpoint:
    category: str
    method: str
    path: str
    title: str
    summary: str
    section: str
    query_parameters: list[ApiParameter] = field(default_factory=list)
    body_schema: list[ApiParameter] = field(default_factory=list)
    request_example: str = ""
    response_example: str = ""


class SimulationRequest(BaseModel):
    path: str = Field(min_length=1)
    method: str = Field(min_length=1)
    namespace: str = Field(default="public")
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


def _normalize_text(value: str) -> str:
    return value.strip().replace("\u3000", " ")


def _read_doc() -> str:
    return DOC_PATH.read_text(encoding="utf-8")


def _parse_overview(markdown_text: str) -> list[ApiEndpoint]:
    lines = markdown_text.splitlines()
    endpoints: list[ApiEndpoint] = []
    in_table = False
    for line in lines:
        stripped = line.strip()
        if stripped == "| 分类 | 方法 | 路径 | 说明 |":
            in_table = True
            continue
        if not in_table:
            continue
        if stripped.startswith("| ---"):
            continue
        if not stripped.startswith("|"):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 4:
            continue
        category, method, path, summary = cells
        endpoints.append(
            ApiEndpoint(
                category=category,
                method=method.upper(),
                path=path,
                title=summary,
                summary=summary,
                section="",
            )
        )
    return endpoints


def _extract_table(lines: list[str], start_index: int) -> tuple[list[ApiParameter], int]:
    parameters: list[ApiParameter] = []
    index = start_index
    while index < len(lines) and not lines[index].strip().startswith("|"):
        index += 1
    if index >= len(lines):
        return parameters, index
    header = lines[index].strip()
    if not header.startswith("|"):
        return parameters, index
    index += 2
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("|"):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) == 4:
            location, name, required, description = cells
        elif len(cells) == 3:
            name, required, description = cells
            location = "Body"
        else:
            index += 1
            continue
        parameters.append(
            ApiParameter(
                name=name,
                location=location,
                required=required == "是",
                description=description,
            )
        )
        index += 1
    return parameters, index


def _extract_code_block(lines: list[str], start_index: int) -> tuple[str, int]:
    index = start_index
    while index < len(lines) and not lines[index].strip().startswith("```"):
        index += 1
    if index >= len(lines):
        return "", index
    fence = lines[index].strip()
    index += 1
    block_lines: list[str] = []
    while index < len(lines) and lines[index].strip() != "```":
        block_lines.append(lines[index])
        index += 1
    if index < len(lines) and lines[index].strip() == "```":
        index += 1
    if fence in {"```json", "```http"}:
        return "\n".join(block_lines).strip(), index
    return "", index


def _apply_detail_sections(markdown_text: str, endpoints: list[ApiEndpoint]) -> list[ApiEndpoint]:
    endpoint_map = {(item.method, item.path): item for item in endpoints}
    lines = markdown_text.splitlines()
    index = 0
    current_section = ""
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith("## "):
            current_section = line.removeprefix("## ").strip()
        if line.startswith("### "):
            title = line.removeprefix("### ").strip()
            method = ""
            path = ""
            summary = ""
            query_parameters: list[ApiParameter] = []
            body_schema: list[ApiParameter] = []
            request_example = ""
            response_example = ""
            cursor = index + 1
            while cursor < len(lines):
                stripped = lines[cursor].strip()
                if stripped.startswith("### ") or stripped.startswith("## "):
                    break
                if stripped.startswith("- 方法："):
                    method = stripped.removeprefix("- 方法：").strip().upper()
                elif stripped.startswith("- 路径："):
                    path = stripped.removeprefix("- 路径：").strip()
                elif stripped.startswith("- 说明："):
                    summary = stripped.removeprefix("- 说明：").strip()
                elif stripped in {"请求参数：", "查询参数："}:
                    query_parameters, cursor = _extract_table(lines, cursor + 1)
                    continue
                elif stripped == "请求字段：":
                  body_schema, cursor = _extract_table(lines, cursor + 1)
                  continue
                elif stripped == "字段说明：":
                    body_schema, cursor = _extract_table(lines, cursor + 1)
                    continue
                elif stripped.startswith("请求体：") or stripped.startswith("请求体示例：") or stripped.startswith("示例请求体："):
                    request_example, cursor = _extract_code_block(lines, cursor + 1)
                    continue
                elif stripped.startswith("示例返回："):
                    response_example, cursor = _extract_code_block(lines, cursor + 1)
                    continue
                cursor += 1
            if method and path and (method, path) in endpoint_map:
                endpoint = endpoint_map[(method, path)]
                endpoint.title = title
                endpoint.summary = summary or endpoint.summary
                endpoint.section = current_section
                endpoint.query_parameters = query_parameters
                endpoint.body_schema = body_schema
                endpoint.request_example = request_example
                endpoint.response_example = response_example
            index = cursor
            continue
        index += 1
    return endpoints


def load_catalog() -> list[ApiEndpoint]:
    markdown_text = _read_doc()
    endpoints = _parse_overview(markdown_text)
    return _apply_detail_sections(markdown_text, endpoints)


def _render_html(catalog: list[ApiEndpoint]) -> str:
    serialized = json.dumps([asdict(item) for item in catalog], ensure_ascii=False)
    return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AF API 模拟平台</title>
  <style>
    :root {{
      --bg: #f4efe7;
      --panel: #fffaf4;
      --border: #d8c7b5;
      --text: #2b2118;
      --muted: #6f5b49;
      --accent: #0e7490;
      --accent-soft: #d7eef4;
      --danger: #9f1239;
      --code: #efe7dc;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Microsoft YaHei", "PingFang SC", sans-serif; background: radial-gradient(circle at top left, #fff7ed 0, var(--bg) 45%, #efe5d7 100%); color: var(--text); }}
    .layout {{ display: grid; grid-template-columns: 360px 1fr; min-height: 100vh; }}
    .sidebar {{ border-right: 1px solid var(--border); background: rgba(255,250,244,0.92); backdrop-filter: blur(16px); padding: 24px; position: sticky; top: 0; height: 100vh; overflow: auto; }}
    .main {{ padding: 24px 28px 48px; }}
    h1, h2, h3 {{ margin: 0; }}
    .headline {{ display: grid; gap: 10px; margin-bottom: 18px; }}
    .headline p {{ margin: 0; color: var(--muted); line-height: 1.6; }}
    .base-form, .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 18px; padding: 18px; box-shadow: 0 10px 30px rgba(43,33,24,0.06); }}
    .base-form {{ display: grid; gap: 12px; margin-bottom: 18px; }}
    .field-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    label {{ font-size: 13px; color: var(--muted); display: grid; gap: 6px; }}
    input, textarea, select {{ width: 100%; border: 1px solid var(--border); border-radius: 12px; background: white; padding: 10px 12px; font: inherit; color: var(--text); }}
    textarea {{ min-height: 120px; resize: vertical; }}
    .catalog {{ display: grid; gap: 10px; }}
    .endpoint-button {{ border: 1px solid var(--border); border-radius: 14px; background: white; padding: 12px; text-align: left; cursor: pointer; transition: 160ms ease; }}
    .endpoint-button:hover, .endpoint-button.active {{ border-color: var(--accent); background: var(--accent-soft); transform: translateY(-1px); }}
    .method {{ display: inline-flex; min-width: 58px; justify-content: center; padding: 2px 8px; border-radius: 999px; font-size: 12px; color: white; margin-right: 8px; }}
    .GET {{ background: #15803d; }}
    .POST {{ background: #2563eb; }}
    .PATCH {{ background: #b45309; }}
    .PUT {{ background: #7c3aed; }}
    .DELETE {{ background: #be123c; }}
    .detail-grid {{ display: grid; gap: 18px; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; color: var(--muted); }}
    .path {{ font-family: Consolas, monospace; background: var(--code); padding: 6px 10px; border-radius: 999px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid var(--border); text-align: left; padding: 10px 8px; vertical-align: top; }}
    pre {{ background: var(--code); border-radius: 14px; padding: 14px; overflow: auto; white-space: pre-wrap; word-break: break-word; }}
    .actions {{ display: flex; gap: 10px; align-items: center; }}
    button.primary {{ border: 0; background: var(--accent); color: white; padding: 12px 18px; border-radius: 12px; cursor: pointer; font: inherit; }}
    .response-status.ok {{ color: #166534; }}
    .response-status.error {{ color: var(--danger); }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 980px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--border); }}
      .field-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="headline">
        <h1>AF API 模拟平台</h1>
        <p>从 Markdown 文档自动提取接口清单，不访问真实 AF，仅在本地模拟接口响应，适合前期联调和字段演练。</p>
      </div>
      <form class="base-form" id="base-form">
        <div class="field-grid">
          <label>命名空间
            <input id="namespace" value="public" />
          </label>
          <label>模拟模式
            <input value="mock-response" disabled />
          </label>
        </div>
        <label>额外请求头 JSON
          <textarea id="headers-json">{{}}</textarea>
        </label>
        <label>Cookie JSON
          <textarea id="cookies-json">{{}}</textarea>
        </label>
      </form>
      <div class="catalog" id="catalog"></div>
    </aside>
    <main class="main">
      <div class="detail-grid">
        <section class="panel">
          <div class="headline">
            <h2 id="endpoint-title">请选择一个接口</h2>
            <p id="endpoint-summary" class="muted">左侧点击接口后，这里会显示接口说明、参数和请求结果。</p>
          </div>
          <div class="meta">
            <span class="method" id="endpoint-method">GET</span>
            <span class="path" id="endpoint-path">/api/v1/namespaces/@namespace/login</span>
            <span id="endpoint-section" class="muted"></span>
          </div>
        </section>

        <section class="panel">
          <h3>参数说明</h3>
          <div id="parameter-tables"></div>
        </section>

        <section class="panel">
          <h3>请求构造</h3>
          <div class="field-grid">
            <label>Query 参数 JSON
              <textarea id="query-json">{{}}</textarea>
            </label>
            <label>请求体 JSON
              <textarea id="body-json"></textarea>
            </label>
          </div>
          <div class="actions">
            <button class="primary" id="send-request" type="button">发送请求</button>
            <span id="response-status" class="response-status muted"></span>
          </div>
        </section>

        <section class="panel">
          <h3>文档示例</h3>
          <div class="field-grid">
            <div>
              <p class="muted">请求示例</p>
              <pre id="request-example">无</pre>
            </div>
            <div>
              <p class="muted">响应示例</p>
              <pre id="response-example">无</pre>
            </div>
          </div>
        </section>

        <section class="panel">
          <h3>模拟响应</h3>
          <pre id="live-response">尚未发送请求。</pre>
        </section>
      </div>
    </main>
  </div>
  <script>
    const catalog = {serialized};
    const catalogElement = document.getElementById('catalog');
    const titleElement = document.getElementById('endpoint-title');
    const summaryElement = document.getElementById('endpoint-summary');
    const methodElement = document.getElementById('endpoint-method');
    const pathElement = document.getElementById('endpoint-path');
    const sectionElement = document.getElementById('endpoint-section');
    const parameterTablesElement = document.getElementById('parameter-tables');
    const requestExampleElement = document.getElementById('request-example');
    const responseExampleElement = document.getElementById('response-example');
    const queryJsonElement = document.getElementById('query-json');
    const bodyJsonElement = document.getElementById('body-json');
    const liveResponseElement = document.getElementById('live-response');
    const responseStatusElement = document.getElementById('response-status');
    const sendButton = document.getElementById('send-request');
    let selectedEndpoint = null;

    function renderParameterTable(title, items) {{
      if (!items || items.length === 0) {{
        return `<p class="muted">${{title}}：无</p>`;
      }}
      const rows = items.map(item => `
        <tr>
          <td>${{item.location}}</td>
          <td>${{item.name}}</td>
          <td>${{item.required ? '是' : '否'}}</td>
          <td>${{item.description || ''}}</td>
        </tr>
      `).join('');
      return `
        <div>
          <p class="muted">${{title}}</p>
          <table>
            <thead>
              <tr><th>位置</th><th>参数</th><th>必选</th><th>说明</th></tr>
            </thead>
            <tbody>${{rows}}</tbody>
          </table>
        </div>
      `;
    }}

    function selectEndpoint(endpoint, button) {{
      selectedEndpoint = endpoint;
      document.querySelectorAll('.endpoint-button').forEach(node => node.classList.remove('active'));
      if (button) {{
        button.classList.add('active');
      }}
      titleElement.textContent = endpoint.title;
      summaryElement.textContent = endpoint.summary || '文档未提供额外说明。';
      methodElement.textContent = endpoint.method;
      methodElement.className = `method ${{endpoint.method}}`;
      pathElement.textContent = endpoint.path;
      sectionElement.textContent = endpoint.section || endpoint.category;
      parameterTablesElement.innerHTML = renderParameterTable('Query / 路径参数', endpoint.query_parameters) + renderParameterTable('请求体字段', endpoint.body_schema);
      requestExampleElement.textContent = endpoint.request_example || '无';
      responseExampleElement.textContent = endpoint.response_example || '无';
      queryJsonElement.value = endpoint.query_parameters.length ? JSON.stringify(Object.fromEntries(endpoint.query_parameters.map(item => [item.name, ''])), null, 2) : '{{}}';
      bodyJsonElement.value = endpoint.request_example || '';
      liveResponseElement.textContent = '尚未发送请求。';
      responseStatusElement.textContent = '';
      responseStatusElement.className = 'response-status muted';
    }}

    function buildCatalog() {{
      catalog.forEach((endpoint, index) => {{
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'endpoint-button';
        button.innerHTML = `<div><span class="method ${{endpoint.method}}">${{endpoint.method}}</span>${{endpoint.title}}</div><div class="muted">${{endpoint.path}}</div>`;
        button.addEventListener('click', () => selectEndpoint(endpoint, button));
        catalogElement.appendChild(button);
        if (index === 0) {{
          selectEndpoint(endpoint, button);
        }}
      }});
    }}

    async function sendRequest() {{
      if (!selectedEndpoint) {{
        return;
      }}
      responseStatusElement.textContent = '模拟执行中...';
      responseStatusElement.className = 'response-status muted';
      try {{
        const payload = {{
          namespace: document.getElementById('namespace').value,
          method: selectedEndpoint.method,
          path: selectedEndpoint.path,
          headers: JSON.parse(document.getElementById('headers-json').value || '{{}}'),
          cookies: JSON.parse(document.getElementById('cookies-json').value || '{{}}'),
          query: JSON.parse(queryJsonElement.value || '{{}}'),
          body: bodyJsonElement.value.trim() || null,
        }};
        const response = await fetch('/simulate', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload),
        }});
        const data = await response.json();
        liveResponseElement.textContent = JSON.stringify(data, null, 2);
        responseStatusElement.textContent = `${{data.status_code || response.status}} ${{data.reason || ''}}`.trim();
        responseStatusElement.className = response.ok ? 'response-status ok' : 'response-status error';
      }} catch (error) {{
        liveResponseElement.textContent = String(error);
        responseStatusElement.textContent = '模拟失败';
        responseStatusElement.className = 'response-status error';
      }}
    }}

    sendButton.addEventListener('click', sendRequest);
    buildCatalog();
  </script>
</body>
</html>
"""


def _replace_namespace(path: str, namespace: str) -> str:
    return path.replace("@namespace", namespace)


def _parse_body(raw_body: str | None) -> Any:
    if raw_body is None or not raw_body.strip():
        return None
    return json.loads(raw_body)


def _parse_json_example(raw_text: str) -> Any:
  if not raw_text.strip():
    return None
  try:
    return json.loads(raw_text)
  except json.JSONDecodeError:
    return raw_text


def _find_endpoint(catalog: list[ApiEndpoint], method: str, path: str) -> ApiEndpoint | None:
  for endpoint in catalog:
    if endpoint.method == method.upper() and endpoint.path == path:
      return endpoint
  return None


def _validate_required_parameters(endpoint: ApiEndpoint, query: dict[str, Any], body: Any) -> list[str]:
  missing: list[str] = []
  for parameter in endpoint.query_parameters:
    if parameter.required and query.get(parameter.name) in (None, ""):
      missing.append(f"query.{parameter.name}")

  if not endpoint.body_schema:
    return missing

  if not isinstance(body, dict):
    required_fields = [parameter.name for parameter in endpoint.body_schema if parameter.required]
    return missing + [f"body.{field}" for field in required_fields]

  for parameter in endpoint.body_schema:
    if parameter.required and body.get(parameter.name) in (None, ""):
      missing.append(f"body.{parameter.name}")
  return missing


def _mock_login_response(response_body: dict[str, Any], body: Any, namespace: str) -> dict[str, Any]:
  payload = response_body.copy()
  data = dict(payload.get("data") or {})
  login_result = dict(data.get("loginResult") or {})
  username = body.get("name") if isinstance(body, dict) else None
  if username:
    data["name"] = username
  data["namespace"] = namespace
  login_result["token"] = f"MOCK-TOKEN-{namespace.upper()}"
  data["loginResult"] = login_result
  payload["data"] = data
  return payload


def _mock_exception_record() -> dict[str, Any]:
  return {
    "description": "",
    "ipAddr": {"start": "192.168.1.1"},
    "enable": True,
    "ipName": "test",
    "addTime": "test",
  }


def _mock_block_record() -> dict[str, Any]:
  return {
    "dstIP": "192.168.1.1",
    "srcBussinessName": "test",
    "dstPort": 0,
    "policyId": 0,
    "policy": "test",
    "deblockTime": 0,
    "blockType": "SRC",
    "attack": "PHISHING_EMAIL",
    "blockAddr": "test",
    "enableLog": True,
    "dns": "test",
    "url": "test",
    "module": "test",
    "blockTime": "1949-10-01 10:00:00",
    "scope": "BUSINESS",
    "dstBussinessName": "test",
    "srcIP": "192.168.1.1",
  }


def _mock_attacker_list_record() -> dict[str, Any]:
  return {
    "attack": "NULL",
    "blockTimeLen": 4320,
    "blockScope": "global",
    "blockAddr": "192.168.1.1",
    "dstIP": "0.0.0.0",
    "blockType": "src_ip",
    "enableLog": False,
    "dstPort": 0,
    "module": "手动添加规则",
    "blockTime": "2020-11-25 15:54:05",
    "policy": "",
    "deblockTime": "71:59:53",
    "srcIP": "192.168.1.1",
  }


def _mock_paginated(items: list[dict[str, Any]], page_size: int = 200, page_number: int = 1) -> dict[str, Any]:
  return {
    "totalItems": len(items),
    "itemsOffset": 0,
    "itemLength": len(items),
    "pageSize": page_size,
    "items": items,
    "totalPages": 1,
    "pageNumber": page_number,
  }


def _build_mock_body(endpoint: ApiEndpoint, namespace: str, query: dict[str, Any], body: Any) -> Any:
  parsed_example = _parse_json_example(endpoint.response_example)
  if isinstance(parsed_example, dict):
    if endpoint.path.endswith("/login"):
      return _mock_login_response(parsed_example, body, namespace)
    return parsed_example

  if endpoint.method == "GET" and endpoint.path == "/api/v1/namespaces/@namespace/blockip/excludeblockip":
    return {
      "code": 0,
      "message": "",
      "data": _mock_paginated([_mock_exception_record()]),
    }

  if endpoint.path == "/api/batch/v1/namespaces/@namespace/blockip/excludeblockips" and endpoint.method == "POST":
    return {"code": 0, "message": "", "data": body if isinstance(body, list) else [_mock_exception_record()]}

  if endpoint.path == "/api/batch/v1/namespaces/@namespace/blockip/excludeblockip?_method=delete" and endpoint.method == "POST":
    return {"code": 0, "message": "", "data": body if isinstance(body, list) else [_mock_exception_record()]}

  if endpoint.path == "/api/batch/v1/namespaces/@namespace/blockip/excludeblockip" and endpoint.method == "PATCH":
    return {"code": 0, "message": "", "data": body if isinstance(body, list) else [_mock_exception_record()]}

  if endpoint.path == "/api/v1/namespaces/@namespace/blockip/excludeblockip" and endpoint.method == "PATCH":
    return {"code": 0, "message": "", "data": body if isinstance(body, dict) else _mock_exception_record()}

  if endpoint.method == "GET" and endpoint.path == "/api/v1/namespaces/@namespace/blockip":
    return {
      "code": 0,
      "message": "成功",
      "data": _mock_paginated([_mock_attacker_list_record()], page_size=100),
    }

  if endpoint.method == "POST" and endpoint.path == "/api/batch/v1/namespaces/@namespace/blockip":
    payload = body if isinstance(body, dict) else {}
    payload.setdefault("ipType", "SRC")
    payload.setdefault("blockTime", "3d")
    payload.setdefault("srcIP", ["192.168.1.2", "192.168.1.3"])
    payload.setdefault("conflictNum", 0)
    payload.setdefault("conflictItem", [])
    return {"code": 0, "message": "成功", "data": payload}

  if endpoint.method == "POST" and endpoint.path == "/api/batch/v1/namespaces/@namespace/blockip?_method=delete":
    return {"code": 0, "message": "成功", "data": body if isinstance(body, list) else [_mock_attacker_list_record()]}

  generic_data: dict[str, Any] = {
    "mock": True,
    "title": endpoint.title,
    "namespace": namespace,
    "query": query,
    "body": body,
  }
  if endpoint.method == "GET" and "blocktotalcnt" in endpoint.path:
    generic_data = {"cnt": 3}
  elif endpoint.method == "GET" and "blockiptime" in endpoint.path:
    generic_data = {"blockTime": "1d", "bruteBlockTime": "1d", "minutes": 1440}
  elif endpoint.method == "GET" and endpoint.path in {
    "/api/v1/namespaces/@namespace/wrapper/blockip",
    "/api/v1/namespaces/@namespace/bizblockip",
  }:
    generic_data = _mock_paginated([_mock_block_record()])
  elif endpoint.method == "DELETE" and endpoint.path in {
    "/api/v1/namespaces/@namespace/blockipclear",
    "/api/v1/namespaces/@namespace/blockbizipclear",
    "/api/v1/namespaces/@namespace/wrapper/blockipclear",
  }:
    generic_data = [_mock_block_record()]
  elif endpoint.method == "POST" and endpoint.path in {
    "/api/batch/v1/namespaces/@namespace/bizblockip",
    "/api/batch/v1/namespaces/@namespace/bizblockip?_method=delete",
    "/api/v1/namespaces/@namespace/wrapper/blockip?_method=delete",
  }:
    generic_data = body if body is not None else [_mock_block_record()]

  return {
    "code": 0,
    "message": "模拟成功",
    "data": generic_data,
  }


def simulate_request(catalog: list[ApiEndpoint], request: SimulationRequest) -> dict[str, Any]:
  endpoint = _find_endpoint(catalog, request.method, request.path)
  if endpoint is None:
    return {
      "simulated": True,
      "status_code": 404,
      "reason": "Mock Endpoint Not Found",
      "body": {
        "code": 404,
        "message": "文档中未找到该接口定义",
        "data": {
          "method": request.method.upper(),
          "path": request.path,
        },
      },
    }

  body = _parse_body(request.body)
  missing = _validate_required_parameters(endpoint, request.query, body)
  resolved_path = _replace_namespace(request.path, request.namespace)
  if missing:
    return {
      "simulated": True,
      "status_code": 400,
      "reason": "Mock Validation Failed",
      "body": {
        "code": 400,
        "message": "缺少必填参数",
        "data": {
          "missing": missing,
          "resolvedPath": resolved_path,
        },
      },
    }

  return {
    "simulated": True,
    "status_code": 200,
    "reason": "Mock OK",
    "body": _build_mock_body(endpoint, request.namespace, request.query, body),
    "request_echo": {
      "method": request.method.upper(),
      "resolvedPath": resolved_path,
      "query": request.query,
      "headers": request.headers,
      "cookies": request.cookies,
      "body": body,
    },
  }


def create_app() -> FastAPI:
  app = FastAPI(title="AF API 模拟平台", version="0.1.0")
  catalog = load_catalog()

  @app.get("/", response_class=HTMLResponse)
  async def index() -> str:
    return _render_html(catalog)

  @app.get("/catalog")
  async def get_catalog() -> list[dict[str, Any]]:
    return [asdict(item) for item in catalog]

  @app.post("/simulate")
  async def simulate(request: SimulationRequest) -> dict[str, Any]:
    try:
      return simulate_request(catalog, request)
    except json.JSONDecodeError as error:
      raise HTTPException(status_code=400, detail=f"请求体不是合法 JSON: {error}") from error

  return app


app = create_app()