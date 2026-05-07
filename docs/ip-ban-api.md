# 认证与 IP 封禁相关 API 文档

本文档基于仓库中的 AF8.0.106-API中文文档.pdf 整理，聚焦“认证鉴权”和“IP 封禁”两类接口。

当前已整理的能力包括：

- 例外封锁配置
- 用户登录
- 用户注销
- token 保活
- 封锁攻击者查询与维护
- 临时封锁 IP
- 业务封锁 IP
- 自动封锁时间配置

说明：文中的部分接口在原 PDF 中标注为“虚拟系统不支持该 API”，具体以原始章节说明为准。

## 1. 接口总览

| 分类 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| 认证鉴权 | POST | /api/v1/namespaces/@namespace/login | 用户登录 |
| 认证鉴权 | POST | /api/v1/namespaces/@namespace/logout | 用户注销 |
| 认证鉴权 | GET | /api/v1/namespaces/@namespace/keepalive | token 保活 |
| 例外封锁 | POST | /api/batch/v1/namespaces/@namespace/blockip/excludeblockips | 批量添加例外封锁 |
| 例外封锁 | POST | /api/batch/v1/namespaces/@namespace/blockip/excludeblockip?_method=delete | 批量删除例外封锁 |
| 例外封锁 | PATCH | /api/batch/v1/namespaces/@namespace/blockip/excludeblockip | 批量修改例外封锁 |
| 例外封锁 | GET | /api/v1/namespaces/@namespace/blockip/excludeblockip | 获取所有例外封锁配置 |
| 例外封锁 | PATCH | /api/v1/namespaces/@namespace/blockip/excludeblockip | 修改单项例外 |
| 封锁攻击者 | GET | /api/v1/namespaces/@namespace/blockip | 获取封锁攻击者 IP 列表 |
| 封锁攻击者 | POST | /api/batch/v1/namespaces/@namespace/blockip | 批量添加封锁攻击者 |
| 封锁攻击者 | POST | /api/batch/v1/namespaces/@namespace/blockip?_method=delete | 批量删除封锁攻击者 |
| 封锁攻击者 | DELETE | /api/v1/namespaces/@namespace/blockipclear | 清空封锁攻击者 |
| 自动封锁时间 | PATCH | /api/v1/namespaces/@namespace/blockiptime | 全量修改自动封锁攻击者时间 |
| 自动封锁时间 | GET | /api/v1/namespaces/@namespace/blockiptime | 获取自动封锁攻击者时间 |
| 封锁统计 | GET | /api/v1/namespaces/@namespace/blocktotalcnt | 获取封锁攻击者数量 |
| 临时封锁 IP | GET | /api/v1/namespaces/@namespace/wrapper/blockip | 获取所有临时封锁 IP |
| 业务封锁 IP | GET | /api/v1/namespaces/@namespace/bizblockip | 获取业务封锁 IP |
| 业务封锁 IP | POST | /api/batch/v1/namespaces/@namespace/bizblockip | 添加业务封锁 IP |
| 业务封锁 IP | POST | /api/batch/v1/namespaces/@namespace/bizblockip?_method=delete | 删除业务封锁 IP |
| 临时封锁 IP | POST | /api/v1/namespaces/@namespace/wrapper/blockip?_method=delete | 删除临时封锁 IP |
| 业务封锁 IP | DELETE | /api/v1/namespaces/@namespace/blockbizipclear | 清空业务封锁 IP |
| 临时封锁 IP | DELETE | /api/v1/namespaces/@namespace/wrapper/blockipclear | 清空临时封锁 IP |

## 2. 公共说明

### 2.1 命名空间

所有接口都需要替换路径中的 @namespace，例如：

```http
GET https://{host}/api/v1/namespaces/public/wrapper/blockip
```

### 2.2 通用返回结构

大部分接口返回格式如下：

```json
{
  "code": 0,
  "message": "",
  "data": {}
}
```

其中：

- code：错误码，0 表示成功
- message：错误信息
- data：返回数据，类型依接口不同可能为对象、数组或分页对象

### 2.3 认证流程

根据文档使用说明，标准调用链如下：

1. 调用 login 接口提交账户名和密码。
2. 从返回结果中获取 token。
3. 后续业务接口在 HTTP 请求头中通过 Cookie 携带该 token。
4. 若需要维持登录状态，周期性调用 keepalive。
5. 结束使用时调用 logout 注销登录状态。

文档还说明：若默认 10 分钟没有持续发送 API 请求，则认为用户超时退出，后续请求需要重新认证。

### 2.4 Cookie 头说明

文档在 HTTP 请求头章节明确说明：后续报文必须携带 Cookie 字段，首次请求需要调用登录 API 获取。

示例：

```http
Cookie: token=E1CC915441E1323D1D871713251AE5A88C87CE13142F9D0D9548E7441ADA215
```

### 2.5 常见封锁记录字段

涉及封锁明细列表时，常见字段包括：

| 字段 | 含义 |
| --- | --- |
| blockType | 封锁类型，常见值：SRC、DST、DNS、URL、IP |
| blockAddr | 被封锁地址 |
| srcIP | 源 IP |
| dstIP | 目的 IP |
| dns | 域名 |
| url | URL |
| dstPort | 目的端口 |
| blockTime | 封锁时间 |
| deblockTime | 剩余封锁时间 |
| module | 触发封锁的安全模块 |
| attack | 触发封锁的攻击类型 |
| policyId | 触发封锁的策略 ID |
| policy | 触发封锁的策略名称 |
| enableLog | 是否有日志详情 |
| scope | 封锁范围，常见值：GLOBAL、BUSINESS |

## 3. 例外封锁与封锁攻击者相关接口

### 3.1 批量添加例外封锁

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/blockip/excludeblockips
- 说明：批量添加例外封锁，PDF 标注虚拟系统不支持该 API

请求字段：

| 字段 | 必选 | 说明 |
| --- | --- | --- |
| description | 是 | 例外封锁描述，最长 95 字符 |
| ipAddr.start | 是 | IP 范围起始地址 |
| ipAddr.end | 否 | IP 范围结束地址 |
| ipAddr.bits | 否 | CIDR 掩码简写 |
| ipName | 否 | 例外封锁名称 |
| addTime | 否 | 例外封锁添加时间 |
| enable | 否 | 例外封锁启用状态，默认 true |

请求体示例：

```json
[
  {
    "description": "",
    "ipAddr": {
      "start": "192.168.1.1"
    },
    "enable": true,
    "ipName": "test",
    "addTime": "test"
  }
]
```

示例返回：

```json
{
  "code": 0,
  "message": "",
  "data": [
    {
      "description": "",
      "ipAddr": {
        "start": "192.168.1.1"
      },
      "enable": true,
      "ipName": "test",
      "addTime": "test"
    }
  ]
}
```

### 3.2 批量删除例外封锁

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/blockip/excludeblockip?_method=delete
- 说明：批量删除例外封锁，PDF 标注虚拟系统不支持该 API

请求体与返回体字段与“批量添加例外封锁”一致。

### 3.3 批量修改例外封锁

- 方法：PATCH
- 路径：/api/batch/v1/namespaces/@namespace/blockip/excludeblockip
- 说明：批量修改例外封锁，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| _key | 否 | 目标位置关键字，可选 position 或 name |
| _where | 否 | 指定位置，可选 top、bottom、before、after |
| _dest | 否 | 目标位置关键字对应的值 |

请求体字段与“批量添加例外封锁”一致，返回 data 为例外封锁组数组。

### 3.4 获取所有例外封锁配置

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blockip/excludeblockip
- 说明：获取所有例外封锁配置，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| _sortby | 否 | 指定排序字段 |
| _order | 否 | 排序方式，asc 或 desc |
| _start | 否 | 起始位置，从 0 开始 |
| _select | 否 | 选择字段，多个字段用逗号分隔 |
| _search | 否 | 模糊搜索关键字 |
| _length | 否 | 返回条数，最大 200，默认 100 |

返回结构：

| 字段 | 含义 |
| --- | --- |
| data.totalItems | 总项目数 |
| data.totalPages | 总页数 |
| data.pageNumber | 当前页码 |
| data.pageSize | 每页大小 |
| data.itemsOffset | 当前条目偏移 |
| data.itemLength | 当前页数据条数 |
| data.privateOffset | 内部偏移 |
| data.items[].description | 例外封锁描述 |
| data.items[].ipAddr.start | IP 范围起始地址 |
| data.items[].ipAddr.end | IP 范围结束地址 |
| data.items[].ipAddr.bits | CIDR 掩码简写 |
| data.items[].ipName | 例外封锁名称 |
| data.items[].addTime | 例外封锁添加时间 |
| data.items[].enable | 例外封锁是否启用 |

### 3.5 修改单项例外

- 方法：PATCH
- 路径：/api/v1/namespaces/@namespace/blockip/excludeblockip
- 说明：修改单项例外，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| _key | 否 | 目标位置关键字，可选 position 或 name |
| ipName | 否 | 例外封锁名称 |
| _where | 否 | 指定位置，可选 top、bottom、before、after |
| _dest | 否 | 目标位置关键字对应的值 |

请求体字段与“批量添加例外封锁”一致，返回 data 为单个例外封锁对象。

### 3.6 获取封锁攻击者 IP 列表

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blockip
- 说明：获取封锁攻击者 IP 列表，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF，可选 SIP 或 AF |
| _order | 否 | 排序方式，asc 或 desc |
| _start | 否 | 起始位置，从 0 开始 |
| _length | 否 | 返回条数，最大 200，默认 100 |
| _search | 否 | 模糊搜索关键字 |
| _sortby | 否 | 指定排序字段 |

返回结构：

| 字段 | 含义 |
| --- | --- |
| data.totalItems | 总项目数 |
| data.totalPages | 总页数 |
| data.pageNumber | 当前页码 |
| data.pageSize | 每页大小 |
| data.itemsOffset | 当前条目偏移 |
| data.itemLength | 当前页数据条数 |
| data.items[].blockType | 封锁类型，常见值 SRC、DST、DNS、URL、IP |
| data.items[].blockAddr | 被封锁地址 |
| data.items[].srcIP | 源 IP |
| data.items[].dstIP | 目的 IP |
| data.items[].dns | 域名 |
| data.items[].url | URL |
| data.items[].dstPort | 目的端口 |
| data.items[].blockTime | 封锁时间 |
| data.items[].deblockTime | 剩余封锁时间 |
| data.items[].module | 触发封锁的安全模块 |
| data.items[].attack | 触发封锁的攻击类型 |
| data.items[].policyId | 触发封锁的策略 ID |
| data.items[].policy | 触发封锁的策略名称 |
| data.items[].enableLog | 是否有日志详情 |
| data.items[].scope | 封锁范围，常见值 GLOBAL、BUSINESS |

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "totalItems": 1,
    "itemsOffset": 0,
    "itemLength": 1,
    "pageSize": 100,
    "items": [
      {
        "attack": "NULL",
        "blockTimeLen": 4320,
        "blockScope": "global",
        "blockAddr": "192.168.1.1",
        "dstIP": "0.0.0.0",
        "blockType": "src_ip",
        "enableLog": false,
        "dstPort": 0,
        "module": "手动添加规则",
        "blockTime": "2020-11-25 15:54:05",
        "policy": "",
        "deblockTime": "71:59:53",
        "srcIP": "192.168.1.1"
      }
    ],
    "totalPages": 1,
    "pageNumber": 1
  }
}
```

### 3.7 批量添加封锁攻击者

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/blockip
- 说明：批量添加封锁攻击者，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF，可选 SIP 或 AF |
| aifwType | 否 | 仅 creator=SIP 时生效，默认 MANUAL，可选 AUTO 或 MANUAL |
| override | 否 | 冲突类型，文档给出的枚举值为 PROMPTALL |

请求字段：

| 字段 | 必选 | 说明 |
| --- | --- | --- |
| ipType | 否 | 封锁类型，可选 SRC、DST、DNS、URL，默认 SRC |
| srcIP | 否 | 源 IP 列表，ipType=SRC 时生效 |
| dstIP | 否 | 目的 IP 列表，ipType=DST 时生效 |
| dstPort | 否 | 目的端口 |
| url | 否 | URL 列表 |
| dns | 否 | 域名列表 |
| attack | 否 | 攻击类型 |
| blockTime | 否 | 封锁时长，支持 m/h/d |
| result.blockUrl | 否 | URL |
| result.blockRes | 否 | 封锁结果 |
| result.blockMsg | 否 | 信息 |

返回字段补充：

| 字段 | 含义 |
| --- | --- |
| data.conflictNum | 与全局黑名单或白名单 IP 冲突的数量 |
| data.conflictItem | 与全局黑名单或白名单 IP 冲突的列表 |

请求体示例：

```json
{
  "ipType": "SRC",
  "blockTime": "3d",
  "srcIP": [
    "192.168.1.2",
    "192.168.1.3"
  ]
}
```

### 3.8 批量删除封锁攻击者

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/blockip?_method=delete
- 说明：批量删除封锁攻击者，PDF 标注虚拟系统不支持该 API

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF，可选 SIP 或 AF |

请求字段：

| 字段 | 必选 | 说明 |
| --- | --- | --- |
| srcIP | 否 | 源 IP |
| dstIP | 否 | 目的 IP |
| dstPort | 否 | 目的端口 |
| dns | 否 | 域名 |
| url | 否 | URL |
| attack | 否 | 触发封锁的攻击类型 |
| scope | 否 | 封锁范围，可选 GLOBAL 或 BUSINESS |

示例请求体：

```json
[
  {
    "attack": "PLT-MANUAL",
    "srcIP": "192.168.1.1"
  },
  {
    "attack": "PLT-MANUAL",
    "srcIP": "192.168.1.2"
  },
  {
    "attack": "PLT-MANUAL",
    "srcIP": "192.168.1.3"
  }
]
```

### 3.9 清空封锁攻击者

- 方法：DELETE
- 路径：/api/v1/namespaces/@namespace/blockipclear
- 说明：清空当前命名空间下的封锁攻击者记录，PDF 标注虚拟系统不支持该 API

请求参数：

| 位置 | 参数 | 必选 | 说明 |
| --- | --- | --- | --- |
| Query | creator | 否 | 限制访问身份，默认 AF，可选 SIP 或 AF |

示例：

```http
DELETE https://192.168.1.1/api/v1/namespaces/public/blockipclear
```

返回 data 为被清空的封锁攻击者列表，字段与封锁明细列表类似，包括 blockType、blockAddr、srcIP、dstIP、dns、url、dstPort、blockTime、deblockTime、module、attack、policyId、policy、enableLog、scope 等。

### 3.10 全量修改自动封锁攻击者时间

- 方法：PATCH
- 路径：/api/v1/namespaces/@namespace/blockiptime
- 说明：设置自动封锁攻击者时间，PDF 标注虚拟系统不支持该 API

请求体：

```json
{
  "blockTime": "1d"
}
```

字段说明：

| 字段 | 必选 | 说明 |
| --- | --- | --- |
| blockTime | 否 | 封锁时间，带单位，支持 m/h/d |
| minutes | 否 | 分钟数，自动生成 |
| bruteBlockTime | 否 | 暴力破解封锁时间，单位 d |

### 3.11 获取自动封锁攻击者时间

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blockiptime
- 说明：获取当前自动封锁攻击者时间配置，PDF 标注虚拟系统不支持该 API

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "blockTime": "1d",
    "bruteBlockTime": "1d",
    "minutes": 1440
  }
}
```

### 3.12 获取封锁攻击者数量

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blocktotalcnt
- 说明：返回当前封锁总条数，PDF 标注虚拟系统不支持该 API

示例返回：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "cnt": 0
  }
}
```

## 4. 临时封锁 IP 接口

### 4.1 获取所有临时封锁 IP

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/wrapper/blockip
- 说明：分页查询所有临时封锁 IP

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| _order | 否 | 排序方式，asc 或 desc |
| _start | 否 | 起始位置，从 0 开始 |
| _length | 否 | 返回条数，最大 200，默认 100 |
| _search | 否 | 模糊搜索关键字 |
| _sortby | 否 | 排序字段 |

示例：

```http
GET https://192.168.1.1/api/v1/namespaces/public/wrapper/blockip
```

### 4.2 删除临时封锁 IP

- 方法：POST
- 路径：/api/v1/namespaces/@namespace/wrapper/blockip?_method=delete
- 说明：按明细条件批量删除临时封锁 IP

请求体示例：

```json
[
  {
    "dns": "test",
    "scope": "BUSINESS",
    "srcIP": "192.168.1.1",
    "dstPort": 0,
    "url": "test",
    "attack": "PHISHING_EMAIL",
    "dstIP": "192.168.1.1"
  }
]
```

删除对象支持的关键字段：

- srcIP
- dstIP
- dstPort
- dns
- url
- attack
- scope

### 4.3 清空临时封锁 IP

- 方法：DELETE
- 路径：/api/v1/namespaces/@namespace/wrapper/blockipclear
- 说明：清空当前命名空间下的临时封锁 IP

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF |

## 5. 业务封锁 IP 接口

### 5.1 获取业务封锁 IP

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/bizblockip
- 说明：分页查询业务封锁 IP 列表

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF |
| _order | 否 | 排序方式，asc 或 desc |
| _start | 否 | 起始位置，从 0 开始 |
| _length | 否 | 返回条数，最大 200，默认 100 |
| _search | 否 | 模糊搜索关键字 |
| _sortby | 否 | 排序字段 |

### 5.2 添加业务封锁 IP

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/bizblockip
- 说明：批量添加业务封锁 IP

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF |
| aifwType | 否 | 安全感知平台自动或手动添加，仅 creator=SIP 时生效，默认 MANUAL，可选 AUTO 或 MANUAL |
| override | 否 | 冲突类型，文档中给出的枚举值为 PROMPTALL |

请求体示例：

```json
{
  "blockTime": "3d",
  "srcIP": [
    "192.168.1.1"
  ],
  "result": [
    {
      "blockRes": true,
      "blockUrl": "test",
      "blockMsg": "test"
    }
  ]
}
```

请求体字段：

| 字段 | 必选 | 说明 |
| --- | --- | --- |
| srcIP | 否 | 要封锁的业务 IP 列表 |
| blockTime | 否 | 封锁时长，支持 m/h/d |
| result | 否 | 封锁结果列表 |
| result.blockUrl | 否 | URL |
| result.blockRes | 否 | 封锁结果 |
| result.blockMsg | 否 | 信息 |

### 5.3 删除业务封锁 IP

- 方法：POST
- 路径：/api/batch/v1/namespaces/@namespace/bizblockip?_method=delete
- 说明：按明细条件批量删除业务封锁 IP

请求体示例：

```json
[
  {
    "dns": "test",
    "scope": "BUSINESS",
    "srcIP": "192.168.1.1",
    "dstPort": 0,
    "url": "test",
    "attack": "PHISHING_EMAIL",
    "dstIP": "192.168.1.1"
  }
]
```

删除对象支持字段与临时封锁删除接口一致：

- srcIP
- dstIP
- dstPort
- dns
- url
- attack
- scope

### 5.4 清空业务封锁 IP

- 方法：DELETE
- 路径：/api/v1/namespaces/@namespace/blockbizipclear
- 说明：清空业务封锁 IP

查询参数：

| 参数 | 必选 | 说明 |
| --- | --- | --- |
| creator | 否 | 限制访问身份，默认 AF |

## 6. 推荐调用顺序

如果你的目标是做一套完整的 IP 封禁管理流程，建议按下面顺序使用：

1. 先调用 GET /bizblockip 或 GET /wrapper/blockip 查询现状。
2. 需要新增业务封锁时，调用 POST /api/batch/v1/namespaces/@namespace/bizblockip。
3. 需要删除指定封锁记录时，调用对应的 _method=delete 接口。
4. 需要一次性清空时，调用 blockbizipclear、blockipclear 或 wrapper/blockipclear。
5. 需要调整自动封锁时长时，调用 PATCH /blockiptime。

## 7. 认证鉴权入口

### 7.1 用户登录

- 方法：POST
- 路径：/api/v1/namespaces/@namespace/login
- 说明：管理员账户通过该接口发起登录

请求体示例：

```json
{
  "password": "admin",
  "name": "admin"
}
```

请求字段：

| 字段 | 必选 | 含义 |
| --- | --- | --- |
| name | 是 | 账户名，最短 1 字符，最长 60 字符 |
| password | 是 | 密码，最短 1 字符，最长 512 字符 |

关键返回字段：

| 字段 | 含义 |
| --- | --- |
| data.name | 执行操作的管理员账户名 |
| data.loginResult.token | 登录后得到的会话令牌 |
| data.passwdStatus | 密码状态，是否过期或需要修改 |
| data.authResult | 认证结果，常见值 LOCAL 或 REMOTE |
| data.role | 账户角色 |
| data.cftoken | 防跨站请求伪造的会话令牌 |
| data.namespace | 账号所属系统标识 |

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "loginResult": {
      "token": "3869A36E56525592B3AD88DADD6E87C0F67A3EAA4DFB3C223541EA10E611761"
    },
    "name": "admin",
    "role": "ADMINISTRATOR",
    "passwdStatus": true
  }
}
```

### 7.2 用户注销

- 方法：POST
- 路径：/api/v1/namespaces/@namespace/logout
- 说明：管理员账户通过该接口注销登录状态

请求样例：

```http
POST https://192.168.1.1/api/v1/namespaces/public/logout
```

示例请求体：

```json
{
  "loginResult": {
    "token": "3869A36E56525592B3AD88DADD6E87C0F67A3EAA4DFB3C223541EA10E611761"
  }
}
```

关键返回字段：

| 字段 | 含义 |
| --- | --- |
| data.name | 执行操作的管理员账户名 |
| data.authResult | 认证结果，常见值 LOCAL 或 REMOTE |
| data.cftoken | 防跨站请求伪造的会话令牌 |
| data.namespace | 账号所属系统标识 |

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "name": "admin"
  }
}
```

### 7.3 token 保活

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/keepalive
- 说明：刷新 token 时间戳，保持 token 不超时

返回 data 类型为 int32，常见成功返回值为 0。

示例：

```http
GET https://192.168.1.1/api/v1/namespaces/public/keepalive
```

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": 0
}
```

## 8. 认证相关返回码

从附录中可确认以下与认证直接相关的返回码：

| 返回码 | 含义 |
| --- | --- |
| 1 | 操作不允许，如认证失败 |
| 13 | 缺少对应接口调用权限 |
| 1003 | 未登录 |
| 1010 | 密码过期 |
| 1012 | 登录状态过期 |

## 9. 来源定位

以上内容整理自 AF8.0.106-API中文文档.pdf 的以下章节：

- 1.2 交互流程与报文格式
- 1.3 HTTP请求头格式
- 2.1 用户登录
- 2.2 用户注销
- 2.3 token保活
- 8.3.1.1 批量添加例外封锁
- 8.3.1.2 批量删除例外封锁
- 8.3.1.3 批量修改例外封锁
- 8.3.1.4 获取所有例外封锁配置
- 8.3.1.5 修改单项例外
- 8.3.2 获取封锁攻击者IP列表
- 8.3.3 批量添加封锁攻击者
- 8.3.4 批量删除封锁攻击者
- 8.3.5 清空封锁攻击者
- 8.3.6 全量修改自动封锁攻击者时间
- 8.3.7 获取自动封锁攻击者时间
- 8.3.8 获取封锁攻击者的数量
- 8.3.9 获取所有临时封锁 IP
- 8.3.10 获取业务封锁 IP
- 8.3.11 添加业务封锁 IP
- 8.3.12 删除业务封锁 IP
- 8.3.13 删除临时封锁 IP
- 8.3.14 清空业务封锁 IP
- 8.3.15 清空临时封锁 IP
- 12.1 完整返回码列表
