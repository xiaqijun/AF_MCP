# 认证与 IP 封禁相关 API 文档

本文档基于仓库中的 AF8.0.106-API中文文档.pdf 整理，聚焦“认证鉴权”和“IP 封禁”两类接口。

当前已整理的能力包括：

- 用户登录
- 用户注销
- token 保活
- 账户密码安全策略
- 当前已登录管理员账户权限查询
- 3A 认证配置
- 封锁攻击者
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
| 密码策略 | GET | /api/v1/namespaces/@namespace/accountpasswdpolicy | 获取账户密码安全策略 |
| 密码策略 | PATCH | /api/v1/namespaces/@namespace/accountpasswdpolicy | 修改账户密码安全策略 |
| 当前登录账户 | GET | /api/v1/namespaces/@namespace/accountpermissions/@name | 查询当前已登录管理员账户权限 |
| 3A 认证 | GET | /api/v1/namespaces/@namespace/aaacertification | 获取 3A 认证信息 |
| 3A 认证 | PUT | /api/v1/namespaces/@namespace/aaacertification | 修改 3A 认证信息 |
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

## 3. 封锁攻击者相关接口

### 3.1 清空封锁攻击者

- 方法：DELETE
- 路径：/api/v1/namespaces/@namespace/blockipclear
- 说明：清空当前命名空间下的封锁攻击者记录

请求参数：

| 位置 | 参数 | 必选 | 说明 |
| --- | --- | --- | --- |
| Query | creator | 否 | 限制访问身份，默认 AF，可选 SIP 或 AF |

示例：

```http
DELETE https://192.168.1.1/api/v1/namespaces/public/blockipclear
```

返回 data 为被清空的封锁攻击者列表。

### 3.2 全量修改自动封锁攻击者时间

- 方法：PATCH
- 路径：/api/v1/namespaces/@namespace/blockiptime
- 说明：设置自动封锁攻击者时间

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

### 3.3 获取自动封锁攻击者时间

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blockiptime
- 说明：获取当前自动封锁攻击者时间配置

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

### 3.4 获取封锁攻击者数量

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/blocktotalcnt
- 说明：返回当前封锁总条数

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
| name | 是 | 账户名 |
| password | 是 | 密码 |

关键返回字段：

| 字段 | 含义 |
| --- | --- |
| data.name | 执行操作的管理员账户名 |
| data.loginResult.token | 登录后得到的会话令牌 |
| data.passwdStatus | 密码状态，是否过期或需要修改 |
| data.authResult | 认证结果 |
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
| data.authResult | 认证结果 |
| data.cftoken | 防跨站请求伪造的会话令牌 |
| data.namespace | 账号所属系统标识 |

### 7.3 token 保活

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/keepalive
- 说明：刷新 token 时间戳，保持 token 不超时

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

## 8. 账户密码安全策略

### 8.1 获取账户密码安全策略

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/accountpasswdpolicy
- 说明：查询当前命名空间下的账户密码安全策略

示例：

```http
GET https://192.168.1.1/api/v1/namespaces/public/accountpasswdpolicy
```

示例返回：

```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "changeInitialPasswd": false,
    "passwdExpiredChange": false,
    "passwdValidity": 30
  }
}
```

返回字段：

| 字段 | 含义 |
| --- | --- |
| changeInitialPasswd | 下次登录是否需要修改密码 |
| passwdExpiredChange | 密码过期后是否需要修改密码 |
| passwdValidity | 密码有效期，单位天 |

### 8.2 修改账户密码安全策略

- 方法：PATCH
- 路径：/api/v1/namespaces/@namespace/accountpasswdpolicy
- 说明：修改账户密码安全策略

请求体示例：

```json
{
  "changeInitialPasswd": false,
  "passwdExpiredChange": true,
  "passwdValidity": 15
}
```

请求字段：

| 字段 | 必选 | 含义 |
| --- | --- | --- |
| changeInitialPasswd | 否 | 下次登录是否需要修改密码 |
| passwdExpiredChange | 否 | 密码过期后是否需要修改密码 |
| passwdValidity | 是 | 密码有效期 |

## 9. 当前已登录管理员账户权限

### 9.1 查询当前已登录管理员账户权限

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/accountpermissions/@name
- 说明：查询当前已登录管理员账户权限信息

示例：

```http
GET https://192.168.1.1/api/v1/namespaces/public/accountpermissions/admin
```

关键返回字段：

| 字段 | 含义 |
| --- | --- |
| name | 用户名 |
| uuid | 账户唯一标识 |
| enable | 账户状态 |
| description | 描述 |
| roleName | 账户角色 |
| authType | 认证类型 |
| authentication.usbKeyEnable | 是否启用 USB Key 认证 |
| authentication.fingerprintEnable | 是否启用指纹校验 |
| authentication.manageMode | 管理方式 |
| modulePermissions | 模块权限列表 |

常见枚举：

#### roleName

- ADMINISTRATOR：超级管理员
- COMMON：普通管理员
- SAFE：安全管理员
- LOG：审计员
- SYSTEM：系统管理员

#### authType

- LOCAL：仅本地认证
- REMOTE：仅外部服务器认证
- REMOTE_OR_LOCAL：优先外部认证，失败时回退到本地认证

#### manageMode

- WEBCONSOLE：Web 管理界面
- APIINTERFACE：API 接口
- COMMANDLINE：命令行

## 10. 3A 认证配置

### 10.1 获取 3A 认证信息

- 方法：GET
- 路径：/api/v1/namespaces/@namespace/aaacertification
- 说明：获取当前 3A 认证配置

示例：

```http
GET https://192.168.1.1/api/v1/namespaces/public/aaacertification
```

示例返回：

```json
{
  "code": 0,
  "message": "",
  "data": {
    "allowRemoteAccess": true,
    "enable": true,
    "basic": {
      "sharekey": "test",
      "ip": "192.168.1.1",
      "protocol": "eap",
      "port": 0
    },
    "aaatype": "radius",
    "name": "admin"
  }
}
```

### 10.2 修改 3A 认证信息

- 方法：PUT
- 路径：/api/v1/namespaces/@namespace/aaacertification
- 说明：修改当前 3A 认证配置

请求体示例：

```json
{
  "allowRemoteAccess": true,
  "enable": true,
  "basic": {
    "sharekey": "test",
    "ip": "192.168.1.1",
    "protocol": "eap",
    "port": 0
  },
  "aaatype": "radius",
  "name": "admin"
}
```

请求字段：

| 字段 | 必选 | 含义 |
| --- | --- | --- |
| enable | 否 | 3A 认证开关 |
| name | 否 | 外部认证服务器名称 |
| aaatype | 否 | 3A 认证方式 |
| allowRemoteAccess | 否 | 是否允许远程管理员接入 |
| basic.ip | 否 | 认证服务器 IP |
| basic.port | 否 | 认证端口 |
| basic.sharekey | 否 | 共享秘钥 |
| basic.protocol | 否 | 采用协议 |

相关枚举：

#### aaatype

- tacacs：TACACS 认证
- radius：RADIUS 认证

#### basic.protocol

- pap：PAP
- ask：质询握手身份验证协议
- chap：Microsoft CHAP
- chap2：Microsoft CHAP2
- eap：EAP_MD5

## 11. 认证相关返回码

从附录中可确认以下与认证直接相关的返回码：

| 返回码 | 含义 |
| --- | --- |
| 1 | 操作不允许，如认证失败 |
| 13 | 缺少对应接口调用权限 |
| 1003 | 未登录 |
| 1010 | 密码过期 |
| 1012 | 登录状态过期 |

## 12. 来源定位

以上内容整理自 AF8.0.106-API中文文档.pdf 的以下章节：

- 1.2 交互流程与报文格式
- 1.3 HTTP请求头格式
- 2.1 用户登录
- 2.2 用户注销
- 2.3 token保活
- 7.2.10 获取账户密码安全策略
- 7.2.11 修改账户密码安全策略
- 7.2.12 查询当前已登录管理员账户权限
- 7.2.13 获取 3A 认证信息
- 7.2.14 修改 3A 认证信息
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
