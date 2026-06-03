# SRC 漏洞挖掘项目

基于 AI（Claude）驱动的 SRC 漏洞挖掘工作流。操作员做决策、跑流程，AI 做执行、构造 PoC、验证漏洞。

---

## Skills 总览

所有 skill 位于 `.claude/skills/{name}/SKILL.md`，通过 `Skill()` 工具调用。

### 工作流 Skill（按执行顺序）

#### 1. asset-recon — 资产梳理（入口）

使用 FOFA/ZoomEye 被动侦察目标，初始化目标 DB，写入 targets/pages 表，资产自动入队。

**不收录低危；只收录中危及以上漏洞**

## 高危

* 直接获取核心场景/模块权限（服务器端权限、客户端权限）的漏洞，包括但不限于：远程命令执行漏洞、任意代码执行漏洞、SQL 注入获取系统可执行权限、缓冲区溢出、获取root权限、获取集群权限、获取服务级别关键凭证(AK/SK/证书/秘钥等）。
* 泄露百万条以上且可遍历的重要敏感数据漏洞，包括但不限于：核心DB的SQL注入漏洞、用户敏感信息接口越权导致的大范围泄露、无限制获取和破坏数据资产。
* 核心系统的严重逻辑设计缺陷或流程缺陷，包括但不限于修改任意账号密码、任意账号登陆（获取特定账号的登录及操作权限）、影响巨大的越权漏洞（如任意商品下架、交易及聊天场景的批量任意伪造身份并发送任意内容信息)。
* 客户端大量敏感信息泄露的漏洞，包括但不限于远程获取用户大量敏感信息、本地越权访问TEE保护的支付相关或者用户认证相关信息、TEE任意代码执行（高权限）。
* 设备端/硬件安全机制绕过，包括但不限于绕过SELinuX、绕过安全启动。
* 直接获取一般系统权限（服务器端权限、客户端权限）的漏洞，包括但不限于：远程命令执行漏洞、任意代码执行漏洞、上传 WebShell、缓冲区溢出。
* 本地任意文件读写、打开非导出组件并做代码执行等敏感操作。

## 中危

* 少量敏感数据或无重要敏感数据的SQL注入。
* 任意文件读取或操作部分非敏感文件且无法进一步利用的。
* 存储型XSS漏洞、敏感信息的JSONP劫持。
* 客户端远程临时性拒绝服务。
* 本地数据库注入（可造成信息泄漏或其他危害的）。

## 不在奖励范围的漏洞

* 基于流量的拒绝服务攻击
* 需要物理访问用户设备的攻击或中间人攻击
* 不能访问公司内网的 SSRF 行为
* 暴力破解导致的账户锁定（无实际危害拓展类爆破）
* 公开文件、目录、数据、页面的信息（如无敏感信息的 json hijacking、js/img 等公开资源文件、含内网 IP / 域名的页面）
* 应用程序错误、服务器错误信息（如返回包报错导致的 SQL 语句泄漏、服务器绝对路径泄露按无危害处理）
* 任何无敏感信息的信息泄露（如一般信息的 logcat、内网 IP / 域名泄漏）
* 无意义的异常信息泄漏
* 接口泄漏漏洞（如 swagger 类似的 api 泄漏无法证明实际危害则不收）
* 事件漏洞：无法利用的漏洞，包括但不限于 Self-XSS、仅针对自身浏览器 XSS、无敏感操作的 CSRF、复杂且随机的 id 越权（如雪花算法生成的 10 位数以上无规律组合 id 越权）
* 不能直接反映漏洞存在的其他问题：包括但不限于纯属用户猜测、未经过验证的问题、无实际危害证明的扫描器结果
* 登录 / 忘记密码页面的用户枚举
* 遍历手机号发短信、遍历用户名（邮箱）判断是否已注册、邮箱轰炸、验证码爆破、无额外验证导致的可爆破（非重点核心功能）、对同一个手机号 / 邮箱地址大量发送信息等爆破类漏洞
* XSS 漏洞：简单弹窗、插入 url、dnslog、pdfxss、htmlxss 等未获取用户 COOKIE 或造成蠕虫的操作
* CSRF 漏洞：无敏感操作的 CSRF 漏洞（如不涉及金额支付、用户密码、核心信息修改的 CSRF）
* 越权漏洞：无敏感操作、无法批量操作的越权（如越权评论、添加备注、复杂 id 越权）、子母账户越权漏洞
* 不涉及安全问题的 Bug：包括但不限于产品功能缺陷、网页乱码、样式混乱、静态文件目录遍历、应用兼容性等
* 内部已知、正在处理的漏洞（包括第三方已公开通用、白帽子 / 内部已发现的漏洞）
* 针对开发者调测能力设备或特性的拒绝服务漏洞
* 需绕过已有风控策略，在 5 分钟内连续对同一号码发送 50 条以上信息，横向轰炸（对不同号码发送）不收取。

## 漏洞收录规则

* 同一漏洞源导致的多个漏洞（如同一 JS、发布系统、框架、泛域名解析、同接口多参数、同一资源 ID 导致的多个漏洞），仅确认 1 个有效漏洞；若修复一个其他自动修复，只收录 1 个。
* 同一系统中同一类型 / 利用手段相似的多个漏洞（如同一站点多个接口 SQL 注入、同一系统多个密码泄露），60 天内重复提交的，仅记前三个为有效漏洞。
* 同一功能的越权增删改查，合并在一个报告提交，按一个漏洞收取。
* 具有利用顺序关系的多个漏洞（如弱口令 + 越权），按最大危害计算；分多个报告提交则适当升级一个报告评级，其他忽略；合并报告则修改原评级，其他忽略。
* 弱口令相关漏洞：按弱口令用户权限收取。
* 若提交问题在修复中未逾期，不予收录；若已修复但其他位置仍存在，重新收录。

```
Skill(skill="asset-recon", args="目标: 台州学院")
```

#### 2. stealth-scanner — BFS 爬虫扫描

Scrapling + Burp 驱动网站爬虫。BFS 遍历页面、收割 JS 端点、框架指纹识别、API 方法探测、参数 fuzz、表单交互、框架专项探测。写 SQLite，不验证漏洞。每 10 轮自动向 memory 写入进度总结。

```
Skill(skill="stealth-scanner", args="目标: 台州学院")
```

#### 3. business-logic-hunt — 业务逻辑漏洞自动猎手

读取 Burp HTTP 历史 → MiniMax 筛选业务接口 → 三层重放（A 账号 / B 账号 / 未授权）。覆盖：

- IDOR 越权（水平/垂直）
- 未授权访问
- 信息泄露（手机号/身份证/邮箱）
- 验证码缺陷（重用/绕过）
- 用户枚举
- 任意密码重置
- 参数逻辑注入（替换 status/role/amount 等）

增量队列模式，每次调用处理 5 个端点。确认漏洞写 findings 表（`F-BLH-*`），低置信度写 suspicious_points（`SP-BLH-*`）。

```
Skill(skill="business-logic-hunt", args="目标: 台州学院")
Skill(skill="business-logic-hunt", args="目标: 台州学院; 模式: refresh")
```

**前置条件**：`auth_sessions` 表中准备 primary + secondary 两个账号的 token。

#### 4. manual-replay — 手工流程变种攻击

操作员在 Burp 中手工跑完业务流程（注册→登录→下单等），回到 Claude 调用此 skill。AI 读取时间窗口内的 Burp 历史：

1. 时间窗口采集（默认最近 5 分钟）→ MiniMax 分类业务意图
2. AI 识别流程步骤和跨请求参数依赖
3. 按业务意图生成变种（IDOR/未授权/参数逻辑/验证码复用等）
4. 三层执行（A 账号 / B 账号 / 未授权）
5. 确认漏洞写 findings 表（`F-RP-*`），低置信度写 suspicious_points（`SP-RP-*`）

```
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay; 窗口: 5; 流程: 下单")
Skill(skill="manual-replay", args="目标: 台州学院; 模式: replay")
```

参数说明：

- `窗口` — 时间窗口（分钟），默认 5
- `流程` — 按 business_intent 筛选（可选）

**前置条件**：`auth_sessions` 表中已有 primary + secondary 两个账号的 token。

#### 5. vuln-review — PoC 验证引擎

轮询 DB 中 `suspicious_points`（test_status='untested'），逐条构造 PoC 通过 Burp 发送验证。含门控探测（已修复类型跳过）、WAF 绕过、价值决策树、双层变种分析。结果写入 findings/suppressions 表。

```
Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院")
Skill(skill="vuln-review", args="模式: 复核; 目标: 台州学院; 规则文件: res/vuln_rules.json")
```

#### 6. vuln-auditor — 补天审核员视角复核

站在补天平台审核员视角复核漏洞报告。解析 docx 提取 PoC HTTP 请求并通过 Burp 发送，运行 PoC 脚本，打回不可复现漏洞并记录到 memory，通过后更新 audit_status。

```
Skill(skill="vuln-auditor", args="目标: {target}")
Skill(skill="vuln-auditor", args="目标: {target}; finding: F-001,F-002")
```

#### 7. src-report — 漏洞报告生成

两阶段：Phase 1 证据评审 + 等级复核，Phase 2 逐漏洞写入独立报告文件。管理员可直接复制文件内容到 SRC 平台提交。支持 edu/补天/CNVD 三平台。

```
Skill(skill="src-report", args="平台: edu; 目标: 台州学院")
Skill(skill="src-report", args="平台: 补天; 目标: 台州学院")
Skill(skill="src-report", args="平台: CNVD; 目标: 台州学院")
```

报告保存到 `reports/{平台}_提交_{目标}_{日期}.md`。

#### 8. compress-lessons — lessons 压缩归档

当确认某目标短期内不再返工后，压缩 lessons 到 archive，清理扫描状态。

```
Skill(skill="compress-lessons", args="target: 货讯通科技")
```

---

### 协议 / 工具 Skill（非直接调用）

以下 skill 供其他 skill 内部引用，不直接通过 `Skill()` 调用：

| Skill                  | 用途                                                                                                                                                |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ip-rotate**    | Clash 代理 IP 轮换协议。提供请求计数器管理、亚洲节点优先顺序切换、环境变量设置。供 stealth-scanner 和 vuln-review 引用。                            |
| **mmx-router**   | MiniMax CLI token 路由协议。定义何时必须把数据交给 mmx 处理而非 Claude 直读，以及安全测试专用 prompt 模板。供 stealth-scanner 和 vuln-review 引用。 |
| **skill-editor** | 分析和修改 SKILL.md 的工具。确保 AI 指令简洁、完整、一致。不引入面向人类的修饰内容。                                                                |

---

## 目录规范

| 目录                        | 用途                                                   |
| --------------------------- | ------------------------------------------------------ |
| `dbs/`                    | 按目标分库的 DB 目录 —`dbs/{目标}_{日期}.db`        |
| `TOOLS/`                  | 通用工具脚本（长期维护）                               |
| `reports/`                | 正式漏洞报告（可提交 SRC）                             |
| `res/`                    | 静态资源（截图、验证码样本等）                         |
| `tmp/`                    | 所有临时文件（分析中间产物、PoC 草稿、日志、调试脚本） |
| `migrations/`             | DB 迁移 SQL 文件（按编号顺序执行）                     |
| `docs/superpowers/specs/` | 设计文档                                               |
| `docs/superpowers/plans/` | 实施计划                                               |
| `.claude/skills/`         | Skill 定义文件                                         |

**临时文件铁律**：所有临时文件必须写到 `tmp/` 目录，禁止写入根目录或 `.claude/`。

---

## 并发三 Session 模型

三个独立 Claude Code session 通过 SQLite 协同工作，可同时运行：

| Session | Skill           | 职责                                        |
| ------- | --------------- | ------------------------------------------- |
| A       | asset-recon     | FOFA + ZoomEye 被动侦察，初始化目标 DB      |
| B       | stealth-scanner | BFS 爬虫遍历页面、收割 JS、识别可疑参数     |
| C       | vuln-review     | 轮询 DB 中 suspicious_points，逐条 PoC 验证 |

**协作机制**：

- WAL 模式 + busy_timeout=5000 处理并发
- asset-recon 写 targets、pages、scan_state
- stealth-scanner 写 pages、js_files、suspicious_points
- vuln-review 读上述表，写 suspicious_points.test_status、findings
- business-logic-hunt 和 manual-replay 独立运行，写 findings/suspicious_points

---

## 环境依赖

| 工具                     | 用途                                                          |
| ------------------------ | ------------------------------------------------------------- |
| Burp Suite MCP           | HTTP 历史查询 + 请求重放                                      |
| MiniMax MCP + CLI（mmx） | 低智商高 Token 任务（Burp 历史过滤、DB 结果分析、大文件摘要） |
| SQLite（Python sqlite3） | 数据库操作（通过 TOOLS/db_query.py）                          |
| Scrapling（Python）      | 爬虫引擎                                                      |
| Clash（PowerShell）      | 代理切换（HK→JP→SG→TW→KR→MY 轮换）                       |

详细配置见 `CLAUDE.md`。
