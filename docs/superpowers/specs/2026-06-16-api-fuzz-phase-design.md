# API Fuzz Phase 设计文档

**日期**: 2026-06-16  
**状态**: 已批准，待实现

---

## 问题陈述

当前 stealth-scanner + business-logic-hunt 流程是**被动收集型**：只能测试已被 BFS 爬虫发现、或已在 Burp 历史中出现的端点。隐藏的 admin/teacher/manage API（前端无直接链接、需经验推断）无法自动纳入测试范围。

目标：在 stealth-scanner 的 probe 阶段之后、exploit 阶段之前，新增一个 `api_fuzz` 阶段，主动用词列+模式推断探测隐藏 API 命名空间，结果写入 hunt_queue，由 business-logic-hunt 自然消费。

---

## 方案选择

**选择方案 A**：在 stealth-scanner 的状态机中插入新 phase。

理由：全自动，与现有流程无缝衔接，操作员无需额外干预。

---

## 状态机变更

```
之前: probe → exploit
之后: probe → api_fuzz → exploit
```

`probe_next_phase()` 原返回 `'exploit'`，改为返回 `'api_fuzz'`。新增 `handle_api_fuzz()` 完成后切换到 `exploit`。

---

## api_fuzz.py 详细设计

### 入口

```bash
uv run python TOOLS/pipeline/api_fuzz.py --target "台州学院" [--delay 1.5] [--max-rotations 3]
```

### 四步流程

#### Step 1：提取已知 API 根路径

从 DB 聚合所有已知 API 路径，推导 base prefix：

```sql
-- 来源 1：pages.api_calls_json（auth_explore/blh_explore 拦截的 XHR）
SELECT api_calls_json FROM pages WHERE api_calls_json IS NOT NULL;

-- 来源 2：js_files.discovered_apis_json（JS 静态分析提取的端点）
SELECT discovered_apis_json FROM js_files WHERE analyzed=1 AND discovered_apis_json IS NOT NULL;

-- 来源 3：suspicious_points.url（probe 阶段发现的可疑点）
SELECT DISTINCT url FROM suspicious_points;
```

**Prefix 推导规则**：对所有 URL 路径按 `/` 分段，取频率最高的前2-3段作为 base prefix（如 `/api/v1/`、`/rest/api/`）。若推导失败则只用 `/api/`。

#### Step 2：构建探测列表

**Tier 1 — 内嵌词列**（约 50 条，覆盖教育/政务平台常见命名）：

```python
ADMIN_NAMESPACE_PATHS = [
    # 通用管理
    "/api/admin", "/api/admin/users", "/api/admin/list", "/api/admin/info",
    "/api/manage", "/api/management", "/api/manager",
    "/api/staff", "/api/internal", "/api/system", "/api/backstage",
    "/api/console", "/api/superadmin", "/api/privileged",
    # 教育平台专项
    "/api/teacher", "/api/teacher/list", "/api/teacher/course",
    "/api/instructor", "/api/tutor", "/api/faculty",
    # 版本化路径
    "/api/v1/admin", "/api/v1/teacher", "/api/v1/manage", "/api/v1/staff",
    "/api/v2/admin", "/api/v2/teacher", "/api/v2/manage",
    # 反转结构
    "/admin/api", "/admin/api/users", "/admin/api/list",
    "/manage/api", "/teacher/api", "/system/api", "/console/api",
    # 中文平台拼音路径
    "/api/jiaoshi", "/api/guanli", "/api/xitong", "/api/jiaowu",
]
```

**Tier 2 — 动态推导**：

- 已知路径 `/api/v1/student` → 生成 `/api/v1/teacher`、`/api/v1/admin`、`/api/v1/manage`
- 已知路径 `/student-service/api/` → 生成 `/teacher-service/api/`、`/admin-service/api/`
- 已知 base prefix `/api/v1/` + ADMIN_NAMESPACE_STEMS（admin/teacher/manage/staff/system）

**去重**：跳过已在 `pages` 表（status IN ('visited','queued')）或 `hunt_queue` 中已有的 URL。

#### Step 3：探测（带 WAF 轮换保护）

```python
from waf_rotate import RotatingFetcher, is_waf_blocked, rotate_ip

fetcher = RotatingFetcher(max_rotations=args.max_rotations, rotate_delay=30.0)

for url in probe_list:
    # 探测 1：携带 primary auth cookie
    resp_auth = fetcher.fetch_with_rotation(
        lambda: requests.get(url, headers={"Cookie": primary_cookie},
                             proxies=burp_proxy, timeout=10, verify=False)
    )
    time.sleep(args.delay)  # 默认 1.5s

    # 探测 2：不携带 cookie（未认证）
    resp_unauth = fetcher.fetch_with_rotation(
        lambda: requests.get(url, proxies=burp_proxy, timeout=10, verify=False)
    )
    time.sleep(args.delay)
```

**WAF 处理**：`RotatingFetcher` 内部自动检测 `is_waf_blocked()`，命中则调 `rotate_ip()` 并等待 `rotate_delay`（30s）后重试，最多 `max_rotations` 次。超出上限则记录日志、跳过当前 URL 继续。

**代理**：所有请求走 `http://127.0.0.1:8080`（Burp）。

#### Step 4：分类写 hunt_queue

| unauth 响应码 | auth 响应码 | 操作 | risk_hint | business_intent |
|---|---|---|---|---|
| 200/201/204 | any | 写入 | **Critical** | `unauth_admin_access` |
| 403/401 | 200/201/204 | 写入 | **High** | `vertical_priv_esc` |
| any | 403 (路径含 admin/teacher) | 写入 | **Medium** | `admin_403_probe` |
| any | 500 | 写入 | **Medium** | `server_error_probe` |
| 404 | 404 | 跳过 | — | — |
| 429/503 | — | WAF 轮换 + 重试 | — | — |

写入 `hunt_queue`（`source='auto'`，CHECK 约束已支持；`notes` 字段标记来源和响应码）：
```sql
INSERT OR IGNORE INTO hunt_queue
  (target_id, method, url, endpoint_type, business_intent, risk_hint, status, source, notes)
VALUES
  (?, 'GET', ?, 'admin_api', ?, ?, 'queued', 'auto',
   'api_fuzz | auth={auth_code} unauth={unauth_code}');
```

`notes` 格式：`api_fuzz | auth=200 unauth=403`，方便 BLH 三层重放时参考初始响应。

### 输出标签

```
[API_FUZZ] probed={n} found={m} waf_rotations={k}
  Critical: {list of unauth 200 URLs}
  High: {list of priv_esc candidates}
  Medium: {count} 条
```

---

## 需要修改的文件

| 文件 | 类型 | 变更说明 |
|---|---|---|
| `TOOLS/pipeline/api_fuzz.py` | 新建 | 主逻辑脚本 |
| `TOOLS/run_scan.py` | 修改 | `probe_next_phase()` 改返回 `'api_fuzz'`；新增 `handle_api_fuzz()`；加入 HANDLERS dict |
| `TOOLS/db/schema.sql` | 无需修改 | `source='auto'` 已在 CHECK 允许列表中，`notes` 字段承载来源标记 |
| `.claude/skills/stealth-scanner/SKILL.md` | 修改 | 状态机表格加 `api_fuzz` 行；输出标签表加 `[API_FUZZ]` 行 |

---

## 数据流

```
run_scan.py (phase=api_fuzz)
  └─ api_fuzz.py
       ├─ DB: pages.api_calls_json + js_files.discovered_apis_json → 已知 API 路径
       ├─ ADMIN_NAMESPACE_PATHS (内嵌词列) + Tier 2 动态推导
       ├─ RotatingFetcher → HTTP 探测（1.5s/req，WAF 自动 rotate）
       └─ hunt_queue (source='api_fuzz', endpoint_type='admin_api')
            └─ business-logic-hunt (三层重放)
                 └─ findings / suspicious_points
```

---

## 约束与边界

- **不做漏洞验证**：api_fuzz 只负责发现端点并写 hunt_queue，验证由 BLH 完成
- **不重复 probe 已知页面**：去重逻辑排除 pages 表已有的 URL
- **速率限制**：默认 1.5s/req，可通过 `--delay` 调整；WAF 命中后 30s 冷却
- **Clash 不可用时降级**：`is_clash_alive()` 返回 False → 打印警告，继续探测（无 IP 轮换）
- **无 primary session 时**：仅发 unauth 请求，跳过 auth 对比

---

## 测试要点

- `test_api_fuzz.py`：单测 prefix 推导逻辑、去重逻辑、分类写 hunt_queue 逻辑
- mock `RotatingFetcher`：验证 WAF 触发后正确调用 rotate_ip 并重试
- 状态机测试：verify `probe_next_phase()` 返回 `'api_fuzz'`
