# Raw Duplicates 存储设计

**日期**: 2026-06-19
**状态**: 已批准

## 背景

当前去重逻辑以 `SHA-256(method|url)` 为 key，5 分钟窗口内相同接口的重复请求只累加 `hit_count`，原始数据永久丢失。这导致同一接口的不同账号登录凭证只能保留第一条，后续均被丢弃。

目标：参照噪音过滤的设计哲学，让 AI 默认只看到每个接口的 canonical（代表）条目，同时通过外键保留原始重复数据供按需查询。

## 设计决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 存储架构 | 独立 raw 表 + FK | 主表不膨胀，语义清晰，pruning 独立 |
| canonical 选取 | 第一条捕获 | 逻辑最简单，无需 UPDATE canonical |
| raw 数据保留策略 | 每 canonical 最近 N 条 | 平衡存储与可追溯性 |
| AI 访问接口 | 扩展 `get_http_detail` | 不增加新工具，参数可选，向后兼容 |

## 数据库 Schema

### 新增表：`proxy_http_raw_duplicates`

```sql
CREATE TABLE IF NOT EXISTS proxy_http_raw_duplicates (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_id     INTEGER NOT NULL
                       REFERENCES proxy_http_history(id) ON DELETE CASCADE,
    method           TEXT NOT NULL,
    status           INTEGER,
    url              TEXT NOT NULL,
    request_headers  TEXT,
    request_body     TEXT,
    response_headers TEXT,
    response_body    TEXT,
    content_type     TEXT,
    captured_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_dup_canonical
    ON proxy_http_raw_duplicates(canonical_id, captured_at DESC);
```

**设计要点**：
- `ON DELETE CASCADE`：canonical 被 pruning 删除时，raw 行自动清理
- 不存 `dedup_key`、`param_names` 等派生字段，节省空间
- `id` 使用 AUTOINCREMENT，与 canonical 的 Burp 原生 id 不冲突

### `proxy_http_history` 无需改动 Schema

现有 `dedup_key`、`hit_count` 字段继续使用，`hit_count` 等于 raw 表行数 + 1。

## 写入路径

### 变化前

```
for entry in entries:
    if dedup_key 在窗口内存在:
        hit_count += 1   ← raw data 丢失
    else:
        INSERT canonical
```

### 变化后

```
for entry in entries:
    if dedup_key 在窗口内存在:
        canonical_id = 已存在行的 id
        INSERT INTO proxy_http_raw_duplicates (canonical_id, ...)
        UPDATE proxy_http_history SET hit_count = hit_count + 1
        pruneRawDuplicates(canonical_id, maxPerCanonical)
    else:
        INSERT INTO proxy_http_history (canonical)
```

### Raw 条数限制 SQL

```sql
DELETE FROM proxy_http_raw_duplicates
WHERE canonical_id = ?
  AND id NOT IN (
    SELECT id FROM proxy_http_raw_duplicates
    WHERE canonical_id = ?
    ORDER BY captured_at DESC
    LIMIT ?
  )
```

每次写入重复后立即执行，保证每个 canonical 不超过 `maxRawDuplicatesPerCanonical` 条。

## 读取路径

### `get_http_detail` 新增 `include_duplicates` 参数

- `include_duplicates=false`（默认）：行为不变，只返回 canonical
- `include_duplicates=true`：额外查询 `proxy_http_raw_duplicates` 并按 canonical_id 分组附加到结果

### 新增数据类

```kotlin
data class RawDuplicateEntry(
    val id: Int,
    val method: String,
    val status: Int?,
    val url: String,
    val requestHeaders: String?,
    val requestBody: String?,
    val responseHeaders: String?,
    val responseBody: String?,
    val contentType: String?,
    val capturedAt: Long
)
```

`ProxyHttpEntry` 新增字段：

```kotlin
val duplicates: List<RawDuplicateEntry> = emptyList()
```

### MCP Tool Schema 变化（`ExporterTools.kt`）

```json
"include_duplicates": {
  "type": "boolean",
  "description": "If true, include all raw duplicate requests captured for the same endpoint. Useful when multiple accounts logged into the same URL.",
  "default": false
}
```

## 迁移策略

- `migrateSchema()` 启动时自动创建新表和索引（`CREATE TABLE IF NOT EXISTS`）
- 存量 canonical 数据不受影响
- 历史上已丢失的 raw data 无法恢复，接受现状
- `clearAll()` 通过 CASCADE 自动清理 raw 表，无需额外操作

## UI 变化

### `McpConfig.kt`

```kotlin
var maxRawDuplicatesPerCanonical by storage.int(10)
```

### `ServerConfigurationPanel.kt`

在噪音过滤模式选择器下方新增：

```
[✓] 保存重复请求的原始数据
    每个接口最多保留  [10 ▲▼] 条
```

实现：`JCheckBox` 控制是否启用，`JSpinner(SpinnerNumberModel(10, 1, 100, 1))` 控制数量，与 `config.maxRawDuplicatesPerCanonical` 双向绑定。

### `StatusDashboardPanel.kt`

在数据库统计区新增徽章：

```
数据库    [HTTP: 1234]  [扫描: 56]  [原始重复: 78]
```

`DbStats` 新增 `rawDuplicateCount: Int`，`stats()` 新增计数查询。

## 受影响文件汇总

| 文件 | 变化类型 |
|---|---|
| `db/Database.kt` | 新增表/索引、写入逻辑、读取方法、DbStats 字段 |
| `db/Database.kt` | 新增 `RawDuplicateEntry` 数据类 |
| `tools/ExporterTools.kt` | `get_http_detail` 新增 `include_duplicates` 参数 |
| `config/McpConfig.kt` | 新增 `maxRawDuplicatesPerCanonical` |
| `config/components/ServerConfigurationPanel.kt` | 新增开关 + spinner |
| `config/StatusDashboardPanel.kt` | 新增 `dbRawDupBadge` |

## 不在范围内

- WebSocket 历史的类似改造（可后续单独处理）
- Scanner Issues 的 raw 存储（无去重需求）
- `maxRawDuplicatesPerCanonical` 的全局清理 job（按需添加）
