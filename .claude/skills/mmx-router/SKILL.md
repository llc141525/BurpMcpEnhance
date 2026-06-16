---
name: mmx-router
description: SRC 项目的文本ETL路由协议。定义何时调用 etl_analyzer.py 处理数据而非 Claude 直读，以及各 task 的适用场景。供 stealth-scanner、vuln-review、business-logic-hunt、manual-replay 引用。
allowed-tools: Bash
---

# etl-router

SRC 漏洞挖掘场景的文本ETL规范。定义**何时必须用 `etl_analyzer.py` 处理数据**，以及使用哪个 task。

## 核心原则

**Claude 不读原始噪音数据。** 以下数据源必须先交给 `etl_analyzer.py` 处理，Claude 只读返回的精简结果。

## 路由规则

| 数据源 | 阈值 | etl_analyzer task |
|--------|------|-------------------|
| Burp HTTP 历史查询结果 | 任意大小 | `filter_burp` |
| DB 查询结果 | >10 行 | `filter_db` |
| JS 文件内容 | 含密钥信号¹ | `analyze_js` |
| HTML 页面内容 | >5KB | `extract_endpoints` |
| 业务接口意图分类 | 任意 | `classify_business` |
| HTTP 请求流程分析 | 任意 | `analyze_flow` |
| 安全测试变种生成 | 任意 | `generate_variants` |
| PoC 响应差异对比 | 任意 | `diff_responses` |

¹ **JS 两层处理规则**：URL 端点提取由 `js_analyzer.py` 的正则层完成，直接写入 `pages` 表，**不调 etl_analyzer**。只有含密钥信号（`api_key / secret / token / auth / Bearer / accessKey / appSecret / REACT_APP_ / VUE_APP_`）时，才将文件内容送 `analyze_js`。

## 图像理解 / 联网搜索

- **图像/截图**：直接用 Claude 的 `Read` 工具读取图片文件（Claude 是多模态的）
- **联网搜索**：直接用 Claude 内置 `WebSearch` 工具

## 调用方式

```bash
# CLI 调用（stdin 输入）
echo "{burp_json}" | uv run python TOOLS/utils/etl_analyzer.py --task filter_burp

# CLI 调用（--data 参数）
uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat /tmp/target.js)"

# 加额外指令
uv run python TOOLS/utils/etl_analyzer.py --task classify_business \
  --instruction "额外要求：每条增加 flow_step 字段" \
  --data "$(cat /tmp/burp_history.json)"
```

## Python 调用（脚本内）

```python
import sys
sys.path.insert(0, "TOOLS")
from utils.etl_analyzer import analyze

result = analyze("filter_burp", raw_burp_json)
result = analyze("classify_business", burp_json, instruction="额外要求：...")
```

## Task 一览

| task | 用途 |
|------|------|
| `filter_burp` | 过滤Burp历史，提取目标URL/参数列表 |
| `analyze_js` | 提取JS中的API端点、硬编码密钥、敏感参数 |
| `filter_db` | 筛选DB查询结果中的可疑/异常记录 |
| `extract_endpoints` | 从HTML提取表单/API URL/注释 |
| `classify_business` | 业务接口意图分类（business_api/auth_*/admin_api等）|
| `analyze_flow` | 识别HTTP请求序列中的业务流程链 |
| `generate_variants` | 生成安全测试变种（IDOR/unauth/param_logic等）|
| `diff_responses` | 对比两个HTTP响应判断安全差异 |
