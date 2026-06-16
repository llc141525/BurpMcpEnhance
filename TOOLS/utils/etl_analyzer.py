"""
ETL Adapter: DeepSeek-backed text analysis for SRC vulnerability hunting.
Replaces mmx text chat as the primary data ETL engine.

Usage (Python):
    from utils.etl_analyzer import analyze
    result = analyze("filter_burp", raw_json_text)

Usage (CLI):
    uv run python TOOLS/utils/etl_analyzer.py --task filter_burp < data.json
    uv run python TOOLS/utils/etl_analyzer.py --task analyze_js --data "$(cat file.js)"
"""

import argparse
import os
import sys

from openai import OpenAI

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

_SYSTEM_PROMPTS: dict[str, str] = {
    "filter_burp": (
        "从以下Burp代理历史中提取所有API端点（路径+参数名），"
        "JSON格式，字段：url(string), params(array of string)。"
        "排除第三方CDN/统计/广告。返回纯JSON数组，无markdown围栏。"
    ),
    "analyze_js": (
        "从以下JS代码提取：1.API端点 2.硬编码密钥/token 3.敏感参数名。"
        "JSON输出，字段：apis(数组), secrets(数组), sensitive_params(数组)。"
        "返回纯JSON，无markdown围栏。"
    ),
    "filter_db": (
        "以下是数据库查询结果，请标出其中测试状态异常、风险等级High、"
        "或参数名可疑（含file/path/uid/cmd/role等）的记录，"
        "只输出可疑行，保留原始格式。"
    ),
    "extract_endpoints": (
        "从以下HTML提取：1.所有表单（action, method, 字段名）"
        "2.外链API URL 3.注释中的敏感信息。"
        "JSON输出，字段：forms(数组), api_urls(数组), sensitive_comments(数组)。"
        "返回纯JSON，无markdown围栏。"
    ),
    "classify_business": (
        "你是SRC渗透测试助手，从Burp HTTP历史列表筛选业务接口。"
        '输出JSON数组，每条: {"burp_history_id":<int>,"method":"POST",'
        '"url":"...","endpoint_type":"business_api|auth_login|auth_register'
        '|auth_reset_password|auth_verify_code","business_intent":"一句话业务含义",'
        '"risk_hint":"High|Medium|Low","flow_step":<int>,"auth_required":true|false}\n'
        "判定: auth_*: URL含login/register/reset/sms/captcha; "
        "business_api: /api/或.do/.action且非登录; "
        "risk=High: 含id/uid/oid参数或DELETE/PUT; Low: 字典/枚举无参数\n"
        "排除: 第三方CDN/统计/广告; 同URL去重保留risk最高; health check/version端点\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "analyze_flow": (
        "分析以下HTTP请求序列，识别业务流程链，输出JSON:\n"
        '{"flow_chains":[{"chain_id":1,"steps":[1,2,3],"flow_name":"创建订单流程",'
        '"state_params":{"order_id":"请求2响应→请求3请求"},"auth_context":"primary"}],'
        '"cross_request_params":[{"param_name":"token",'
        '"source_request_id":1,"target_request_id":2}]}\n'
        "规则: flow_chains 识别 flow_step>0 的连续请求链; "
        "state_params 标注跨请求传递参数。返回纯JSON，无markdown围栏。"
    ),
    "generate_variants": (
        "给定HTTP请求及业务意图，生成安全测试变种，输出JSON数组（5-15条）:\n"
        '[{"test_type":"idor|unauth|param_logic|user_enum|captcha_reuse'
        '|password_reset_takeover|info_leak",'
        '"target_param":"参数名","original_value":"原始值",'
        '"replacement_value":"替换值",'
        '"modification":"replace_param|remove_auth|replace_cookie|remove_param|add_param",'
        '"description":"变种说明"}]\n'
        "业务意图→变种映射: 订单创建/查询→idor+unauth+param_logic; "
        "登录→user_enum; 验证码→captcha_reuse; "
        "密码重置→password_reset_takeover; 用户信息→idor+info_leak\n"
        "返回纯JSON，无markdown围栏。"
    ),
    "diff_responses": (
        "对比以下两个HTTP响应，判断是否存在安全漏洞（如IDOR/注入/信息泄露），"
        '说明差异和判断依据。输出格式：{"has_vuln": true|false, '
        '"vuln_type": "类型或null", "evidence": "差异说明", '
        '"confidence": "High|Medium|Low"}'
    ),
}


def analyze(task: str, data: str, instruction: str = "") -> str:
    """Call DeepSeek to perform ETL analysis on data.

    Args:
        task: One of the keys in _SYSTEM_PROMPTS.
        data: Raw text to analyze (JSON, JS, HTML, SQL output, etc.).
        instruction: Optional extra instruction prepended to data.

    Returns:
        DeepSeek response text (typically JSON).

    Raises:
        RuntimeError: If DEEPSEEK_API env var is not set.
        ValueError: If task is not a recognized task name.
    """
    api_key = os.environ.get("DEEPSEEK_API")
    if not api_key:
        raise RuntimeError("DEEPSEEK_API environment variable not set")

    system_prompt = _SYSTEM_PROMPTS.get(task)
    if not system_prompt:
        valid = list(_SYSTEM_PROMPTS.keys())
        raise ValueError(f"Unknown task: {task!r}. Valid tasks: {valid}")

    client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
    user_content = f"{instruction}\n{data}" if instruction else data

    response = client.chat.completions.create(
        model=DEEPSEEK_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        temperature=0.1,
        max_tokens=4096,
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL text analyzer via DeepSeek")
    parser.add_argument(
        "--task",
        required=True,
        choices=list(_SYSTEM_PROMPTS.keys()),
        help="Analysis task type",
    )
    parser.add_argument("--instruction", default="", help="Additional instruction")
    parser.add_argument("--data", default=None, help="Data to analyze (or stdin)")
    args = parser.parse_args()

    raw_data = args.data if args.data is not None else sys.stdin.read()
    print(analyze(args.task, raw_data, args.instruction))
