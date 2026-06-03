# 方法论

## 标准工作流
1. Operator 通过 Burp 浏览目标 → 捕获全部请求
2. Operator 识别可疑请求/参数 → 告知 Claude 精确目标
3. Claude 做被动分析（无自动化扫描工具）:
   - TOOLS/js-harvest.js (DevTools) → JS 端点收割
   - TOOLS/burp-surface.py → 参数/路径/模式分析
   - WebArchive / crt.sh / GitHub 搜索 → OSINT
4. Claude 通过 Burp MCP 分析（regex 过滤，永不读全量历史）
5. Claude 通过 Burp Repeater 测试（参数 fuzz、PoC 构造）
6. Operator 确认发现 → Claude 写报告

## 测试优先级
业务逻辑缺陷 > 越权 > XSS/SQLi
手动分析 + Burp > 盲目自动化扫描
发现即报告，不批量累积

## 升级触发条件
Claude 遇到以下情况必须暂停并询问 operator：
- 潜在高危（RCE、可写 SQLi、任意文件上传）
- 会话过期且 Stealth Browser 无法重新登录
- WAF/反爬阻挡自动化测试
- 目标返回异常大量响应（可能数据泄露）
- 不确定测试是否在授权范围内
