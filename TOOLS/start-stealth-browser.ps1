# 按需启动 Stealth Browser MCP（HTTP 模式，端口 9878）
# 用法: ./TOOLS/start-stealth-browser.ps1
# 停止: Ctrl+C 或关闭这个 PowerShell 窗口

$env:SAB_HEADLESS = "false"
$env:SAB_VIEWPORT_W = "1366"
$env:SAB_VIEWPORT_H = "768"
$env:SAB_LOCALE = "zh-CN"
$env:SAB_TIMEZONE = "Asia/Shanghai"
$env:SAB_PORT = "9878"

Write-Host "Starting Stealth Browser MCP on http://127.0.0.1:9878/mcp ..." -ForegroundColor Green
Write-Host "Claude Code will connect automatically on next tool call." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow

npx stealth-agent-browser-mcp --http --port 9878
