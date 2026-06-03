# Proxy 配置

## Clash Verge API
- API: `http://127.0.0.1:9097`
- Secret: `set-your-secret`
- Proxy Port: `127.0.0.1:9870` (HTTP/SOCKS5 mixed)
- Core: verge-mihomo v1.19.21

## IP 轮换
使用 `TOOLS/clash-helper.ps1`:
```powershell
. .\TOOLS\clash-helper.ps1
Switch-ClashProxy -Region HK    # 切香港节点
Switch-ClashProxy -Region JP    # 切日本节点
Switch-ClashProxy               # 完全随机
Set-ClashMode -Mode global      # 切换模式
```

## 各通道代理方案
| 通道 | 配置方式 |
|------|----------|
| Burp MCP | Burp UI → Project Options → Connections → Upstream Proxy, Host: 127.0.0.1:9870, Dest: \* |
| PowerShell | `$env:HTTP_PROXY="http://127.0.0.1:9870"` |
| Chrome DevTools | 依赖系统代理（Clash system proxy enabled） |

## 网络代理规则
当 WebSearch / WebFetch 因网络限制失败时，立刻用 curl 通过 127.0.0.1:9870 重试。
