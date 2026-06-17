---
name: ip-rotate
description: Clash 代理 IP 轮换协议。提供请求计数器管理、亚洲节点优先顺序切换、环境变量设置。供 stealth-scanner 和 vuln-review 引用。
allowed-tools: Bash, PowerShell
---

# ip-rotate

Clash Verge 驱动的 IP 轮换协议。所有用到代理的 skill 统一引用本协议，不在各自 SKILL.md 中重复定义。

## 常量

| 变量 | 值 |
|------|----|
| Clash API | `http://127.0.0.1:9097` |
| Secret | `set-your-secret` |
| HTTP 代理 | `127.0.0.1:9870` |
| 代理组 | `Proxy` |
| 助手脚本 | `.\TOOLS\clash-helper.ps1` |

## 轮换规则

**IP 切换不自动触发，仅当操作员明确要求时执行。**

切换时的地区优先顺序: **HK → JP → SG → TW → KR → MY**（亚洲优先）
- 某地区无可用节点 → 跳过，尝试下一个
- 所有亚洲地区均无可用节点 → 回退随机节点

## 命令

### 加载助手

```powershell
. .\TOOLS\clash-helper.ps1
```

### 切换 IP（亚洲顺序）

```powershell
. .\TOOLS\clash-helper.ps1
# 按优先顺序依次尝试:
Switch-ClashProxy -Region HK   # 香港（第1优先）
Switch-ClashProxy -Region JP   # 日本（第2优先）
Switch-ClashProxy -Region SG   # 新加坡（第3优先）
Switch-ClashProxy -Region TW   # 台湾（第4优先）
Switch-ClashProxy -Region KR   # 韩国（第5优先）
Switch-ClashProxy -Region MY   # 马来西亚（第6优先）
Switch-ClashProxy              # 随机回退（全部亚洲无节点时）
```

实际执行时：先尝试 HK，节点数 > 0 则切换并停止；否则尝试 JP，以此类推。

### 设置代理环境变量（Python/curl/其他工具）

```powershell
. .\TOOLS\clash-helper.ps1; Enable-ClashProxyEnv
```

执行后 `HTTP_PROXY` 和 `HTTPS_PROXY` 均指向 `http://127.0.0.1:9870`，当前 PowerShell session 内所有工具自动走代理。

### 清除代理环境变量

```powershell
. .\TOOLS\clash-helper.ps1; Disable-ClashProxyEnv
```

### 查看当前节点

```powershell
. .\TOOLS\clash-helper.ps1; (Get-ClashProxies).groups["Proxy"].now
```

## 按场景的标准操作

| 场景 | 操作 |
|------|------|
| 初始化 | 加载助手 + `Enable-ClashProxyEnv`（不自动切节点） |
| 操作员要求换 IP | `Switch-ClashProxy -Region HK`（按亚洲优先顺序） |
| PoC 脚本 / Python 扫描 | `Enable-ClashProxyEnv` 确保 HTTP_PROXY 已设置 |
| Burp 发包 | Burp 上游代理指向 `127.0.0.1:9870`；切 IP 时 Burp 自动使用新节点 |
| req_count 达到 4 | 按 HK→JP→SG→TW→KR→MY 顺序执行一次切换，重置计数器 |
| 爬虫每 10 页 | `Switch-ClashProxy -Region HK` |

## 验证 Clash 是否可用

```powershell
Invoke-RestMethod "http://127.0.0.1:9097/proxies/Proxy" -Headers @{"Authorization"="Bearer set-your-secret"} | Select-Object -ExpandProperty now
```

输出节点名说明 Clash API 正常。若报错则 Clash Verge 未启动或 secret 不匹配。
