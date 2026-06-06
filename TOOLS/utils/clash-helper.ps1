# Clash 代理切换助手
# 用法: . .\TOOLS\clash-helper.ps1  (dot-source 加载)

$CLASH_API = "http://127.0.0.1:9097"
$CLASH_SECRET = "set-your-secret"
$CLASH_PROXY = "http://127.0.0.1:9870"
$HEADERS = @{ "Authorization" = "Bearer $CLASH_SECRET" }

function Get-ClashProxies {
    <#
    .SYNOPSIS
    获取所有代理节点和代理组
    #>
    $p = Invoke-RestMethod "$CLASH_API/proxies" -Headers $HEADERS -TimeoutSec 5
    $groups = @{}
    $nodes = @{}
    $p.proxies | Get-Member -MemberType NoteProperty | ForEach-Object {
        $name = $_.Name
        $proxy = $p.proxies.$name
        if ($proxy.type -eq "Selector") {
            $groups[$name] = @{
                now   = $proxy.now
                all   = $proxy.all
                type  = "Selector"
            }
        } elseif ($proxy.type -eq "LoadBalance") {
            $groups[$name] = @{
                now      = $proxy.now
                all      = $proxy.all
                type     = "LoadBalance"
                strategy = $proxy.strategy
            }
        } elseif ($proxy.type -eq "URLTest") {
            $groups[$name] = @{
                now  = $proxy.now
                all  = $proxy.all
                type = "URLTest"
            }
        } else {
            $nodes[$name] = @{
                type   = $proxy.type
                server = $proxy.server
                port   = $proxy.port
            }
        }
    }
    return @{ groups = $groups; nodes = $nodes }
}

function Set-ClashProxy {
    <#
    .SYNOPSIS
    切换指定代理组到指定节点
    .PARAMETER GroupName
    代理组名，默认 "Proxy"
    .PARAMETER NodeName
    节点名，不指定则随机选一个
    #>
    param(
        [string]$GroupName = "Proxy",
        [string]$NodeName = $null
    )

    $data = Get-ClashProxies
    if (-not $data.groups.ContainsKey($GroupName)) {
        Write-Error "代理组 '$GroupName' 不存在。可用组: $($data.groups.Keys -join ', ')"
        return
    }

    $available = $data.groups[$GroupName].all
    if (-not $NodeName) {
        # 排除 DIRECT/REJECT/当前节点，随机选一个
        $candidates = $available | Where-Object {
            $_ -notin @('DIRECT', 'REJECT', $data.groups[$GroupName].now)
        }
        if ($candidates.Count -eq 0) {
            $candidates = $available | Where-Object {
                $_ -notin @('DIRECT', 'REJECT')
            }
        }
        $NodeName = $candidates | Get-Random
    }

    if ($NodeName -notin $available) {
        Write-Error "节点 '$NodeName' 不在组 '$GroupName' 中"
        return
    }

    $body = @{ name = $NodeName } | ConvertTo-Json
    $null = Invoke-RestMethod "$CLASH_API/proxies/$([System.Uri]::EscapeDataString($GroupName))" `
        -Headers $HEADERS -Method PUT -Body $body -ContentType "application/json" -TimeoutSec 5

    Write-Output "[Clash] $GroupName → $NodeName"
    return $NodeName
}

function Set-ClashMode {
    <#
    .SYNOPSIS
    切换 Clash 模式 (Rule/Global/Direct)
    #>
    param([ValidateSet("rule","global","direct")][string]$Mode = "global")

    $body = @{ mode = $Mode } | ConvertTo-Json
    $null = Invoke-RestMethod "$CLASH_API/configs" -Headers $HEADERS -Method PATCH `
        -Body $body -ContentType "application/json" -TimeoutSec 5

    # 如果在 Global 模式，把所有流量导向 Proxy 组
    if ($Mode -eq "global") {
        $data = Get-ClashProxies
        if ($data.groups.ContainsKey("GLOBAL")) {
            $proxyNode = $data.groups["GLOBAL"].now
            if ($proxyNode -eq "DIRECT") {
                $candidates = $data.groups["GLOBAL"].all | Where-Object { $_ -notin @('DIRECT','REJECT') }
                if ($candidates.Count -gt 0) {
                    $pick = $candidates | Get-Random
                    $body2 = @{ name = $pick } | ConvertTo-Json
                    $null = Invoke-RestMethod "$CLASH_API/proxies/GLOBAL" -Headers $HEADERS -Method PUT `
                        -Body $body2 -ContentType "application/json" -TimeoutSec 5
                    Write-Output "[Clash] GLOBAL → $pick (auto-selected)"
                }
            }
        }
    }

    Write-Output "[Clash] Mode → $Mode"
}

function Switch-ClashProxy {
    <#
    .SYNOPSIS
    一键切换 IP — 选一个随机的目标地区节点，断开旧连接
    .PARAMETER Region
    地区关键词 (HK/JP/SG/US/TW/KR/RU/TR/UK/AR)，不指定则完全随机
    #>
    param([string]$Region = $null)

    $data = Get-ClashProxies
    $groupName = "Proxy"

    if (-not $data.groups.ContainsKey($groupName)) {
        Write-Error "找不到 Proxy 组"
        return
    }

    $allNodes = $data.groups[$groupName].all | Where-Object {
        $_ -notin @('DIRECT', 'REJECT', $data.groups[$groupName].now)
    }

    if ($Region) {
        $regionMap = @{
            "HK" = "香港"; "JP" = "日本"; "SG" = "新加坡"
            "US" = "美国"; "TW" = "台湾"; "KR" = "韩国"
            "RU" = "俄罗斯"; "TR" = "土耳其"; "UK" = "英国"
            "AR" = "阿根廷"; "MY" = "马来西亚"
        }
        $keyword = if ($regionMap.ContainsKey($Region.ToUpper())) { $regionMap[$Region.ToUpper()] } else { $Region }
        $candidates = $allNodes | Where-Object { $_ -match $keyword }
        if ($candidates.Count -eq 0) {
            Write-Warning "地区 '$Region' 无匹配节点，从所有节点随机选"
            $candidates = $allNodes
        }
    } else {
        $candidates = $allNodes
    }

    if ($candidates.Count -eq 0) {
        Write-Warning "无可选节点"
        return
    }

    $pick = $candidates | Get-Random
    Set-ClashProxy -GroupName $groupName -NodeName $pick

    # 断开旧连接，强制新连接使用新 IP
    try {
        $null = Invoke-RestMethod "$CLASH_API/connections" -Headers $HEADERS -Method DELETE -TimeoutSec 5
        Write-Output "[Clash] 已断开所有旧连接"
    } catch {
        # 忽略
    }

    return $pick
}

function Enable-ClashProxyEnv {
    <#
    .SYNOPSIS
    设置 PowerShell 环境变量，让所有 Web 请求走 Clash 代理
    #>
    $env:HTTP_PROXY = $CLASH_PROXY
    $env:HTTPS_PROXY = $CLASH_PROXY
    $env:NO_PROXY = "localhost,127.0.0.1,::1"
    Write-Output "[Clash] 代理环境变量已设置 (HTTP_PROXY=$CLASH_PROXY)"
}

function Disable-ClashProxyEnv {
    <#
    .SYNOPSIS
    清除代理环境变量
    #>
    $env:HTTP_PROXY = $null
    $env:HTTPS_PROXY = $null
    $env:NO_PROXY = $null
    Write-Output "[Clash] 代理环境变量已清除"
}

# 自动导出函数
Export-ModuleMember -Function Get-ClashProxies, Set-ClashProxy, Set-ClashMode, Switch-ClashProxy, Enable-ClashProxyEnv, Disable-ClashProxyEnv

Write-Output "[Clash] 助手已加载。可用命令:"
Write-Output "  Get-ClashProxies     - 查看所有节点和组"
Write-Output "  Switch-ClashProxy    - 随机切换 IP (地区: HK/JP/SG/US/TW/KR)"
Write-Output "  Set-ClashProxy       - 指定节点"
Write-Output "  Set-ClashMode        - 切换模式 (rule/global/direct)"
Write-Output "  Enable-ClashProxyEnv - 设置 PowerShell 代理环境变量"
Write-Output "  Disable-ClashProxyEnv- 清除代理环境变量"
