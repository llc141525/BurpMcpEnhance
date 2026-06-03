# SRC 项目记忆 — 黑板模式

## ── 静态配置 ──
- [env/proxy.md](env/proxy.md) — Clash 代理、IP 轮换、各通道方案
- [env/mcp-config.md](env/mcp-config.md) — MCP 服务器配置
- [workflow/methodology.md](workflow/methodology.md) — 标准工作流 + 升级触发条件

## ── 目标情报 ──
- [intel/台州学院.md](intel/台州学院.md) — 锐捷 CAS 端点树、ECB 加密栈、攻击面

## ── 归档（已完成目标）──
- [archive/货讯通科技.md](archive/货讯通科技.md) — 40 findings, OOCL/CargoSmart/Weikayun
- [archive/智德校园.md](archive/智德校园.md) — IDOR 55万学生数据+账号接管，edu拒收（企业资产），DES硬编码密钥
- [archive/德能管家水卡充值系统.md](archive/德能管家水卡充值系统.md) — 补天高危×2均降级（中危+低危），合计300荣誉币，水卡完结

## ── session 黑板（运行时生成）──
- boards/{target}/{role}.md — 各 Specialist 写自己的格

## ── lessons（运行时积累）──
- lessons/{target}/  — per-target 经验教训，完结后 compress 入 archive

## ── 边界规则 ──
- env/ + workflow/: AI 永不修改，仅 operator 变更
- boards/{target}/{role}.md: 只追加，不覆盖
- lessons/{target}/: 任何 Specialist 可在运行中追加
- archive/: 仅 compress-lessons skill 写入，写入后不可变
- MEMORY.md: 仅 compress-lessons 或迁移时修改
- archive 最多保留 20 个，超出删最旧
