import sqlite3, os, json
from datetime import datetime

DB = os.path.expandvars(r'E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db')
conn = sqlite3.connect(DB)
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA busy_timeout=5000;')

now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# SP-MTZX-001: captchaImage - false_positive
conn.execute(
    "UPDATE suspicious_points SET reasoning=?, risk=?, test_status=?, notes=? WHERE id=?",
    (
        '验证码接口GET /prod-api/captchaImage 返回200含base64图片+UUID，此为ZYSZ框架标准设计。验证码必须在登录前公开获取，否则登录页无法工作。',
        'Medium',
        'false_positive',
        '框架设计如此，验证码需公开才能实现登录验证功能',
        'SP-MTZX-001'
    )
)

# SP-MTZX-002: loginUseWlUser - confirmed unauth_access
conn.execute(
    "UPDATE suspicious_points SET reasoning=?, risk=?, test_status=?, notes=? WHERE id=?",
    (
        'GET /prod-api/modules/singleLogin/loginUseWlUser 无需任何认证返回 {"msg":"登录失败，请检查用户权限！","code":500}，POST 返回 405。该单点登录接口应要求认证，但当前完全公开可访问。',
        'Medium',
        'confirmed',
        '单点登录接口未授权访问，返回用户权限错误信息，可用于用户名枚举',
        'SP-MTZX-002'
    )
)

# SP-MTZX-003: druid - confirmed, downgraded to Medium
conn.execute(
    "UPDATE suspicious_points SET reasoning=?, risk=?, test_status=?, notes=? WHERE id=?",
    (
        'Druid监控登录页 /prod-api/druid/login.html 完全公开可访问(200, 3829B HTML)。内部页面 /api.html /datasource.html /basic.json /weburi.json 均 302 跳转到登录页(认证已生效)。admin/admin, druid/druid, admin/123456 等默认密码均返回 "error"。登录页暴露允许攻击者暴力破解 Druid 管理密码。',
        'Medium',
        'confirmed',
        '原标记 High 降为 Medium：内部页面有认证保护，但登录页暴露可暴力破解',
        'SP-MTZX-003'
    )
)

conn.commit()

cur = conn.execute('SELECT id, test_status, risk FROM suspicious_points')
rows = cur.fetchall()
for r in rows:
    print(f'{r[0]}: {r[1]} ({r[2]})')

conn.close()
