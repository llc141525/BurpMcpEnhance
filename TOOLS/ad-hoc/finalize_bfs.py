"""Finalize BFS, mark remaining pages, record findings."""
import sqlite3, json, uuid
from datetime import datetime

db = r'E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db'
c = sqlite3.connect(db)
c.execute('PRAGMA busy_timeout=5000')
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# 1. Mark remaining 4 pages as visited
final_pages = {
    'https://api-jxy.peeavp.com.cn': 'APISIX_admin_api_previously_scanned',
    'https://wechattest02.pep.com.cn': 'Tencent_WAF_420_blocked',
    'https://www.mypep.cn': 'redirects_to_rjdiandu_pointedu',
    'https://rjszgsres.mypep.cn/rjzhpt/': 'auto_trigger_EXE_download',
}
for url, title in final_pages.items():
    c.execute("UPDATE pages SET status='visited', title=?, crawled_at=? WHERE url=? AND status='queued'", (title, now, url))

# 2. Record rjdiandu SPA findings
# 2a. Queue SPA JS files for reference
spa_js = [
    ('https://rjdiandu.mypep.cn/dist/static/js/chunk-vendors.90188ed8.js', 'https://rjdiandu.mypep.cn'),
    ('https://rjdiandu.mypep.cn/dist/static/js/index.3e487724.js', 'https://rjdiandu.mypep.cn'),
]
for js_url, page_url in spa_js:
    c.execute("INSERT OR IGNORE INTO js_files (url, page_url, analyzed) VALUES (?, ?, 0)", (js_url, page_url))

# 2b. Record obfuscation finding
sp_id = f"SP-RJDIANDU-{uuid.uuid4().hex[:8]}"
c.execute("""INSERT OR IGNORE INTO suspicious_points
    (id, page_url, url, param, test_type, evidence, source, risk, created_at)
    VALUES (?, ?, ?, ?, 'js_obfuscation', ?, 'bfs_crawl', 'Info', ?)""",
    (sp_id, 'https://rjdiandu.mypep.cn', 'https://rjdiandu.mypep.cn/dist/static/js/index.3e487724.js',
     'app_js', '人教点读 SPA 使用 uni-app 构建，app JS 和 vendors JS 均被完全混淆（a0_0x1d52 字符串编码）。API 端点/路由无法静态提取', now))

# 2c. Track SPA as new page
c.execute("INSERT OR IGNORE INTO pages (url, depth, status, title) VALUES (?, 0, 'visited', ?)",
          ('https://rjdiandu.mypep.cn', '人教点读 VUE_SPA_uni-app'))

# 3. Record ddb.peeavp.com.cn → pepchangdu redirect finding
sp_id2 = f"SP-PEPCHANGDU-{uuid.uuid4().hex[:8]}"
c.execute("""INSERT OR IGNORE INTO suspicious_points
    (id, page_url, url, param, test_type, evidence, source, risk, created_at)
    VALUES (?, ?, ?, ?, 'redirect_chain', ?, 'bfs_crawl', 'Low', ?)""",
    (sp_id2, 'https://www.pepchangdu.com', 'https://www.pepchangdu.com',
     '301', 'pepchangdu.com 301 重定向到 ddb.peeavp.com.cn (成都 peplinux 服务器)，疑似同机部署', now))

# 4. Update scan_state to scanning
c.execute("""UPDATE scan_state SET
    phase='scanning',
    spider_ended_at=?,
    total_pages=(SELECT count(*) FROM pages),
    total_js=(SELECT count(*) FROM js_files),
    total_suspicious=(SELECT count(*) FROM suspicious_points)
    WHERE id=1""", (now,))

c.commit()

# Summary
total = c.execute('SELECT count(*) FROM pages').fetchone()[0]
visited = c.execute("SELECT count(*) FROM pages WHERE status='visited'").fetchone()[0]
queued = c.execute("SELECT count(*) FROM pages WHERE status='queued'").fetchone()[0]
js = c.execute("SELECT count(*) FROM js_files").fetchone()[0]
sp = c.execute("SELECT count(*) FROM suspicious_points").fetchone()[0]
phase = c.execute("SELECT phase FROM scan_state WHERE id=1").fetchone()[0]
c.close()

print(json.dumps({
    'phase': phase, 'total_pages': total, 'visited': visited,
    'queued': queued, 'js_files': js, 'suspicious_points': sp,
}))
