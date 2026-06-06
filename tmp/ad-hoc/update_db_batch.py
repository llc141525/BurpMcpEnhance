"""Batch update DB with latest scrapling results."""
import sqlite3, json, uuid, sys
from datetime import datetime

db = r'E:\SRC挖掘\SRC\.claude\skills\stealth-scanner\scanner.db'
c = sqlite3.connect(db)
c.execute('PRAGMA busy_timeout=5000')
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# === 1. Mark visited: empty subdomain 200s ===
empty_200s = [
    'https://diandu.mypep.cn', 'https://book.mypep.cn', 'https://spokenenglish.mypep.cn',
    'https://px.pep.com.cn', 'https://ebook.pep.com.cn', 'https://hd.pep.com.cn',
    'https://image.mypep.cn', 'https://bsk-tj.mypep.cn', 'https://dianducs.mypep.cn',
    'https://i.mypep.cn', 'https://rjddsz.mypep.cn', 'https://szgs.pep.com.cn',
    'https://zxxszhjx.pep.com.cn',
]

for url in empty_200s:
    c.execute("UPDATE pages SET status='visited', title='empty_subdomain', crawled_at=? WHERE url=? AND status='queued'", (now, url))

# === 2. Mark 403/503 visited ===
failed_urls = [
    'https://zy.pep.com.cn', 'https://tp.pep.com.cn',  # 403
    'https://ex.mypep.cn', 'https://exdata.mypep.cn', 'https://gxadmin.mypep.cn',  # 503
    'https://rjszgsres.mypep.cn', 'https://yuncdn.peplexue.com',  # 403
]
for url in failed_urls:
    c.execute("UPDATE pages SET status='visited', title='blocked_waf', crawled_at=? WHERE url=? AND status='queued'", (now, url))

# === 3. Mark 000/unreachable as visited ===
dead_urls = [
    'https://api.gopep.cn', 'https://bd1.pep.com.cn', 'https://dteduadmin.gopep.cn',
    'https://info.gopep.cn', 'https://mx.pep.com.cn', 'https://rjdd.mypep.cn',
    'https://rjddressz.mypep.cn', 'https://rjddw.mypep.cn', 'https://rjyytbl.mypep.cn',
    'https://szxy.tj.mypep.cn', 'https://tj.mypep.cn',
    'https://manager.pepchangdu.com', 'https://bd.pep.com.cn',
]
for url in dead_urls:
    c.execute("UPDATE pages SET status='visited', title='unreachable_or_redirect', crawled_at=? WHERE url=? AND status='queued'", (now, url))

# === 4. Mark brute force noise as visited ===
brute_noise = [
    'https://www.pep.com.cn/!.htaccess', 'https://www.pep.com.cn/.0', 'https://www.pep.com.cn/.asp',
]
for url in brute_noise:
    c.execute("UPDATE pages SET status='visited', title='brute_noise', crawled_at=? WHERE url=? AND status='queued'", (now, url))

# === 5. Update jcyjfk pages ===
c.execute("UPDATE pages SET status='visited', title='jcyjfk论坛_登录页', links_found=5, crawled_at=? WHERE url='https://jcyjfk.pep.com.cn/member.php?mod=logging&action=login'", (now,))
c.execute("UPDATE pages SET status='visited', title='jcyjfk论坛_注册_SSO跳转', crawled_at=? WHERE url='https://jcyjfk.pep.com.cn/member.php?mod=register'", (now,))
c.execute("UPDATE pages SET status='visited', title='jcyjfk论坛_首页', links_found=5, crawled_at=? WHERE url='https://jcyjfk.pep.com.cn/forum.php?mod=index'", (now,))

# === 6. Update jiaoyan article ===
c.execute("UPDATE pages SET status='visited', title='教研平台_文章页', crawled_at=? WHERE url='https://jiaoyan.pep.com.cn/wqhgcs/202603/t20260319_2005759.html'", (now,))

# === 7. Update user.mypep pages ===
c.execute("UPDATE pages SET status='visited', title='SSO_密码找回', links_found=0, crawled_at=? WHERE url='https://user.mypep.com.cn/index.php?/passport/question'", (now,))
c.execute("UPDATE pages SET status='visited', title='SSO_注册', links_found=0, crawled_at=? WHERE url='https://user.mypep.com.cn/index.php?/passport/reg'", (now,))
c.execute("UPDATE pages SET status='visited', title='SSO_登录页', links_found=0, crawled_at=? WHERE url='https://user.mypep.com.cn'", (now,))

# === 8. Update jcyjfk forum.php?mod=guide&view=my ===
c.execute("UPDATE pages SET status='visited', title='jcyjfk_论坛指南', crawled_at=? WHERE url='https://jcyjfk.pep.com.cn/forum.php?mod=guide&view=my'", (now,))

# === 9. Queue new JS files for analysis ===
js_queue = [
    ('https://jcyjfk.pep.com.cn/static/js/common.js?c7t', 'https://jcyjfk.pep.com.cn'),
    ('https://jcyjfk.pep.com.cn/static/js/sso/peppassport.js', 'https://jcyjfk.pep.com.cn'),
    ('https://jcyjfk.pep.com.cn/static/js/sso/loginfuntion.js', 'https://jcyjfk.pep.com.cn'),
    ('https://jcyjfk.pep.com.cn/static/js/forum.js?c7t', 'https://jcyjfk.pep.com.cn'),
    ('https://jcyjfk.pep.com.cn/static/js/logging.js?c7t', 'https://jcyjfk.pep.com.cn'),
    ('https://user.mypep.com.cn/js/jquery-1.9.1.min.js', 'https://user.mypep.com.cn'),
    ('https://user.mypep.com.cn/js/peppassport.js', 'https://user.mypep.com.cn'),
    ('https://user.mypep.com.cn/js/time_js.js', 'https://user.mypep.com.cn'),
    ('https://www.pep.com.cn/images/jquery_pep.js', 'https://jiaoyan.pep.com.cn'),
    ('https://bd-st.mypep.cn/js/points-u.js', 'https://jcyjfk.pep.com.cn'),
]
imported_js = 0
for js_url, page_url in js_queue:
    c.execute("INSERT OR IGNORE INTO js_files (url, page_url, analyzed) VALUES (?, ?, 0)", (js_url, page_url))
    if c.total_changes > 0:
        imported_js += 1

# === 10. Write suspicious points for forum ===
forms_data = {
    'formhash': 'Discuz! formhash CSRF token (hidden field, dynamic per session)',
    'session_id': 'PHP session ID in login form (hidden)',
    'validcode': 'Captcha field in forum login',
    'referer': 'Hidden referer field in login form',
}

sp_count = 0
for param, evidence in forms_data.items():
    sp_id = f"SP-FORUM-{uuid.uuid4().hex[:8]}"
    c.execute("""INSERT OR IGNORE INTO suspicious_points
        (id, page_url, url, param, test_type, evidence, source, risk, created_at)
        VALUES (?, ?, ?, ?, 'idor_or_csrf', ?, 'bfs_crawl', 'Medium', ?)""",
        (sp_id, 'https://jcyjfk.pep.com.cn', 'https://jcyjfk.pep.com.cn/member.php?mod=logging&action=login',
         param, evidence, now))
    if c.total_changes > 0:
        sp_count += 1

# === 11. SSO注册表单可疑点 ===
sp_id = f"SP-SSO-{uuid.uuid4().hex[:8]}"
c.execute("""INSERT OR IGNORE INTO suspicious_points
    (id, page_url, url, param, test_type, evidence, source, risk, created_at)
    VALUES (?, ?, ?, ?, 'captcha', ?, 'bfs_crawl', 'Medium', ?)""",
    (sp_id, 'https://user.mypep.com.cn', 'https://user.mypep.com.cn/index.php?/passport/reg',
     'validcode', 'SSO注册页含邮箱验证码+图形验证码', now))
if c.total_changes > 0:
    sp_count += 1

# === 12. www.pepchangdu.com 301→ddb.peeavp.com.cn ===
c.execute("UPDATE pages SET status='visited', title='pepchangdu_301_to_ddb', crawled_at=? WHERE url='https://www.pepchangdu.com' AND status='queued'", (now,))
c.execute("UPDATE pages SET status='visited', title='ddb_peeavp_PC版首页', links_found=1, crawled_at=? WHERE url='https://www.pepchangdu.com' AND status='queued'", (now,))

c.commit()

# === Summary ===
total = c.execute('SELECT count(*) FROM pages').fetchone()[0]
queued = c.execute("SELECT count(*) FROM pages WHERE status='queued'").fetchone()[0]
visited = c.execute("SELECT count(*) FROM pages WHERE status='visited'").fetchone()[0]
js_queued = c.execute("SELECT count(*) FROM js_files WHERE analyzed=0").fetchone()[0]
sp_total = c.execute("SELECT count(*) FROM suspicious_points").fetchone()[0]
c.close()

print(json.dumps({
    'total': total, 'queued': queued, 'visited': visited,
    'js_new': imported_js, 'js_unanalyzed': js_queued,
    'sp_new': sp_count, 'sp_total': sp_total,
}))
