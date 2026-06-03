"""Batch process scrapling_fetch.py results into scanner.db.
Usage: python3 TOOLS/batch_crawl_result.py < json_results.json

JSON input: array of {url, status, links[], forms[], js_files[], apis[], suspicious_params[], title?}
"""

import json, sys, sqlite3, os
from datetime import datetime

DB = os.path.join(os.path.dirname(__file__), '..', '.claude', 'skills', 'stealth-scanner', 'scanner.db')

def main():
    data = json.load(sys.stdin)
    if not isinstance(data, list):
        data = [data]

    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA busy_timeout=5000")
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Get visited URLs to skip
    visited = set(row[0] for row in conn.execute("SELECT url FROM pages WHERE status='visited'").fetchall())
    queued = set(row[0] for row in conn.execute("SELECT url FROM pages WHERE status='queued'").fetchall())
    all_known = visited | queued

    new_links_all = []
    visited_urls = []

    for page in data:
        url = page.get('url', '')
        status = page.get('status', 0)
        if status < 200:
            continue

        links = [l for l in page.get('links', []) if l.startswith('https://')]
        forms = page.get('forms', [])
        js_files = page.get('js_files', [])
        apis = page.get('apis', [])
        suspicious = page.get('suspicious_params', [])
        title = page.get('title', '')

        visited_urls.append(url)
        new_links_all.extend(links)

        # Update page as visited
        conn.execute("""UPDATE pages SET status='visited', title=?, links_found=?,
            forms_json=?, js_files_json=?, api_calls_json=?, suspicious_params_json=?,
            crawled_at=? WHERE url=?""", (
            title, len(links),
            json.dumps(forms, ensure_ascii=False),
            json.dumps(js_files, ensure_ascii=False),
            json.dumps(apis, ensure_ascii=False),
            json.dumps(suspicious, ensure_ascii=False),
            now, url
        ))
        if conn.total_changes == 0:
            # URL not in DB yet, insert+update
            conn.execute("INSERT OR IGNORE INTO pages (url, depth, status) VALUES (?, 0, 'queued')", (url,))
            conn.execute("""UPDATE pages SET status='visited', title=?, links_found=?,
                forms_json=?, js_files_json=?, api_calls_json=?, suspicious_params_json=?,
                crawled_at=? WHERE url=?""", (
                title, len(links),
                json.dumps(forms, ensure_ascii=False),
                json.dumps(js_files, ensure_ascii=False),
                json.dumps(apis, ensure_ascii=False),
                json.dumps(suspicious, ensure_ascii=False),
                now, url
            ))

        # Insert new JS files
        for js in js_files:
            conn.execute("INSERT OR IGNORE INTO js_files (url, page_url) VALUES (?, ?)", (js, url))

        # Insert suspicious points
        for sp in suspicious:
            sp_id = f"SP-{abs(hash(url+str(sp))):x}"[:16]
            conn.execute("""INSERT OR IGNORE INTO suspicious_points
                (id, page_url, url, param, method, test_type, evidence, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'scanner', ?)""", (
                sp_id, url, url,
                sp.get('param', ''), sp.get('method', 'GET'),
                sp.get('test_type', 'unknown'), sp.get('evidence', ''),
                now
            ))

    # Determine max depth from source pages
    depth_map = {}
    for url in visited_urls:
        row = conn.execute("SELECT depth FROM pages WHERE url=?", (url,)).fetchone()
        depth_map[url] = row[0] if row else 0

    # Insert new links (depth+1)
    max_depth_setting = conn.execute("SELECT max_depth FROM scan_state WHERE id=1").fetchone()
    max_depth = max_depth_setting[0] if max_depth_setting else 3

    new_count = 0
    for link in new_links_all:
        if link not in all_known:
            # Determine depth: find which source page it came from
            for src_url, depth in depth_map.items():
                if link.startswith(src_url.rstrip('/').rsplit('/', 1)[0]) or link in page.get('links', []):
                    break
            depth = min(depth + 1, max_depth)

            if depth < max_depth:
                conn.execute("INSERT OR IGNORE INTO pages (url, depth, status) VALUES (?, ?, 'queued')", (link, depth))
                new_count += 1
                all_known.add(link)

    conn.commit()

    # Update scan_state counts
    total_pages = conn.execute("SELECT count(*) FROM pages").fetchone()[0]
    total_visited = conn.execute("SELECT count(*) FROM pages WHERE status='visited'").fetchone()[0]
    total_queued = conn.execute("SELECT count(*) FROM pages WHERE status='queued'").fetchone()[0]
    conn.execute("""UPDATE scan_state SET
        total_pages=?, total_js=(SELECT count(*) FROM js_files),
        total_suspicious=(SELECT count(*) FROM suspicious_points)
        WHERE id=1""", (total_pages,))
    conn.commit()
    conn.close()

    print(json.dumps({
        "visited": len(visited_urls),
        "new_links_added": new_count,
        "total_visited": total_visited,
        "total_queued": total_queued,
        "total_pages": total_pages,
        "js_files_added": sum(len(page.get('js_files', [])) for page in data)
    }))

if __name__ == '__main__':
    main()
