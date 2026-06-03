"""Quick HTTP probe of remaining unprobed subdomains."""
import subprocess, concurrent.futures, json

domains = [
    'bd.pep.com.cn', 'bd1.pep.com.cn', 'mx.pep.com.cn', 'zxxszhjx.pep.com.cn',
    'szgs.pep.com.cn', 'ex.mypep.cn', 'exdata.mypep.cn', 'gxadmin.mypep.cn',
    'info.gopep.cn', 'api.gopep.cn', 'dteduadmin.gopep.cn', 'www.pepchangdu.com',
    'yuncdn.peplexue.com', 'rjdd.mypep.cn', 'rjddressz.mypep.cn', 'rjddsz.mypep.cn',
    'rjddw.mypep.cn', 'rjyytbl.mypep.cn', 'szxy.tj.mypep.cn', 'tj.mypep.cn',
    'i.mypep.cn', 'bsk-tj.mypep.cn', 'dianducs.mypep.cn', 'rjszgsres.mypep.cn',
]

def probe(d):
    try:
        r = subprocess.run(
            ['curl', '-sk', '--max-time', '8', '-o', '/dev/null', '-w', '%{http_code}\t%{size_download}',
             f'https://{d}', '-H', 'User-Agent: Mozilla/5.0'],
            capture_output=True, text=True, timeout=15)
        parts = r.stdout.strip().split('\t')
        return {'domain': d, 'code': parts[0] if parts else '000', 'size': parts[1] if len(parts) > 1 else '0'}
    except Exception as e:
        return {'domain': d, 'code': 'ERR', 'size': '0', 'error': str(e)[:60]}

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futures = {ex.submit(probe, d): d for d in domains}
    results = [f.result() for f in concurrent.futures.as_completed(futures)]

results.sort(key=lambda r: (0 if r['code'].startswith('2') else 1 if r['code'].startswith('3') else 2 if r['code'].startswith('4') else 3, r['domain']))
for r in results:
    print(f"{r['code']:>3}  {r['size']:>6}  {r['domain']}")
