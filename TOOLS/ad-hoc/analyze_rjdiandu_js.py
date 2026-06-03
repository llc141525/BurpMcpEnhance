"""Extract API endpoints, routes, config from rjdiandu Vue SPA JS."""
import re, json

js = open(r'C:\Users\llc\AppData\Local\Temp\rjdiandu_main.js', encoding='utf-8').read()

results = {}

# 1. URLs
urls = set(re.findall(r'https?://[a-zA-Z0-9./_?=&%-]+', js))
results['urls'] = sorted(u for u in urls if len(u) > 10 and not u.startswith('https://i05xl') and not u.startswith('https://bd-st'))

# 2. API path patterns
api_paths = set()
for m in re.finditer(r'["\'](/[a-zA-Z0-9/_.-]*(?:api|service|app|gateway|open)[a-zA-Z0-9/_.-]*)["\']', js, re.I):
    api_paths.add(m.group(1))
results['api_paths'] = sorted(api_paths)

# 3. baseURL / domain config
configs = set()
for m in re.finditer(r'(baseURL|baseUrl|BASE_URL|apiUrl|domain|host)[:=]\s*["\']([^"\']+)["\']', js):
    configs.add(f"{m.group(1)} = {m.group(2)}")
results['configs'] = sorted(configs)

# 4. Page routes (Vue Router style)
pages = set()
for m in re.finditer(r'["\'](/pages/[a-zA-Z0-9/_-]+)["\']', js):
    pages.add(m.group(1))
for m in re.finditer(r'path:\s*["\']([^"\']+)["\']', js):
    pages.add(m.group(1))
results['routes'] = sorted(pages)

# 5. Content keys/endpoint patterns
content_patterns = set()
for m in re.finditer(r'["\'](/content/|[a-z]+/[a-z]+/\d+|[a-z]+/[a-z]+/[a-zA-Z0-9_.-]+)["\']', js):
    p = m.group(1)
    if '/' in p and ' ' not in p:
        content_patterns.add(p)
results['content_patterns'] = sorted(content_patterns)

# 6. App IDs / product IDs
ids = set()
for m in re.finditer(r'["\'](\d{6,})["\']', js):
    ids.add(m.group(1))
results['app_ids'] = sorted(ids)

# 7. Key names for API endpoints
keys = set()
for m in re.finditer(r'["\'](\w+_[Uu]rl|\w+_URL|\w+_API|\w+_END[PO]*\w*|api_?\w*)["\']', js):
    keys.add(m.group(1))
results['api_keys'] = sorted(keys)

print(json.dumps(results, ensure_ascii=False, indent=2))
