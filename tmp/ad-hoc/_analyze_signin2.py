"""Extract addSignInTask function and its callers from JS bundle."""
import urllib.request
import re

url = 'https://skl.tzc.edu.cn/js/app.cdfa0260.js'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
content = urllib.request.urlopen(req, timeout=15).read().decode('utf-8', errors='ignore')

# Find the module that contains addSignInTask
# Pattern: function _(e){return Object(a["a"])("/skl/signIn/addSignInTask","post",e)}
# The function is named '_' which is mapped to 'd' in exports

# Search for the complete module definition around addSignInTask
sign_pattern = r'/skl/signIn/addSignInTask'
match = re.search(sign_pattern, content)
if match:
    start = max(0, match.start() - 3000)
    end = min(len(content), match.end() + 1000)
    ctx = content[start:end]
    print("=== Module containing addSignInTask ===")
    print(ctx)

# Also search for where addSignInTask is USED (callers)
# Look for the export name mapping
print("\n\n=== Searching for export mappings containing 'd' (addSignInTask) ===")
# t.d is the export for addSignInTask
for m in re.finditer(r'n\.d\(t,"d"', content):
    ctx_start = max(0, m.start()-100)
    ctx_end = min(len(content), m.end()+200)
    print(content[ctx_start:ctx_end])
    print('---')

# Search for the Vue component that imports this module
print("\n\n=== Searching for imports of the signIn module ===")
# Look for the chunk that uses these signIn functions
for m in re.finditer(r'"(?:[0-9a-f]+)"[:\s]*function.*signIn', content):
    ctx_start = max(0, m.start()-50)
    ctx_end = min(len(content), m.end()+500)
    print(content[ctx_start:ctx_end])
    print('---')
