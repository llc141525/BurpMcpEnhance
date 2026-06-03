"""Extract sign-in related code from JS bundle."""
import urllib.request
import re

url = 'https://skl.tzc.edu.cn/js/app.cdfa0260.js'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
content = urllib.request.urlopen(req, timeout=15).read().decode('utf-8', errors='ignore')

# Search for addSignInTask and surrounding context
for keyword in ['addSignInTask', 'addSignInRecord', 'getSignInTaskList', 'getSignInHistory',
                 'signInTask', 'signInRecord', 'uploadPictures']:
    matches = [(m.start(), m.group()) for m in re.finditer(re.escape(keyword), content)]
    if matches:
        print(f'\n=== {keyword} ({len(matches)} matches) ===')
        for start, match in matches[:5]:
            ctx = content[max(0,start-200):start+len(match)+400]
            print(f'--- Context at offset {start} ---')
            print(ctx[:600])
            print('...')

# Also search for parameter patterns in API calls
print('\n\n=== API call patterns around signIn ===')
api_patterns = re.finditer(r'(/(?:skl/)?signIn\w*/?\w*)[\"\']?\s*[,\)]', content)
for m in api_patterns:
    start = m.start()
    ctx = content[max(0,start-100):start+200]
    print(ctx[:300])
    print('---')
