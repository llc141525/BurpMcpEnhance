"""加密智德校园 API 请求（DES-64-HEX）
用法:
  python3 tmp/encrypt_req.py '{"USI_Id": 1, "Page_Name": "test"}'
  python3 tmp/encrypt_req.py --payload "{\"USI_Id\": 1}"
  python3 tmp/encrypt_req.py --uid 356387
"""

import sys
import json
import time
import random
import hashlib
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


KEY = IV = b'a1@998#.'
APP_VER = "Android-1.0.32"


def md5_sign(timestamp: str) -> str:
    return hashlib.md5((timestamp + "a1@998#.").encode()).hexdigest().lower()


def make_timestamp() -> str:
    return time.strftime("%Y%m%d%H%M%S") + str(random.randint(10, 99))


def encrypt_payload(payload: dict) -> str:
    plaintext = json.dumps(payload, ensure_ascii=False)
    return (
        DES.new(KEY, DES.MODE_CBC, IV)
        .encrypt(pad(plaintext.encode("utf-8"), 8))
        .hex()
        .upper()
    )


def build_request(uid: int, page_name: str = "test") -> tuple[str, str]:
    """返回 (hex_ciphertext, timestamp)"""
    ts = make_timestamp()
    payload = {
        "USI_Id": uid,
        "Page_Name": page_name,
        "ver": APP_VER,
        "timestamp": ts,
        "sign": md5_sign(ts),
    }
    return encrypt_payload(payload), ts


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    # --uid 模式：直接构造请求
    if sys.argv[1] == "--uid":
        uid = int(sys.argv[2])
        hex_ct, ts = build_request(uid)
        print(f"timestamp: {ts}")
        print(f"sign:     {md5_sign(ts)}")
        print(f"cipher:   {hex_ct}")
        return

    # --payload 模式：加密指定 JSON
    if sys.argv[1] == "--payload":
        payload_str = sys.argv[2]
    else:
        payload_str = sys.argv[1]

    payload = json.loads(payload_str)

    # 自动补 timestamp + sign
    if "timestamp" not in payload:
        ts = make_timestamp()
        payload["timestamp"] = ts
        payload["sign"] = md5_sign(ts)

    hex_ct = encrypt_payload(payload)
    print(hex_ct)


if __name__ == "__main__":
    main()
