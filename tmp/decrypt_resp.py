"""解密智德校园 API 响应（DES-64-HEX）
用法:
  python3 tmp/decrypt_resp.py <HEX密文>
  python3 tmp/decrypt_resp.py --file response.hex
  echo "<HEX>" | python3 tmp/decrypt_resp.py --stdin
"""

import sys
import json
from base64 import b64decode
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


KEY = IV = b'a1@998#.'


def hex_to_bytes(hex_str: str) -> bytes:
    hex_str = hex_str.strip()
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)


def decrypt(hex_str: str) -> dict:
    ciphertext = hex_to_bytes(hex_str)
    plaintext = unpad(
        DES.new(KEY, DES.MODE_CBC, IV).decrypt(ciphertext),
        8
    )
    return json.loads(plaintext.decode('utf-8'))


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == '--stdin':
        hex_input = sys.stdin.read()
    elif sys.argv[1] == '--file':
        with open(sys.argv[2], 'r') as f:
            hex_input = f.read()
    else:
        hex_input = sys.argv[1]

    try:
        result = decrypt(hex_input)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"解密失败: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
