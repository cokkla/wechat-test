"""加解密与签名校验：企业微信回调的 AES 解密、XML 解析、消息签名校验"""

import base64
import hashlib
import struct
import xml.etree.ElementTree as ET


def aes_decrypt(encoding_aes_key: str, encrypted: str) -> str:
    # 使用 AES-256-CBC 解密微信推送内容（GET 校验的 echostr 与 POST 回调的 Encrypt 字段通用）
    key = base64.b64decode(encoding_aes_key + "=")  # 32 字节的 AES-256 密钥
    iv = key[:16]  # 使用密钥的前 16 字节作为初始化向量
    from Crypto.Cipher import AES

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(base64.b64decode(encrypted))
    # 移除 PKCS7 填充
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    # 提取消息内容：16字节随机数 | 4字节大端序长度 | 内容 | appid
    msg_len = struct.unpack(">I", plaintext[16:20])[0]
    return plaintext[20 : 20 + msg_len].decode("utf-8")


def parse_xml(xml_bytes: bytes) -> dict:
    # 将简单的一层 XML（<xml><Tag>...</Tag>...</xml>）转成字典
    root = ET.fromstring(xml_bytes)
    return {child.tag: child.text for child in root}


def check_signature(token: str, timestamp: str, nonce: str, echostr: str, sig: str) -> bool:
    # 校验企业微信客服签名：sha1(sort(token, timestamp, nonce, encrypt_msg))
    # 企业微信客服的 msg_signature 计算方法和普通公众号不同
    parts = sorted([token, timestamp, nonce, echostr])
    digest = hashlib.sha1("".join(parts).encode("utf-8")).hexdigest()
    return digest == sig
