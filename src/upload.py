"""大文件上传通道：专属上传链接 token 的签发/校验/核销，以及上传文件名安全处理

用于接收超过企业微信 20MB 上限的大文件，走独立 HTTP 通道而非客服消息接口。
"""

import re

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import config
from . import storage

_serializer: URLSafeTimedSerializer | None = None


def configure(secret_key: str) -> None:
    """初始化 token 签名密钥，须在应用启动时执行一次"""
    global _serializer
    _serializer = URLSafeTimedSerializer(secret_key)


def make_upload_token(external_userid: str, open_kfid: str) -> str:
    # 签发一次性上传链接 token，编码客户与客服账号信息，带签名和时间戳
    return _serializer.dumps({"external_userid": external_userid, "open_kfid": open_kfid})


def load_upload_token(token: str) -> dict:
    """
    校验上传 token：签名、有效期、是否已使用过
    返回: {"valid": bool, "external_userid": str, "open_kfid": str, "error": str}
    """
    try:
        data = _serializer.loads(token, max_age=config.UPLOAD_TOKEN_MAX_AGE)
    except SignatureExpired:
        return {"valid": False, "error": "链接已过期"}
    except BadSignature:
        return {"valid": False, "error": "链接无效"}

    with storage.upload_tokens_lock:
        if token in storage.used_upload_tokens:
            return {"valid": False, "error": "链接已被使用"}

    return {"valid": True, "external_userid": data["external_userid"], "open_kfid": data["open_kfid"]}


def mark_upload_token_used(token: str) -> None:
    with storage.upload_tokens_lock:
        storage.used_upload_tokens.add(token)


def safe_upload_filename(filename: str) -> str:
    # 保留中文等 Unicode 字符（werkzeug.secure_filename 会剥掉），只去掉路径分隔符和危险字符
    filename = filename.replace("\x00", "")
    filename = re.sub(r'[/\\:*?"<>|]', "_", filename)  # 去掉路径分隔符和 Windows 非法字符
    filename = filename.strip(". ")  # 去掉首尾空格和点（防止 ".." 之类）
    return filename or "unnamed"
