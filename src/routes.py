"""Flask 路由定义：微信回调验证/接收、测试文件下载、大文件上传表单与接收"""

import os
import time

from flask import Blueprint, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

import config

from . import crypto, message, upload, wechat_api

FILES_DIR = "files"

bp = Blueprint("wechat", __name__)

# 运行期凭证，由 configure() 在应用启动时注入
_credentials = {"token": None, "encoding_aes_key": None}


def configure(token: str, encoding_aes_key: str) -> None:
    """注入微信回调校验所需的 Token / EncodingAESKey，须在应用启动时执行一次"""
    _credentials["token"] = token
    _credentials["encoding_aes_key"] = encoding_aes_key


_UPLOAD_FORM_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>文件上传</title></head>
<body>
<h3>请选择要上传的文件</h3>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">上传</button>
</form>
</body></html>"""


@bp.route("/files/<path:filename>", methods=["GET"])
def serve_file(filename):
    # 提供测试文件的公开下载（未做鉴权，仅用于测试环境）
    return send_from_directory(FILES_DIR, filename, as_attachment=True)


@bp.route("/upload/<token>", methods=["GET"])
def upload_form(token):
    # 展示上传表单页面，先校验 token 有效性
    result = upload.load_upload_token(token)
    if not result["valid"]:
        return result["error"], 403
    return _UPLOAD_FORM_HTML


@bp.route("/upload/<token>", methods=["POST"])
def upload_file(token):
    # 接收客户通过专属链接上传的大文件，走独立 HTTP 通道，不受企业微信 20MB 限制
    result = upload.load_upload_token(token)
    if not result["valid"]:
        return result["error"], 403

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return "未选择文件", 400

    os.makedirs(config.UPLOADS_DIR, exist_ok=True)
    filename = upload.safe_upload_filename(uploaded.filename)
    timestamp = int(time.time() * 1000)
    base, ext = os.path.splitext(filename)
    final_filename = f"{base}_{timestamp}{ext}"
    filepath = os.path.join(config.UPLOADS_DIR, final_filename)
    uploaded.save(filepath)

    upload.mark_upload_token_used(token)  # 保存成功后才标记已用，避免上传失败导致链接被提前废弃

    print(f"[upload_file] saved: {filepath} for external_userid={result['external_userid']}")

    try:
        wechat_api.send_text_msg(result["external_userid"], result["open_kfid"], f"已收到文件：{final_filename}")
    except Exception as e:
        print(f"[upload_file] send_msg error: {e}")

    return "上传成功，可以关闭此页面"


@bp.errorhandler(RequestEntityTooLarge)
def handle_upload_too_large(e):
    max_mb = config.UPLOAD_MAX_SIZE / (1024 * 1024)
    return f"文件过大，最大支持{max_mb:.0f}MB", 413


@bp.route("/wechat/callback", methods=["GET"])
def verify():
    # 处理微信服务器 URL 验证请求
    print(f"[verify] All request args: {dict(request.args)}")
    print(f"[verify] Request URL: {request.url}")
    print(f"[verify] User-Agent: {request.headers.get('User-Agent', 'N/A')}")

    sig = request.args.get("msg_signature", "")
    ts = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    echostr = request.args.get("echostr", "")

    print(f"[verify] sig={sig} ts={ts} nonce={nonce} echostr={echostr[:20] if echostr else '(empty)'}...")

    # 签名校验失败则拒绝请求
    if not crypto.check_signature(_credentials["token"], ts, nonce, echostr, sig):
        print("[verify] signature mismatch")
        return "Invalid signature", 403

    try:
        # 解密 echostr 并原样返回，完成握手验证
        plaintext = crypto.aes_decrypt(_credentials["encoding_aes_key"], echostr)
        print(f"[verify] OK, returning echostr plaintext: {plaintext}")
        return plaintext
    except Exception as e:
        print(f"[verify] decrypt error: {e}")
        return str(e), 400


@bp.route("/wechat/callback", methods=["POST"])
def receive():
    # 接收微信推送的回调事件（外层是加密包裹，需解密出内层事件 XML）
    sig = request.args.get("msg_signature", "")
    ts = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")

    outer = crypto.parse_xml(request.data)
    encrypt = outer.get("Encrypt", "")

    if not crypto.check_signature(_credentials["token"], ts, nonce, encrypt, sig):
        print("[receive] signature mismatch")
        return "Invalid signature", 403

    try:
        plaintext = crypto.aes_decrypt(_credentials["encoding_aes_key"], encrypt)
        event = crypto.parse_xml(plaintext.encode("utf-8"))
    except Exception as e:
        print(f"[receive] decrypt error: {e}")
        return str(e), 400

    print(f"[receive] event={event}")

    if event.get("MsgType") == "event" and event.get("Event") == "kf_msg_or_event":
        message.handle_kf_event(event["Token"], event["OpenKfId"])

    return "success"
