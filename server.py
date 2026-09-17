import hashlib
import base64
import struct
import os
import time
import threading
import json
import xml.etree.ElementTree as ET
from flask import Flask, request
from Crypto.Cipher import AES
from dotenv import load_dotenv
import requests

load_dotenv()

# 从环境变量加载微信服务器配置
TOKEN = os.environ["WECHAT_TOKEN"]
ENCODING_AES_KEY = os.environ["WECHAT_ENCODING_AES_KEY"]
CORP_ID = os.environ["CorpTD"]
SECRET = os.environ["Secret"]

WECHAT_API_BASE = "https://qyapi.weixin.qq.com/cgi-bin"
CURSOR_FILE = "cursors.json"

app = Flask(__name__)

# 缓存 access_token，避免频繁调用 gettoken 接口
_token_cache = {"access_token": None, "expires_at": 0.0}
_token_lock = threading.Lock()

# 记录每个客服账号（open_kfid）已同步到的位置，用于增量拉取消息
_cursor_store: dict[str, str] = {}
_cursor_lock = threading.Lock()


def _load_cursors() -> None:
    """启动时从文件加载已保存的游标"""
    global _cursor_store
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, "r", encoding="utf-8") as f:
                _cursor_store = json.load(f)
            print(f"[startup] loaded cursors: {_cursor_store}")
        except Exception as e:
            print(f"[startup] failed to load cursors: {e}")


def _save_cursors() -> None:
    """更新游标后保存到文件"""
    with _cursor_lock:
        try:
            with open(CURSOR_FILE, "w", encoding="utf-8") as f:
                json.dump(_cursor_store, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[save_cursors] error: {e}")


def _aes_decrypt(encoding_aes_key: str, encrypted: str) -> str:
    # 使用 AES-256-CBC 解密微信推送内容（GET 校验的 echostr 与 POST 回调的 Encrypt 字段通用）
    key = base64.b64decode(encoding_aes_key + "=")  # 32 字节的 AES-256 密钥
    iv = key[:16]  # 使用密钥的前 16 字节作为初始化向量
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(base64.b64decode(encrypted))
    # 移除 PKCS7 填充
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    # 提取消息内容：16字节随机数 | 4字节大端序长度 | 内容 | appid
    msg_len = struct.unpack(">I", plaintext[16:20])[0]
    return plaintext[20 : 20 + msg_len].decode("utf-8")


def _parse_xml(xml_bytes: bytes) -> dict:
    # 将简单的一层 XML（<xml><Tag>...</Tag>...</xml>）转成字典
    root = ET.fromstring(xml_bytes)
    return {child.tag: child.text for child in root}


def get_access_token() -> str:
    # 获取并缓存 access_token，提前 60 秒过期以留出安全余量
    with _token_lock:
        now = time.time()
        if _token_cache["access_token"] and now < _token_cache["expires_at"]:
            return _token_cache["access_token"]

        resp = requests.get(
            f"{WECHAT_API_BASE}/gettoken",
            params={"corpid": CORP_ID, "corpsecret": SECRET},
            timeout=5,
        )
        data = resp.json()
        if data.get("errcode"):
            raise RuntimeError(f"gettoken failed: {data}")

        _token_cache["access_token"] = data["access_token"]
        _token_cache["expires_at"] = now + data["expires_in"] - 60
        return _token_cache["access_token"]


def sync_msg(kf_token: str, open_kfid: str) -> list[dict]:
    # 拉取指定客服账号自上次游标之后的全部新消息
    access_token = get_access_token()
    cursor = _cursor_store.get(open_kfid, "")
    msgs = []

    while True:
        resp = requests.post(
            f"{WECHAT_API_BASE}/kf/sync_msg",
            params={"access_token": access_token},
            json={"cursor": cursor, "token": kf_token, "open_kfid": open_kfid, "limit": 1000},
            timeout=5,
        )
        data = resp.json()
        if data.get("errcode"):
            raise RuntimeError(f"sync_msg failed: {data}")

        msgs.extend(data.get("msg_list", []))
        cursor = data.get("next_cursor", cursor)
        _cursor_store[open_kfid] = cursor
        _save_cursors()  # 每次更新游标后立即保存

        if not data.get("has_more"):
            break

    return msgs


def send_text_msg(touser: str, open_kfid: str, content: str) -> dict:
    # 给指定客户发送一条文本消息
    access_token = get_access_token()
    resp = requests.post(
        f"{WECHAT_API_BASE}/kf/send_msg",
        params={"access_token": access_token},
        json={
            "touser": touser,
            "open_kfid": open_kfid,
            "msgtype": "text",
            "text": {"content": content},
        },
        timeout=5,
    )
    data = resp.json()
    if data.get("errcode"):
        raise RuntimeError(f"send_msg failed: {data}")
    return data


def download_media(media_id: str, save_dir: str = "downloads") -> dict:
    """
    下载临时素材并保存到本地
    返回: {"success": bool, "filepath": str, "filename": str, "size": int, "error": str}
    """
    access_token = get_access_token()
    url = f"{WECHAT_API_BASE}/media/get"
    params = {"access_token": access_token, "media_id": media_id}

    print(f"[download_media] GET {url}")
    print(f"[download_media] params: {params}")

    resp = requests.get(url, params=params, timeout=10, stream=True)

    print(f"[download_media] status: {resp.status_code}")
    print(f"[download_media] headers: {dict(resp.headers)}")

    # 判断响应类型：JSON 错误 或 二进制流
    content_type = resp.headers.get("Content-Type", "")
    if "application/json" in content_type:
        data = resp.json()
        return {"success": False, "error": data.get("errmsg", "unknown error")}

    # 从 Content-Disposition 提取文件名，若无则用 media_id 生成
    filename = media_id[:16]
    content_disposition = resp.headers.get("Content-Disposition", "")
    print(f"[download_media] Content-Disposition: {repr(content_disposition)}")

    if content_disposition:
        import re
        from urllib.parse import unquote

        # 优先解析 RFC 5987 格式：filename*=utf-8''%E8%B4%A2...
        rfc5987_match = re.search(r"filename\*=utf-8''([^;\r\n]+)", content_disposition)
        if rfc5987_match:
            raw_filename = rfc5987_match.group(1)
            print(f"[download_media] RFC5987 raw filename: {repr(raw_filename)}")
            filename = unquote(raw_filename, encoding="utf-8")
            print(f"[download_media] decoded filename: {repr(filename)}")
        else:
            # 降级到旧格式：filename="..."
            match = re.search(r'filename="?([^";\r\n]+)"?', content_disposition)
            if match:
                raw_filename = match.group(1)
                print(f"[download_media] fallback raw filename: {repr(raw_filename)}")
                filename = unquote(raw_filename, encoding="utf-8")
                print(f"[download_media] decoded filename: {repr(filename)}")

    # 确保保存目录存在
    os.makedirs(save_dir, exist_ok=True)

    # 避免文件名冲突：追加时间戳
    base, ext = os.path.splitext(filename)
    timestamp = int(time.time() * 1000)
    final_filename = f"{base}_{timestamp}{ext}"
    filepath = os.path.join(save_dir, final_filename)

    # 写入文件
    size = 0
    with open(filepath, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                size += len(chunk)

    return {"success": True, "filepath": filepath, "filename": final_filename, "size": size}


def _check_signature(token: str, timestamp: str, nonce: str, echostr: str, sig: str) -> bool:
    # 校验企业微信客服签名：sha1(sort(token, timestamp, nonce, encrypt_msg))
    # 企业微信客服的 msg_signature 计算方法和普通公众号不同
    parts = sorted([token, timestamp, nonce, echostr])
    digest = hashlib.sha1("".join(parts).encode("utf-8")).hexdigest()
    return digest == sig


@app.route("/wechat/callback", methods=["GET"])
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
    if not _check_signature(TOKEN, ts, nonce, echostr, sig):
        print("[verify] signature mismatch")
        return "Invalid signature", 403

    try:
        # 解密 echostr 并原样返回，完成握手验证
        plaintext = _aes_decrypt(ENCODING_AES_KEY, echostr)
        print(f"[verify] OK, returning echostr plaintext: {plaintext}")
        return plaintext
    except Exception as e:
        print(f"[verify] decrypt error: {e}")
        return str(e), 400


@app.route("/wechat/callback", methods=["POST"])
def receive():
    # 接收微信推送的回调事件（外层是加密包裹，需解密出内层事件 XML）
    sig = request.args.get("msg_signature", "")
    ts = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")

    outer = _parse_xml(request.data)
    encrypt = outer.get("Encrypt", "")

    if not _check_signature(TOKEN, ts, nonce, encrypt, sig):
        print("[receive] signature mismatch")
        return "Invalid signature", 403

    try:
        plaintext = _aes_decrypt(ENCODING_AES_KEY, encrypt)
        event = _parse_xml(plaintext.encode("utf-8"))
    except Exception as e:
        print(f"[receive] decrypt error: {e}")
        return str(e), 400

    print(f"[receive] event={event}")

    if event.get("MsgType") == "event" and event.get("Event") == "kf_msg_or_event":
        _handle_kf_event(event["Token"], event["OpenKfId"])

    return "success"


def _handle_kf_event(kf_token: str, open_kfid: str) -> None:
    # 拉取新消息，打印后对客户主动发来的消息统一回复（文件类消息下载并告知详情）
    try:
        msgs = sync_msg(kf_token, open_kfid)
    except Exception as e:
        print(f"[receive] sync_msg error: {e}")
        return

    for msg in msgs:
        print(f"[receive] msg={msg}")
        if msg.get("origin") == 3:
            msgtype = msg.get("msgtype")
            external_userid = msg["external_userid"]
            reply_text = "成功接收消息"

            # 文件类消息：图片/语音/视频/文件，提取 media_id 并下载
            if msgtype in ["image", "video", "voice", "file"]:
                media_id = msg.get(msgtype, {}).get("media_id")
                if media_id:
                    try:
                        result = download_media(media_id)
                        if result["success"]:
                            if msgtype == "voice":
                                reply_text = "已接收语音消息"
                            else:
                                size_mb = result["size"] / (1024 * 1024)
                                reply_text = f"已成功接收{result['filename']}文件，大小{size_mb:.2f}MB"
                            print(f"[receive] downloaded: {result['filepath']}")
                        else:
                            reply_text = f"文件接收失败：{result['error']}"
                            print(f"[receive] download failed: {result['error']}")
                    except Exception as e:
                        reply_text = f"文件下载异常：{str(e)}"
                        print(f"[receive] download exception: {e}")

            try:
                send_text_msg(external_userid, open_kfid, reply_text)
            except Exception as e:
                print(f"[receive] send_msg error: {e}")


if __name__ == "__main__":
    _load_cursors()  # 启动时加载已保存的游标
    print("Starting on https://0.0.0.0:1681")
    print("Callback path: /wechat/callback")
    app.run(host="0.0.0.0", port=1681, debug=True, use_reloader=False)
