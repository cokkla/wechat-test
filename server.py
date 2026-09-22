import hashlib
import base64
import struct
import os
import time
import threading
import json
import xml.etree.ElementTree as ET
from flask import Flask, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from Crypto.Cipher import AES
from dotenv import load_dotenv
import requests

load_dotenv()

import config  # noqa: E402  (需要先加载 .env，config 里要读 URL 环境变量)

# 从环境变量加载微信服务器配置
TOKEN = os.environ["WECHAT_TOKEN"]
ENCODING_AES_KEY = os.environ["WECHAT_ENCODING_AES_KEY"]
CORP_ID = os.environ["CorpTD"]
SECRET = os.environ["Secret"]

WECHAT_API_BASE = "https://qyapi.weixin.qq.com/cgi-bin"
CURSOR_FILE = "cursors.json"
FILES_DIR = "files"
UPLOADS_DIR = config.UPLOADS_DIR

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.UPLOAD_MAX_SIZE

# 用于签发/校验上传链接 token，密钥由现有微信密钥派生，无需额外保存新密钥
_upload_serializer = URLSafeTimedSerializer(hashlib.sha256((TOKEN + ENCODING_AES_KEY).encode("utf-8")).hexdigest())

# 已使用过的上传 token，防止链接被重复使用（进程重启会清空，测试场景可接受）
_used_upload_tokens: set[str] = set()
_upload_tokens_lock = threading.Lock()

# 缓存 access_token，避免频繁调用 gettoken 接口
_token_cache = {"access_token": None, "expires_at": 0.0}
_token_lock = threading.Lock()

# 记录每个客服账号（open_kfid）已同步到的位置，用于增量拉取消息
_cursor_store: dict[str, str] = {}
_cursor_lock = threading.Lock()

# 模拟任务：记录每个客户（external_userid）名下的任务列表，测试 48 小时窗口/配额耗尽后
# 任务结果推送失败、待客户下次发消息再补推的场景。进程重启会清空，测试场景可接受。
# 任务状态：pending（未完成）/ done（已完成）/ pushed（已推送）/ push_failed（已完成但推送失败）
_tasks_by_user: dict[str, list[dict]] = {}
_tasks_lock = threading.Lock()


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


def upload_temp_media(file_path: str, media_type: str = "file") -> str:
    # 上传本地文件为临时素材，返回 media_id（用于后续发送 file 类型消息）
    access_token = get_access_token()
    filename = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        resp = requests.post(
            f"{WECHAT_API_BASE}/media/upload",
            params={"access_token": access_token, "type": media_type},
            files={"media": (filename, f)},
            timeout=10,
        )
    data = resp.json()
    if data.get("errcode"):
        raise RuntimeError(f"media upload failed: {data}")
    return data["media_id"]


def send_link_msg(touser: str, open_kfid: str, title: str, desc: str, url: str, thumb_media_id: str) -> dict:
    # 给指定客户发送一条图文链接消息
    access_token = get_access_token()
    resp = requests.post(
        f"{WECHAT_API_BASE}/kf/send_msg",
        params={"access_token": access_token},
        json={
            "touser": touser,
            "open_kfid": open_kfid,
            "msgtype": "link",
            "link": {
                "title": title,
                "desc": desc,
                "url": url,
                "thumb_media_id": thumb_media_id,
            },
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

    # 从 Content-Disposition 提取文件名，若无则用时间戳
    filename = None
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

    # 检查文件名是否有效（不是空或纯扩展名）
    if filename:
        base = os.path.splitext(filename)[0]
        if not base or base.startswith("."):
            print(f"[download_media] invalid filename (empty or extension-only): {repr(filename)}")
            filename = None

    # 若未能提取有效文件名，根据 Content-Type 推断扩展名，用时间戳作为文件名
    if not filename:
        ext = ".amr"  # 默认扩展名
        content_type = resp.headers.get("Content-Type", "")
        ext_map = {
            "audio/amr": ".amr",
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "video/mp4": ".mp4",
        }
        for ctype, cext in ext_map.items():
            if ctype in content_type:
                ext = cext
                break
        timestamp = int(time.time() * 1000)
        filename = f"{timestamp}{ext}"
        print(f"[download_media] no valid filename found, using timestamp: {filename}")

    # 确保保存目录存在
    os.makedirs(save_dir, exist_ok=True)

    filepath = os.path.join(save_dir, filename)

    # 写入文件
    size = 0
    with open(filepath, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                size += len(chunk)

    return {"success": True, "filepath": filepath, "filename": filename, "size": size}


def _create_task(external_userid: str, content: str) -> dict:
    # 创建一条模拟任务，标记为未完成，登记到该客户名下
    task = {
        "task_id": f"task_{int(time.time() * 1000)}",
        "external_userid": external_userid,
        "content": content,
        "status": "pending",
    }
    with _tasks_lock:
        _tasks_by_user.setdefault(external_userid, []).append(task)
    return task


def _run_task(task: dict, open_kfid: str) -> None:
    # 模拟任务处理过程：依次推送进度提示，延迟模拟处理耗时，完成后推送结果（真实调用发送接口）
    external_userid = task["external_userid"]
    progress_messages = [
        "收到任务",
        "正在检索本地信息...",
        "正在处理信息...",
        "信息不足，正在联网搜索信息作为补充...",
        "信息收集完毕，开始汇总...",
    ]
    for text in progress_messages:
        try:
            send_text_msg(external_userid, open_kfid, text)
        except Exception as e:
            print(f"[task] progress push error task_id={task['task_id']}: {e}")
        time.sleep(config.TASK_PROGRESS_INTERVAL_SECONDS)

    time.sleep(config.TASK_PROCESS_DELAY_SECONDS)
    task["status"] = "done"

    result_text = f"{task['content']}任务已完成"
    try:
        send_text_msg(external_userid, open_kfid, result_text)
        task["status"] = "pushed"
        print(f"[task] pushed task_id={task['task_id']}")
    except Exception as e:
        task["status"] = "push_failed"
        print(f"[task] push failed task_id={task['task_id']}: {e}")


def _push_pending_task_results(external_userid: str, open_kfid: str) -> None:
    # 客户发来新消息时，检查该客户名下是否有"已完成但推送失败"的任务，若有则补推
    with _tasks_lock:
        tasks = _tasks_by_user.get(external_userid, [])
        failed_tasks = [t for t in tasks if t["status"] == "push_failed"]

    for task in failed_tasks:
        result_text = f"{task['content']}任务已完成"
        try:
            send_text_msg(external_userid, open_kfid, result_text)
            task["status"] = "pushed"
            print(f"[task] retry push succeeded task_id={task['task_id']}")
        except Exception as e:
            print(f"[task] retry push failed task_id={task['task_id']}: {e}")


def _check_signature(token: str, timestamp: str, nonce: str, echostr: str, sig: str) -> bool:
    # 校验企业微信客服签名：sha1(sort(token, timestamp, nonce, encrypt_msg))
    # 企业微信客服的 msg_signature 计算方法和普通公众号不同
    parts = sorted([token, timestamp, nonce, echostr])
    digest = hashlib.sha1("".join(parts).encode("utf-8")).hexdigest()
    return digest == sig


def _make_upload_token(external_userid: str, open_kfid: str) -> str:
    # 签发一次性上传链接 token，编码客户与客服账号信息，带签名和时间戳
    return _upload_serializer.dumps({"external_userid": external_userid, "open_kfid": open_kfid})


def _load_upload_token(token: str) -> dict:
    """
    校验上传 token：签名、有效期、是否已使用过
    返回: {"valid": bool, "external_userid": str, "open_kfid": str, "error": str}
    """
    try:
        data = _upload_serializer.loads(token, max_age=config.UPLOAD_TOKEN_MAX_AGE)
    except SignatureExpired:
        return {"valid": False, "error": "链接已过期"}
    except BadSignature:
        return {"valid": False, "error": "链接无效"}

    with _upload_tokens_lock:
        if token in _used_upload_tokens:
            return {"valid": False, "error": "链接已被使用"}

    return {"valid": True, "external_userid": data["external_userid"], "open_kfid": data["open_kfid"]}


def _mark_upload_token_used(token: str) -> None:
    with _upload_tokens_lock:
        _used_upload_tokens.add(token)


def _safe_upload_filename(filename: str) -> str:
    # 保留中文等 Unicode 字符（werkzeug.secure_filename 会剥掉），只去掉路径分隔符和危险字符
    import re

    filename = filename.replace("\x00", "")
    filename = re.sub(r'[/\\:*?"<>|]', "_", filename)  # 去掉路径分隔符和 Windows 非法字符
    filename = filename.strip(". ")  # 去掉首尾空格和点（防止 ".." 之类）
    return filename or "unnamed"


@app.route("/files/<path:filename>", methods=["GET"])
def serve_file(filename):
    # 提供测试文件的公开下载（未做鉴权，仅用于测试环境）
    return send_from_directory(FILES_DIR, filename, as_attachment=True)


_UPLOAD_FORM_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>文件上传</title></head>
<body>
<h3>请选择要上传的文件</h3>
<form method="post" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">上传</button>
</form>
</body></html>"""


@app.route("/upload/<token>", methods=["GET"])
def upload_form(token):
    # 展示上传表单页面，先校验 token 有效性
    result = _load_upload_token(token)
    if not result["valid"]:
        return result["error"], 403
    return _UPLOAD_FORM_HTML


@app.route("/upload/<token>", methods=["POST"])
def upload_file(token):
    # 接收客户通过专属链接上传的大文件，走独立 HTTP 通道，不受企业微信 20MB 限制
    result = _load_upload_token(token)
    if not result["valid"]:
        return result["error"], 403

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return "未选择文件", 400

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    filename = _safe_upload_filename(uploaded.filename)
    timestamp = int(time.time() * 1000)
    base, ext = os.path.splitext(filename)
    final_filename = f"{base}_{timestamp}{ext}"
    filepath = os.path.join(UPLOADS_DIR, final_filename)
    uploaded.save(filepath)

    _mark_upload_token_used(token)  # 保存成功后才标记已用，避免上传失败导致链接被提前废弃

    print(f"[upload_file] saved: {filepath} for external_userid={result['external_userid']}")

    try:
        send_text_msg(result["external_userid"], result["open_kfid"], f"已收到文件：{final_filename}")
    except Exception as e:
        print(f"[upload_file] send_msg error: {e}")

    return "上传成功，可以关闭此页面"


@app.errorhandler(RequestEntityTooLarge)
def handle_upload_too_large(e):
    max_mb = config.UPLOAD_MAX_SIZE / (1024 * 1024)
    return f"文件过大，最大支持{max_mb:.0f}MB", 413


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

            # 客户发来任意消息，先检查名下是否有已完成但推送失败的任务，补推任务结果
            _push_pending_task_results(external_userid, open_kfid)

            text_content = msg.get("text", {}).get("content") if msgtype == "text" else None

            # 文本消息命中"开始任务：xxx"前缀：创建模拟任务并启动处理流程
            if msgtype == "text" and text_content and text_content.startswith(config.TASK_TRIGGER_PREFIX):
                task_content = text_content[len(config.TASK_TRIGGER_PREFIX):]
                task = _create_task(external_userid, task_content)
                print(f"[task] created task_id={task['task_id']} content={task_content}")
                _run_task(task, open_kfid)
                reply_text = None  # 任务流程已自行推送全部消息，无需再发默认回复

            # 文本消息命中触发词：主动推送配置文件的下载链接
            elif msgtype == "text" and msg.get("text", {}).get("content") == config.PUSH_FILE_TRIGGER:
                try:
                    thumb_media_id = upload_temp_media(config.PUSH_LINK_THUMB_PATH, media_type="image")
                    filename = os.path.basename(config.PUSH_FILE_PATH)
                    download_url = f"{config.PUBLIC_BASE_URL}/files/{filename}"
                    send_link_msg(
                        external_userid,
                        open_kfid,
                        config.PUSH_LINK_TITLE,
                        config.PUSH_LINK_DESC,
                        download_url,
                        thumb_media_id,
                    )
                    reply_text = None  # 链接消息已发送，无需再发文本回复
                except Exception as e:
                    reply_text = f"文件推送失败：{str(e)}"
                    print(f"[receive] push file error: {e}")

            # 文本消息命中触发词：主动推送专属上传链接，接收超过企业微信 20MB 上限的大文件
            elif msgtype == "text" and msg.get("text", {}).get("content") == config.UPLOAD_TRIGGER:
                try:
                    thumb_media_id = upload_temp_media(config.UPLOAD_LINK_THUMB_PATH, media_type="image")
                    upload_token = _make_upload_token(external_userid, open_kfid)
                    upload_url = f"{config.PUBLIC_BASE_URL}/upload/{upload_token}"
                    send_link_msg(
                        external_userid,
                        open_kfid,
                        config.UPLOAD_LINK_TITLE,
                        config.UPLOAD_LINK_DESC,
                        upload_url,
                        thumb_media_id,
                    )
                    reply_text = None  # 上传链接已发送，无需再发文本回复
                except Exception as e:
                    reply_text = f"上传链接生成失败：{str(e)}"
                    print(f"[receive] push upload link error: {e}")

            # 文件类消息：图片/语音/视频/文件，提取 media_id 并下载
            elif msgtype in ["image", "video", "voice", "file"]:
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

            if reply_text is not None:
                if config.REPLY_DELAY_SECONDS > 0:
                    print(f"[receive] delaying reply by {config.REPLY_DELAY_SECONDS}s")
                    time.sleep(config.REPLY_DELAY_SECONDS)
                try:
                    send_text_msg(external_userid, open_kfid, reply_text)
                except Exception as e:
                    print(f"[receive] send_msg error: {e}")


if __name__ == "__main__":
    _load_cursors()  # 启动时加载已保存的游标
    print("Starting on https://0.0.0.0:1681")
    print("Callback path: /wechat/callback")
    app.run(host="0.0.0.0", port=1681, debug=True, use_reloader=False)
