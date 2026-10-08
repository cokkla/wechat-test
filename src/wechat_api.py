"""企业微信客服官方接口封装：access_token 获取、消息同步/发送、素材上传/下载

CORP_ID/SECRET 由 configure() 在应用启动时注入一次，避免每个函数都要求调用方传递。
"""

import os
import time

import requests

from . import storage

WECHAT_API_BASE = "https://qyapi.weixin.qq.com/cgi-bin"

_credentials = {"corp_id": None, "secret": None}


def configure(corp_id: str, secret: str) -> None:
    """注入企业微信应用凭证，须在调用其它接口前执行一次"""
    _credentials["corp_id"] = corp_id
    _credentials["secret"] = secret


def get_access_token() -> str:
    # 获取并缓存 access_token，提前 60 秒过期以留出安全余量
    with storage.token_lock:
        now = time.time()
        if storage.token_cache["access_token"] and now < storage.token_cache["expires_at"]:
            return storage.token_cache["access_token"]

        resp = requests.get(
            f"{WECHAT_API_BASE}/gettoken",
            params={"corpid": _credentials["corp_id"], "corpsecret": _credentials["secret"]},
            timeout=5,
        )
        data = resp.json()
        if data.get("errcode"):
            raise RuntimeError(f"gettoken failed: {data}")

        storage.token_cache["access_token"] = data["access_token"]
        storage.token_cache["expires_at"] = now + data["expires_in"] - 60
        return storage.token_cache["access_token"]


def sync_msg(kf_token: str, open_kfid: str) -> list[dict]:
    # 拉取指定客服账号自上次游标之后的全部新消息
    access_token = get_access_token()
    cursor = storage.cursor_store.get(open_kfid, "")
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
        storage.cursor_store[open_kfid] = cursor
        storage.save_cursors()  # 每次更新游标后立即保存

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


def send_welcome_menu(welcome_code: str, head_content: str, menu_items: list[dict]) -> dict:
    # 用「进入会话事件」返回的 welcome_code 发送欢迎菜单（须在收到事件后 20 秒内调用，且仅一次）
    access_token = get_access_token()
    resp = requests.post(
        f"{WECHAT_API_BASE}/kf/send_msg_on_event",
        params={"access_token": access_token},
        json={
            "code": welcome_code,
            "msgtype": "msgmenu",
            "msgmenu": {
                "head_content": head_content,
                "list": [{"type": "click", "click": item} for item in menu_items],
            },
        },
        timeout=5,
    )
    data = resp.json()
    if data.get("errcode"):
        raise RuntimeError(f"send_msg_on_event failed: {data}")
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
