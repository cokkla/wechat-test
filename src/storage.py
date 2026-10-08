"""进程内状态存储：消息同步游标（含落盘）、access_token 缓存、模拟任务队列、上传 token 使用记录"""

import json
import os
import threading

CURSOR_FILE = "cursors.json"

# 记录每个客服账号（open_kfid）已同步到的位置，用于增量拉取消息
cursor_store: dict[str, str] = {}
cursor_lock = threading.Lock()

# 缓存 access_token，避免频繁调用 gettoken 接口
token_cache = {"access_token": None, "expires_at": 0.0}
token_lock = threading.Lock()

# 模拟任务：记录每个客户（external_userid）名下的任务列表，测试 48 小时窗口/配额耗尽后
# 任务结果推送失败、待客户下次发消息再补推的场景。进程重启会清空，测试场景可接受。
# 任务状态：pending（未完成）/ done（已完成）/ pushed（已推送）/ push_failed（已完成但推送失败）
tasks_by_user: dict[str, list[dict]] = {}
tasks_lock = threading.Lock()

# 已使用过的上传 token，防止链接被重复使用（进程重启会清空，测试场景可接受）
used_upload_tokens: set[str] = set()
upload_tokens_lock = threading.Lock()


def load_cursors() -> None:
    """启动时从文件加载已保存的游标"""
    global cursor_store
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, "r", encoding="utf-8") as f:
                cursor_store = json.load(f)
            print(f"[startup] loaded cursors: {cursor_store}")
        except Exception as e:
            print(f"[startup] failed to load cursors: {e}")


def save_cursors() -> None:
    """更新游标后保存到文件"""
    with cursor_lock:
        try:
            with open(CURSOR_FILE, "w", encoding="utf-8") as f:
                json.dump(cursor_store, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[save_cursors] error: {e}")
