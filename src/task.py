"""模拟任务流程：创建任务、执行进度推送与结果回传、补推失败任务

用于测试 48 小时会话窗口/主动消息配额耗尽后，任务结果推送失败、待客户下次
发消息再补推的场景。任务状态：pending（未完成）/ done（已完成）/
pushed（已推送）/ push_failed（已完成但推送失败）。
"""

import time

import config

from . import storage, wechat_api


def create_task(external_userid: str, content: str) -> dict:
    # 创建一条模拟任务，标记为未完成，登记到该客户名下
    task = {
        "task_id": f"task_{int(time.time() * 1000)}",
        "external_userid": external_userid,
        "content": content,
        "status": "pending",
    }
    with storage.tasks_lock:
        storage.tasks_by_user.setdefault(external_userid, []).append(task)
    return task


def run_task(task: dict, open_kfid: str) -> None:
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
            wechat_api.send_text_msg(external_userid, open_kfid, text)
        except Exception as e:
            print(f"[task] progress push error task_id={task['task_id']}: {e}")
        time.sleep(config.TASK_PROGRESS_INTERVAL_SECONDS)

    time.sleep(config.TASK_PROCESS_DELAY_SECONDS)
    task["status"] = "done"

    result_text = f"{task['content']}任务已完成"
    try:
        wechat_api.send_text_msg(external_userid, open_kfid, result_text)
        task["status"] = "pushed"
        print(f"[task] pushed task_id={task['task_id']}")
    except Exception as e:
        task["status"] = "push_failed"
        print(f"[task] push failed task_id={task['task_id']}: {e}")


def push_pending_task_results(external_userid: str, open_kfid: str) -> None:
    # 客户发来新消息时，检查该客户名下是否有"已完成但推送失败"的任务，若有则补推
    with storage.tasks_lock:
        tasks = storage.tasks_by_user.get(external_userid, [])
        failed_tasks = [t for t in tasks if t["status"] == "push_failed"]

    for task in failed_tasks:
        result_text = f"{task['content']}任务已完成"
        try:
            wechat_api.send_text_msg(external_userid, open_kfid, result_text)
            task["status"] = "pushed"
            print(f"[task] retry push succeeded task_id={task['task_id']}")
        except Exception as e:
            print(f"[task] retry push failed task_id={task['task_id']}: {e}")
