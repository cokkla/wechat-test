"""客服消息事件处理：拉取新消息并按类型分发（任务触发、文件推送、上传引导、媒体接收、默认回复）"""

import os
import time

import config

from . import llm, task, upload, wechat_api


def handle_kf_event(kf_token: str, open_kfid: str) -> None:
    # 拉取新消息，打印后对客户主动发来的消息统一回复（文件类消息下载并告知详情）
    try:
        msgs = wechat_api.sync_msg(kf_token, open_kfid)
    except Exception as e:
        print(f"[receive] sync_msg error: {e}")
        return

    for msg in msgs:
        print(f"[receive] msg={msg}")
        if msg.get("msgtype") == "event":
            _handle_kf_event_msg(msg)
        elif msg.get("origin") == 3:
            _handle_customer_msg(msg, open_kfid)


def _handle_kf_event_msg(msg: dict) -> None:
    event = msg.get("event", {})
    if event.get("event_type") != "enter_session":
        return

    welcome_code = event.get("welcome_code")
    if not welcome_code:
        return  # 不满足发送欢迎语条件（48小时内已收过欢迎语，或已向客服发过消息）

    try:
        wechat_api.send_welcome_menu(welcome_code, config.WELCOME_MENU_HEAD, config.WELCOME_MENU_ITEMS)
    except Exception as e:
        print(f"[receive] send_welcome_menu error: {e}")


def _handle_customer_msg(msg: dict, open_kfid: str) -> None:
    msgtype = msg.get("msgtype")
    external_userid = msg["external_userid"]
    reply_text = "成功接收消息"

    # 客户发来任意消息，先检查名下是否有已完成但推送失败的任务，补推任务结果
    task.push_pending_task_results(external_userid, open_kfid)

    text_content = msg.get("text", {}).get("content") if msgtype == "text" else None

    # 文本消息命中"开始任务：xxx"前缀：创建模拟任务并启动处理流程
    if msgtype == "text" and text_content and text_content.startswith(config.TASK_TRIGGER_PREFIX):
        task_content = text_content[len(config.TASK_TRIGGER_PREFIX):]
        new_task = task.create_task(external_userid, task_content)
        print(f"[task] created task_id={new_task['task_id']} content={task_content}")
        task.run_task(new_task, open_kfid)
        reply_text = None  # 任务流程已自行推送全部消息，无需再发默认回复

    # 文本消息命中触发词：主动推送配置文件的下载链接
    elif msgtype == "text" and text_content == config.PUSH_FILE_TRIGGER:
        reply_text = _push_download_link(external_userid, open_kfid)

    # 文本消息命中触发词：主动推送专属上传链接，接收超过企业微信 20MB 上限的大文件
    elif msgtype == "text" and text_content == config.UPLOAD_TRIGGER:
        reply_text = _push_upload_link(external_userid, open_kfid)

    # 文件类消息：图片/语音/视频/文件，提取 media_id 并下载
    elif msgtype in ["image", "video", "voice", "file"]:
        reply_text = _handle_media_msg(msg, msgtype)

    # 其他文本消息：交给 LLM 生成回复，失败时兜底固定文案
    elif msgtype == "text" and text_content:
        try:
            reply_text = llm.reply(text_content)
        except Exception as e:
            print(f"[receive] llm reply error: {e}")
            reply_text = "成功接收消息"

    if reply_text is not None:
        if config.REPLY_DELAY_SECONDS > 0:
            print(f"[receive] delaying reply by {config.REPLY_DELAY_SECONDS}s")
            time.sleep(config.REPLY_DELAY_SECONDS)
        try:
            wechat_api.send_text_msg(external_userid, open_kfid, reply_text)
        except Exception as e:
            print(f"[receive] send_msg error: {e}")


def _push_download_link(external_userid: str, open_kfid: str) -> str | None:
    try:
        thumb_media_id = wechat_api.upload_temp_media(config.PUSH_LINK_THUMB_PATH, media_type="image")
        filename = os.path.basename(config.PUSH_FILE_PATH)
        download_url = f"{config.PUBLIC_BASE_URL}/files/{filename}"
        wechat_api.send_link_msg(
            external_userid,
            open_kfid,
            config.PUSH_LINK_TITLE,
            config.PUSH_LINK_DESC,
            download_url,
            thumb_media_id,
        )
        return None  # 链接消息已发送，无需再发文本回复
    except Exception as e:
        print(f"[receive] push file error: {e}")
        return f"文件推送失败：{str(e)}"


def _push_upload_link(external_userid: str, open_kfid: str) -> str | None:
    try:
        thumb_media_id = wechat_api.upload_temp_media(config.UPLOAD_LINK_THUMB_PATH, media_type="image")
        upload_token = upload.make_upload_token(external_userid, open_kfid)
        upload_url = f"{config.PUBLIC_BASE_URL}/upload/{upload_token}"
        wechat_api.send_link_msg(
            external_userid,
            open_kfid,
            config.UPLOAD_LINK_TITLE,
            config.UPLOAD_LINK_DESC,
            upload_url,
            thumb_media_id,
        )
        return None  # 上传链接已发送，无需再发文本回复
    except Exception as e:
        print(f"[receive] push upload link error: {e}")
        return f"上传链接生成失败：{str(e)}"


def _handle_media_msg(msg: dict, msgtype: str) -> str | None:
    media_id = msg.get(msgtype, {}).get("media_id")
    if not media_id:
        return "成功接收消息"

    try:
        result = wechat_api.download_media(media_id)
        if result["success"]:
            print(f"[receive] downloaded: {result['filepath']}")
            if msgtype == "voice":
                return "已接收语音消息"
            size_mb = result["size"] / (1024 * 1024)
            return f"已成功接收{result['filename']}文件，大小{size_mb:.2f}MB"
        print(f"[receive] download failed: {result['error']}")
        return f"文件接收失败：{result['error']}"
    except Exception as e:
        print(f"[receive] download exception: {e}")
        return f"文件下载异常：{str(e)}"
