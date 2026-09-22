"""测试用配置，方便调整无需改动业务逻辑"""

import os
from urllib.parse import urlparse

# 用户发送该文本内容时，服务端主动推送下载链接
PUSH_FILE_TRIGGER = "获取文件"

# 主动推送的文件路径（相对项目根目录，需放在 files/ 目录下才能被下载路由访问到）
PUSH_FILE_PATH = "files/test_25mb.pdf"

# 对外可访问的服务根地址，从 .env 的 URL（回调地址）取 scheme+host+port，与回调地址天然同域名
# http://www.parklight.tech:1681
_callback_url = os.environ.get("URL", "").strip()
PUBLIC_BASE_URL = f"{urlparse(_callback_url).scheme}://{urlparse(_callback_url).netloc}" if _callback_url else ""

# 图文链接卡片文案
PUSH_LINK_TITLE = "文件下载"
PUSH_LINK_DESC = "点击查看/下载文件"

# 图文链接卡片缩略图路径（相对项目根目录）
PUSH_LINK_THUMB_PATH = "files/thumb.png"

# 用户发送该文本内容时，服务端推送一个专属上传链接（用于接收超过企业微信 20MB 上限的大文件）
UPLOAD_TRIGGER = "上传文件"

# 上传链接标题/描述、缩略图（复用下载链接的缩略图）
UPLOAD_LINK_TITLE = "文件上传"
UPLOAD_LINK_DESC = "点击上传文件给我们"
UPLOAD_LINK_THUMB_PATH = "files/thumb.png"

# 上传 token 有效期（秒）
UPLOAD_TOKEN_MAX_AGE = 1800

# 用户上传文件的保存目录
UPLOADS_DIR = "uploads"

# 单个上传文件大小上限（字节），200MB
UPLOAD_MAX_SIZE = 200 * 1024 * 1024

# 回复消息前延迟的秒数（用于测试微信客服消息回复的时间限制），0 表示不延迟
REPLY_DELAY_SECONDS = 0

# 用户发送该前缀的文本消息时，触发模拟任务流程，例如"开始任务：查询阿里巴巴公司"
TASK_TRIGGER_PREFIX = "开始任务："

# 模拟任务处理耗时（秒），从"信息收集完毕"到任务被标记为完成之间的延迟
TASK_PROCESS_DELAY_SECONDS = 10

# 任务进度提示消息之间的间隔（秒）
TASK_PROGRESS_INTERVAL_SECONDS = 1