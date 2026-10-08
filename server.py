"""应用启动入口：加载配置、注入运行期凭证、注册路由、启动 Flask 服务

业务逻辑已拆分至 src/ 下各模块：crypto（加解密与签名）、storage（状态存储）、
wechat_api（企业微信官方接口）、upload（大文件上传通道）、task（模拟任务流程）、
message（消息事件分发）、routes（Flask 路由）。
"""

import hashlib
import os

from dotenv import load_dotenv

load_dotenv()

import config  # noqa: E402  (需要先加载 .env，config 里要读 URL 环境变量)
from flask import Flask  # noqa: E402

from src import llm, routes, storage, upload, wechat_api  # noqa: E402

# 从环境变量加载微信服务器配置
TOKEN = os.environ["WECHAT_TOKEN"]
ENCODING_AES_KEY = os.environ["WECHAT_ENCODING_AES_KEY"]
CORP_ID = os.environ["CorpTD"]
SECRET = os.environ["Secret"]
LLM_API_KEY = os.environ["ANTHROPIC_API_KEY"]
LLM_BASE_URL = os.environ["ANTHROPIC_BASE_URL"]
LLM_MODEL = os.environ["ANTHROPIC_MODEL"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.UPLOAD_MAX_SIZE

# 注入运行期凭证：企业微信应用凭证、回调校验凭证、上传链接签名密钥（由现有微信密钥派生，无需额外保存新密钥）、中转 LLM 凭证
wechat_api.configure(CORP_ID, SECRET)
routes.configure(TOKEN, ENCODING_AES_KEY)
upload.configure(hashlib.sha256((TOKEN + ENCODING_AES_KEY).encode("utf-8")).hexdigest())
llm.configure(LLM_API_KEY, LLM_BASE_URL, LLM_MODEL)

app.register_blueprint(routes.bp)


if __name__ == "__main__":
    storage.load_cursors()  # 启动时加载已保存的游标
    print("Starting on https://0.0.0.0:1681")
    print("Callback path: /wechat/callback")
    app.run(host="0.0.0.0", port=1681, debug=True, use_reloader=False)
