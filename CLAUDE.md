# 项目说明

微信客服开发测试项目，基于现有代码迭代开发（Flask 单文件服务 `server.py`）。

## 开发流程（每次新功能必守）

1. 先设计：功能设计 → 明确开发计划 → 再动手写代码
2. 写测试：在 `test_server.py` 中撰写单元测试并跑通
3. 写记录：更新完成后追加/更新 `docs/状态记录.md`

## 必读文档

- `docs/接收消息.md` — 微信客服接收消息接口
- `docs/发送消息.md` — 微信客服发送消息接口
- `docs/状态记录.md` — 历史进度与当前状态

## 环境

- Windows 环境，使用项目 `.venv` 虚拟环境
- 激活：`.venv\Scripts\activate`
- 运行服务：`.venv\Scripts\python.exe server.py`
- 运行测试：`.venv\Scripts\python.exe -m pytest`
- 依赖：`requirements.txt`（运行时）+ `requirements-dev.txt`（测试，含 pytest / pytest-mock）
- 密钥配置在 `.env`（`WECHAT_TOKEN` / `WECHAT_ENCODING_AES_KEY` / `CorpTD` / `Secret`），不要提交或打印其值

## 约定

- 不是从零开始，已有部分代码，改动前先读现有实现
- 保持简洁，不过度设计
