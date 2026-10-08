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

1. `/think` 出实现要点（不写代码），确认后才动手。
2. 编码时 `/ponytail` 保持常开（默认 full 档：YAGNI → stdlib 优先 → 平台原生 → 一行内解决 → 最小实现）。
<!-- 3. 模块代码完成后，跑一次 `/ponytail-review` 自查本次 diff，清掉过度设计再收尾。
4. 写 `test_*.py`（pytest 风格），覆盖 happy path + 设计文档里写明的降级/失败路径，跑通才算模块完成。 -->
5. 编制设计文档/说明类文字用 `/write`。
6. 需求或设计文档留白处需要跟我对齐时用 `/grill-me`，不要自己猜。


## 精简原则

- 遵循 ponytail ladder：不做设计文档没要求的字段、分支、配置项；三行重复代码优于一个只有一处调用的抽象。
- 回复我时同样从简，不要输出无谓的解释性文字，直接给结论和改动点。

