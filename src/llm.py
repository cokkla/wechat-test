"""中转 LLM 接入（OpenAI 兼容协议）：把客户消息交给 LLM 生成回复

API_KEY/BASE_URL/MODEL 由 configure() 在应用启动时注入一次。
"""

import requests

import config

_credentials = {"api_key": None, "base_url": None, "model": None}


def configure(api_key: str, base_url: str, model: str) -> None:
    """注入中转 LLM 凭证，须在调用 reply() 前执行一次"""
    _credentials["api_key"] = api_key
    _credentials["base_url"] = base_url.rstrip("/")
    _credentials["model"] = model


def reply(user_text: str) -> str:
    resp = requests.post(
        f"{_credentials['base_url']}/v1/chat/completions",
        headers={"Authorization": f"Bearer {_credentials['api_key']}"},
        json={
            "model": _credentials["model"],
            "messages": [
                {"role": "system", "content": config.LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_text},
            ],
        },
        timeout=30,
    )
    data = resp.json()
    if "choices" not in data:
        raise RuntimeError(f"llm reply failed: {data}")
    return data["choices"][0]["message"]["content"]
