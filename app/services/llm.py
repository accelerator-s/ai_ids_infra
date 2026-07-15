"""OpenAI 兼容接口的最小客户端，供配置面板拉取模型列表和测试连通性。

AI 辅助研判和评测报告模块后续也复用这里的调用方式。
"""

from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class LlmError(RuntimeError):
    """模型服务调用失败，message 面向 WebUI 直接展示。"""


def _normalize_base_url(base_url: str) -> str:
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        raise LlmError("服务地址不能为空")
    return base


def _read_json(request: Request, timeout: float) -> dict:
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = ""
        try:
            body = json.loads(exc.read().decode("utf-8"))
            detail = body.get("error", {}).get("message", "")
        except Exception:
            detail = ""
        suffix = f"：{detail}" if detail else ""
        raise LlmError(f"模型服务返回 HTTP {exc.code}{suffix}") from exc
    except URLError as exc:
        raise LlmError(f"无法连接模型服务（{exc.reason}）") from exc
    except TimeoutError as exc:
        raise LlmError("请求模型服务超时") from exc


def fetch_models(base_url: str, api_key: str, timeout: float = 20) -> list[str]:
    """调用 GET {base_url}/models 拉取可用模型 ID 列表。"""
    base = _normalize_base_url(base_url)
    request = Request(
        f"{base}/models",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    body = _read_json(request, timeout)
    models = [str(item["id"]) for item in body.get("data", []) if item.get("id")]
    return sorted(models)


def chat_once(
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    temperature: float = 0.2,
    timeout: float = 60,
) -> dict:
    """调用 POST {base_url}/chat/completions 完成一次对话，返回回复内容和耗时。"""
    base = _normalize_base_url(base_url)
    if not model:
        raise LlmError("请先选择模型")

    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
        }
    ).encode("utf-8")
    request = Request(
        f"{base}/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    started = time.perf_counter()
    body = _read_json(request, timeout)
    elapsed_ms = (time.perf_counter() - started) * 1000

    choices = body.get("choices") or []
    if not choices:
        raise LlmError("模型服务没有返回任何回复内容")
    message = choices[0].get("message", {}).get("content", "") or ""
    return {"message": message, "elapsed_ms": round(elapsed_ms, 1)}
