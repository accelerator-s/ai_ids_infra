"""对规则评分处于模糊区间的 HTTP 请求执行 AI 辅助研判。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.detection.risk_score import RiskResult
from app.services import llm


PROMPT_VERSION = "v1"
SYSTEM_PROMPT = (
    "你是网络入侵检测系统的安全分析助手。请结合 HTTP 请求上下文、规则命中和风险分数，"
    "判断请求是否具有攻击意图。只输出一个 JSON 对象，不要输出 Markdown 或其他说明。"
)
USER_PROMPT_TEMPLATE = """请研判下面这条 HTTP 请求。

HTTP 请求：
{request_json}

规则检测结果：
{risk_json}

输出要求：
1. ai_judgement 只能是 malicious 或 benign；
2. attack_type 是最可能的攻击类型，正常请求填写 Normal；
3. confidence 是 0 到 1 之间的数字；
4. reason 简洁说明判断依据，不要仅复述规则名称。

严格按照如下 JSON 格式输出：
{{
  "ai_judgement": "malicious",
  "attack_type": "SQL Injection",
  "confidence": 0.87,
  "reason": "..."
}}"""

REQUEST_FIELDS = (
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
    "method",
    "host",
    "path",
    "query",
    "query_params",
    "headers",
    "user_agent",
    "body",
    "status",
)
MAX_TEXT_LENGTH = 4000


class AnalysisError(RuntimeError):
    """AI 无法完成可靠研判时抛出，由调用方保存待人工复核记录。"""


@dataclass(frozen=True)
class AnalysisResult:
    ai_judgement: str
    attack_type: str
    confidence: float
    reason: str
    model: str
    prompt_version: str = PROMPT_VERSION


def analyze(
    request: dict[str, Any],
    risk: RiskResult,
    settings: dict[str, Any],
) -> AnalysisResult:
    """调用 OpenAI 兼容接口研判一条模糊请求并校验结构化输出。"""
    base_url = str(settings.get("llm.base_url", "")).strip()
    api_key = str(settings.get("llm.api_key", "")).strip()
    model = str(settings.get("llm.model", "")).strip()
    if not (base_url and api_key and model):
        raise AnalysisError("大模型服务尚未完整配置")

    try:
        response = llm.chat_once(
            base_url=base_url,
            api_key=api_key,
            model=model,
            system=SYSTEM_PROMPT,
            user=build_prompt(request, risk),
            temperature=float(settings.get("llm.temperature", 0.2)),
            timeout=60,
        )
        fields = parse_response(response.get("message", ""))
    except (llm.LlmError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise AnalysisError(str(exc)) from exc

    return AnalysisResult(model=model, **fields)


def build_prompt(request: dict[str, Any], risk: RiskResult) -> str:
    """构造仅包含研判所需内容的 Prompt，并限制不可信请求字段长度。"""
    request_info = {
        field: _trim_value(request.get(field))
        for field in REQUEST_FIELDS
        if request.get(field) not in (None, "", {}, [])
    }
    risk_info = {
        "score": risk.score,
        "risk_level": risk.level,
        "matches": [
            {
                "rule_id": match.rule_id,
                "attack_type": match.attack_type,
                "field": match.field,
                "matched_value": _trim_value(match.matched_value),
                "reason": match.reason,
            }
            for match in risk.matches
        ],
    }
    return USER_PROMPT_TEMPLATE.format(
        request_json=json.dumps(request_info, ensure_ascii=False, indent=2),
        risk_json=json.dumps(risk_info, ensure_ascii=False, indent=2),
    )


def parse_response(message: str) -> dict[str, Any]:
    """提取并严格校验模型返回的研判 JSON。"""
    text = str(message or "")
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("模型输出中没有找到 JSON 研判结果")
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"模型输出的 JSON 无法解析：{exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("模型输出的不是 JSON 对象")

    judgement = str(data.get("ai_judgement", "")).strip().lower()
    if judgement not in {"malicious", "benign"}:
        raise ValueError("ai_judgement 必须是 malicious 或 benign")
    attack_type = str(data.get("attack_type", "")).strip()
    reason = str(data.get("reason", "")).strip()
    if not attack_type or not reason:
        raise ValueError("模型输出缺少 attack_type 或 reason")
    try:
        confidence = float(data.get("confidence"))
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence 必须是 0 到 1 之间的数字") from exc
    if not 0 <= confidence <= 1:
        raise ValueError("confidence 必须是 0 到 1 之间的数字")

    return {
        "ai_judgement": judgement,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "reason": reason,
    }


def request_summary(request: dict[str, Any]) -> dict[str, Any]:
    """生成可安全持久化的请求摘要。"""
    return {
        field: _trim_value(request.get(field))
        for field in REQUEST_FIELDS
        if request.get(field) not in (None, "", {}, [])
    }


def _trim_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _trim_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_trim_value(item) for item in value]
    if isinstance(value, str) and len(value) > MAX_TEXT_LENGTH:
        return value[:MAX_TEXT_LENGTH] + "…"
    return value
