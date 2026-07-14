"""AI 评测报告生成。

汇总分析任务的告警统计和典型告警，交给大模型输出任务概况、
风险评估、主要发现和处置建议。报告只读取已保存的检测结果，
不回写风险分数和告警状态；调用失败时保存 failed 记录和原因。
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.database import crud
from app.database.models import Report, Task
from app.services import llm

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = (
    "你是网络入侵检测系统的安全分析助手，负责对已完成的检测任务出具评测报告。"
    "报告使用中文撰写，只输出一个 JSON 对象，不要输出其他说明文字。"
)

USER_PROMPT_TEMPLATE = """请根据以下检测任务的汇总数据出具评测报告。

任务信息：
{task_json}

告警统计：
{stats_json}

典型告警（按风险分数从高到低取样）：
{alerts_json}

输出要求：
1. summary 用一到两句话概括本次任务的流量情况和告警数量；
2. risk_assessment 给出整体风险等级（normal / low / medium / high / critical）并说明依据；
3. key_findings 按重要程度列出需要优先关注的发现，没有告警时可以为空数组；
4. recommendations 给出可执行的处置和防护建议。

严格按照如下 JSON 格式输出：
{{
  "summary": "...",
  "risk_assessment": "...",
  "key_findings": ["..."],
  "recommendations": ["..."]
}}"""

ALERT_FIELDS = (
    "src_ip",
    "method",
    "path",
    "query",
    "attack_type",
    "risk_level",
    "score",
    "matched_rules",
    "reason",
    "ai_judgement",
    "ai_reason",
)


def generate(db: Session, task: Task, settings: dict[str, Any]) -> Report:
    """对单个分析任务生成评测报告，成功和失败都会落库。"""
    model = settings["llm.model"]
    stats = crud.get_task_stats(db, task.id)
    prompt = build_prompt(task, stats)

    try:
        result = llm.chat_once(
            base_url=settings["llm.base_url"],
            api_key=settings["llm.api_key"],
            model=model,
            system=SYSTEM_PROMPT,
            user=prompt,
            temperature=settings["llm.temperature"],
            timeout=120,
        )
        fields = parse_report(result["message"])
    except (llm.LlmError, ValueError) as exc:
        return crud.create_report(
            db,
            task_id=task.id,
            status="failed",
            model=model,
            prompt_version=PROMPT_VERSION,
            error_message=str(exc),
        )

    return crud.create_report(
        db,
        task_id=task.id,
        status="done",
        model=model,
        prompt_version=PROMPT_VERSION,
        **fields,
    )


def build_prompt(task: Task, stats: dict[str, Any]) -> str:
    """把任务信息和告警统计整理成评测报告的用户输入。"""
    task_info = {
        "task_id": task.id,
        "task_type": task.task_type,
        "target": task.target,
        "status": task.status,
        "packet_count": task.packet_count,
        "http_count": task.http_count,
        "alert_count": task.alert_count,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
    }
    stats_info = {
        "alert_total": stats["alert_total"],
        "attack_type_distribution": stats["attack_type_distribution"],
        "risk_level_distribution": stats["risk_level_distribution"],
        "top_source_ips": stats["top_source_ips"],
    }
    typical_alerts = [_trim_alert(alert) for alert in stats["typical_alerts"]]

    return USER_PROMPT_TEMPLATE.format(
        task_json=_dumps(task_info),
        stats_json=_dumps(stats_info),
        alerts_json=_dumps(typical_alerts) if typical_alerts else "（本次任务没有告警）",
    )


def parse_report(message: str) -> dict[str, Any]:
    """解析模型返回的 JSON 报告，格式不符时抛 ValueError。"""
    text = message or ""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("模型输出中没有找到 JSON 报告内容")

    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"模型输出的 JSON 无法解析：{exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("模型输出的不是 JSON 对象")

    summary = str(data.get("summary", "")).strip()
    risk_assessment = str(data.get("risk_assessment", "")).strip()
    if not summary or not risk_assessment:
        raise ValueError("模型输出缺少 summary 或 risk_assessment 字段")

    return {
        "summary": summary,
        "risk_assessment": risk_assessment,
        "key_findings": _string_list(data.get("key_findings")),
        "recommendations": _string_list(data.get("recommendations")),
    }


def _trim_alert(alert: dict[str, Any]) -> dict[str, Any]:
    trimmed = {}
    for field in ALERT_FIELDS:
        value = alert.get(field)
        if isinstance(value, str) and len(value) > 200:
            value = value[:200] + "…"
        if value not in (None, "", []):
            trimmed[field] = value
    return trimmed


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)
