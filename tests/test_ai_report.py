"""AI 评测报告：输出解析、输入汇总、以及 LLM 调用失败时的兜底落库。

用 monkeypatch 桩掉 llm 和 crud，不依赖真实模型服务或数据库。
"""

from types import SimpleNamespace

import pytest

from app.ai import report_generator as rg


def test_parse_valid_report():
    msg = '前言 {"summary":"共 3 条告警","risk_assessment":"high",' \
          '"key_findings":["SQL 注入"],"recommendations":["加 WAF"]} 后记'
    out = rg.parse_report(msg)
    assert out["summary"] == "共 3 条告警"
    assert out["risk_assessment"] == "high"
    assert out["key_findings"] == ["SQL 注入"]
    assert out["recommendations"] == ["加 WAF"]


def test_parse_missing_required_field_raises():
    with pytest.raises(ValueError):
        rg.parse_report('{"summary":"只有摘要"}')  # 缺 risk_assessment


def test_parse_without_json_raises():
    with pytest.raises(ValueError):
        rg.parse_report("模型说了一堆但没有 JSON")


def test_generate_falls_back_on_llm_failure(monkeypatch):
    saved = {}

    def fake_stats(db, task_id):
        return {"alert_total": 0, "attack_type_distribution": {},
                "risk_level_distribution": {}, "top_source_ips": [], "typical_alerts": []}

    def fake_chat(**kwargs):
        raise rg.llm.LlmError("连接超时")

    def fake_create_report(db, **fields):
        saved.update(fields)
        return SimpleNamespace(**fields)

    monkeypatch.setattr(rg.crud, "get_task_stats", fake_stats)
    monkeypatch.setattr(rg.llm, "chat_once", fake_chat)
    monkeypatch.setattr(rg.crud, "create_report", fake_create_report)

    task = SimpleNamespace(id=1, task_type="pcap", target="x.pcap", status="done",
                           packet_count=0, http_count=0, alert_count=0,
                           created_at=None, finished_at=None)
    settings = {"llm.model": "m", "llm.base_url": "http://x", "llm.api_key": "k",
                "llm.temperature": 0.2}

    rg.generate(db=None, task=task, settings=settings)

    assert saved.get("status") == "failed", "LLM 失败时应落一条 failed 报告"
    assert "连接超时" in saved.get("error_message", ""), "应保留失败原因"
