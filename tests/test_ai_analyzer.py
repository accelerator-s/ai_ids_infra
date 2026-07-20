"""AI 辅助研判：研判输出解析校验、Prompt 构造、未配置 / LLM 失败时的降级。

用 monkeypatch 桩掉 llm，不依赖真实模型服务。
"""

import pytest

from app.ai import request_analyzer as ra
from app.detection.risk_score import RiskResult
from app.detection.rule_engine import RuleMatch


def _risk(score: float = 40, level: str = "medium") -> RiskResult:
    match = RuleMatch(rule_id="sqli-003", attack_type="SQL Injection", level="medium",
                      score=25, field="query", matched_value="'", reason="命中 sqli-003")
    return RiskResult(score=score, level=level, matches=[match], need_ai_filter=True)


def test_parse_valid_normalizes_judgement():
    out = ra.parse_response('{"ai_judgement":"MALICIOUS","attack_type":"SQL Injection",'
                            '"confidence":0.87,"reason":"参数含注入特征"}')
    assert out["ai_judgement"] == "malicious"
    assert out["attack_type"] == "SQL Injection"
    assert out["confidence"] == 0.87
    assert out["reason"]


def test_parse_rejects_bad_judgement():
    with pytest.raises(ValueError):
        ra.parse_response('{"ai_judgement":"maybe","attack_type":"X","confidence":0.5,"reason":"r"}')


def test_parse_rejects_confidence_out_of_range():
    with pytest.raises(ValueError):
        ra.parse_response('{"ai_judgement":"benign","attack_type":"Normal","confidence":9,"reason":"r"}')


def test_parse_rejects_no_json():
    with pytest.raises(ValueError):
        ra.parse_response("模型只说了一堆解释，没有 JSON")


def test_build_prompt_trims_long_value_and_keeps_context():
    req = {"src_ip": "1.1.1.1", "path": "/x", "query": "q=" + "A" * 6000}
    prompt = ra.build_prompt(req, _risk())
    assert "1.1.1.1" in prompt
    assert "sqli-003" in prompt            # 规则命中被带入 Prompt
    assert "A" * 6000 not in prompt        # 超长请求字段被截断


def test_analyze_requires_full_config():
    with pytest.raises(ra.AnalysisError):
        ra.analyze({"path": "/x"}, _risk(),
                   settings={"llm.base_url": "", "llm.api_key": "", "llm.model": ""})


def test_analyze_returns_result_on_success(monkeypatch):
    monkeypatch.setattr(ra.llm, "chat_once", lambda **kw: {
        "message": '{"ai_judgement":"malicious","attack_type":"XSS","confidence":0.9,"reason":"脚本注入"}'})
    result = ra.analyze(
        {"path": "/search", "query": "q=<script>"}, _risk(),
        settings={"llm.base_url": "http://x", "llm.api_key": "k", "llm.model": "m", "llm.temperature": 0.2},
    )
    assert result.ai_judgement == "malicious"
    assert result.attack_type == "XSS"
    assert result.model == "m"


def test_analyze_wraps_llm_failure(monkeypatch):
    def boom(**kwargs):
        raise ra.llm.LlmError("请求模型服务超时")

    monkeypatch.setattr(ra.llm, "chat_once", boom)
    with pytest.raises(ra.AnalysisError):
        ra.analyze({"path": "/x"}, _risk(),
                   settings={"llm.base_url": "http://x", "llm.api_key": "k", "llm.model": "m"})
