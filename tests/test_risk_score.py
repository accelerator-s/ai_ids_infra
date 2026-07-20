"""风险评分：无命中、分数聚合、等级映射、AI 辅助研判触发条件。"""

from app.config import DEFAULT_RISK_THRESHOLDS as T
from app.detection.risk_score import calculate_risk
from app.detection.rule_engine import RuleMatch


def _match(score: float, level: str = "high") -> RuleMatch:
    return RuleMatch(rule_id="r", attack_type="X", level=level, score=score,
                     field="query", matched_value="x", reason="")


def test_no_match_is_normal():
    r = calculate_risk([])
    assert r.score == 0
    assert r.level == "normal"
    assert not r.need_ai_filter


def test_high_score_direct_alert():
    r = calculate_risk([_match(70)])
    assert r.score >= T["high"]
    assert r.level in ("high", "critical")
    assert not r.need_ai_filter, "高分应直接告警，不再走 AI"


def test_medium_score_triggers_ai():
    r = calculate_risk([_match(40, "medium")])
    assert T["low"] <= r.score < T["high"]
    assert r.need_ai_filter, "中等分数应触发 AI 辅助研判"


def test_secondary_matches_add_weight():
    r = calculate_risk([_match(70), _match(40, "medium")])
    assert r.score > 70, "多条命中时非最高分应按权重加成"
