"""规则检测：规则库加载、攻击命中、干净样本不误报。"""

from app.config import RULES_DIR
from app.detection.rule_engine import RuleEngine, load_rules
from tests.samples import RULE_SAMPLES


def _engine() -> RuleEngine:
    return RuleEngine.from_dir(RULES_DIR)


def test_rules_load():
    rules = load_rules(RULES_DIR)
    assert rules, "规则库应至少加载到一条规则"
    assert all(r.patterns for r in rules), "每条规则都应有已编译的正则"
    assert all(r.attack_type for r in rules), "每条规则都应有攻击类型"


def test_plain_attacks_detected():
    engine = _engine()
    for s in RULE_SAMPLES:
        if s.is_attack and s.variant == "plain":
            assert engine.match(s.request), f"应命中攻击样本 {s.name}"


def test_clean_benign_not_flagged():
    # 只断言"干净"的正常样本；已知误报诱饵（benign-or 等）留给 evaluate 统计，不在此硬断言
    engine = _engine()
    clean = {"benign-search", "benign-login", "benign-article"}
    for s in RULE_SAMPLES:
        if s.name in clean:
            assert not engine.match(s.request), f"干净样本不应误报：{s.name}"
