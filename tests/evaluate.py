"""跑合成样本，输出规则/行为检测的召回率与误报率，用于优化前后对比。

    python -m tests.evaluate
"""

from __future__ import annotations

from app.config import RULES_DIR
from app.detection.behavior_detector import BehaviorDetector
from app.detection.rule_engine import RuleEngine
from tests.samples import BEHAVIOR_SAMPLES, RULE_SAMPLES


def _pct(a: int, b: int) -> str:
    return f"{100 * a / b:.0f}% ({a}/{b})" if b else "-"


def evaluate_rules() -> None:
    engine = RuleEngine.from_dir(RULES_DIR)
    results = [(s, bool(engine.match(s.request))) for s in RULE_SAMPLES]

    attacks = [(s, hit) for s, hit in results if s.is_attack]
    benign = [(s, hit) for s, hit in results if not s.is_attack]
    encoded = [(s, hit) for s, hit in attacks if s.variant == "encoded"]

    tp = sum(hit for _, hit in attacks)
    enc_tp = sum(hit for _, hit in encoded)
    fp = sum(hit for _, hit in benign)

    print("=== 规则检测 ===")
    print(f"攻击召回率:     {_pct(tp, len(attacks))}")
    print(f"  其中编码变体: {_pct(enc_tp, len(encoded))}   <- 规则①归一化优化后应上升")
    print(f"误报率:         {_pct(fp, len(benign))}   <- 规则②优化后应下降")
    print(f"漏报样本: {[s.name for s, hit in attacks if not hit]}")
    print(f"误报样本: {[s.name for s, hit in benign if hit]}")


def evaluate_behavior() -> None:
    results = [(s, {m.attack_type for m in BehaviorDetector().detect(s.stream)})
               for s in BEHAVIOR_SAMPLES]
    attacks = [(s, got) for s, got in results if s.is_attack]
    benign = [(s, got) for s, got in results if not s.is_attack]
    tp = sum(1 for s, got in attacks if s.expect & got)
    fp = sum(1 for s, got in benign if got)

    print("\n=== 行为检测 ===")
    print(f"攻击召回率: {_pct(tp, len(attacks))}")
    print(f"误报率:     {_pct(fp, len(benign))}")
    for s, got in results:
        ok = bool(s.expect & got) if s.is_attack else not got
        print(f"  [{'OK' if ok else '!!'}] {s.name}: 期望={s.expect or '{}'} 实得={got or '{}'}")


if __name__ == "__main__":
    evaluate_rules()
    evaluate_behavior()
