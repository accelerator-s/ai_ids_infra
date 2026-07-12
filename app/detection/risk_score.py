"""风险评分模块：将规则引擎的多条命中结果汇总为一个最终风险分数和等级。

在整条检测链里的位置：
    抓包 -> 协议解析 -> 规则检测 -> 行为检测 -> [风险评分(本模块)] -> AI 二次过滤 -> 写库

计分公式：
    最终分数 = max(各规则分数) + sum(其他命中规则分数 × 权重系数)

风险等级阈值（来自 config.py）：
    0-19:  normal  — 正常流量，不做处理
    20-69: medium  — 交由 AI 二次过滤判断
    70+:   high    — 直接告警
    90+:   critical — 严重威胁，直接告警
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import DEFAULT_RISK_THRESHOLDS
from app.detection.rule_engine import RuleMatch


# 非最高分规则的加权系数
SECONDARY_WEIGHT = 0.2


@dataclass
class RiskResult:
    """风险评分结果。"""

    score: float          # 最终计算得分
    level: str            # 风险等级：normal / low / medium / high / critical
    matches: list[RuleMatch]  # 命中的规则列表（保留用于后续写库/展示）
    need_ai_filter: bool  # 是否需要 AI 二次过滤


def calculate_risk(
    matches: list[RuleMatch],
    thresholds: dict[str, int] | None = None,
    weight: float = SECONDARY_WEIGHT,
) -> RiskResult:
    """根据规则命中列表计算最终风险分数和等级。

    参数:
        matches  — 规则引擎返回的命中结果列表
        thresholds — 风险等级阈值字典，默认使用 config.py 中的配置
        weight   — 非最高分规则的加权系数，默认 0.2
    """
    if thresholds is None:
        thresholds = DEFAULT_RISK_THRESHOLDS

    if not matches:
        return RiskResult(
            score=0.0,
            level="normal",
            matches=[],
            need_ai_filter=False,
        )

    scores = [m.score for m in matches]
    max_score = max(scores)
    secondary_sum = sum(s for s in scores if s != max_score) * weight

    # 如果有多条规则分数等于最高分，只取一条作为 max，其余仍按权重累加
    max_count = scores.count(max_score)
    if max_count > 1:
        secondary_sum += (max_count - 1) * max_score * weight

    final_score = max_score + secondary_sum

    level = _score_to_level(final_score, thresholds)
    need_ai = thresholds["low"] <= final_score < thresholds["high"]

    return RiskResult(
        score=round(final_score, 1),
        level=level,
        matches=matches,
        need_ai_filter=need_ai,
    )


def _score_to_level(score: float, thresholds: dict[str, int]) -> str:
    """将数值分数映射为风险等级字符串。

    参数:
        score      — 最终计算得分
        thresholds — 风险等级阈值字典
    """
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    if score >= thresholds["low"]:
        return "low"
    return "normal"


if __name__ == "__main__":
    # 简单测试：模拟不同命中场景验证计分逻辑
    print("=== 风险评分模块测试 ===\n")

    # 场景1：命中 sleep() — 单条 high 规则
    case1 = [RuleMatch(
        rule_id="sqli-001", attack_type="SQL Injection",
        level="high", score=70, field="query",
        matched_value="sleep(5)", reason="命中规则 sqli-001",
    )]
    r1 = calculate_risk(case1)
    print(f"场景1 sleep(5): score={r1.score}, level={r1.level}, ai={r1.need_ai_filter}")

    # 场景2：' or 1=1 -- （命中 sqli-003 + sqli-005）
    case2 = [
        RuleMatch(rule_id="sqli-003", attack_type="SQL Injection",
                  level="medium", score=25, field="query",
                  matched_value="'", reason="命中规则 sqli-003"),
        RuleMatch(rule_id="sqli-005", attack_type="SQL Injection",
                  level="low", score=10, field="query",
                  matched_value="or", reason="命中规则 sqli-005"),
    ]
    r2 = calculate_risk(case2)
    print(f"场景2 ' or 1=1 --: score={r2.score}, level={r2.level}, ai={r2.need_ai_filter}")

    # 场景3：union select from users（命中 sqli-002 + sqli-004 + sqli-005）
    case3 = [
        RuleMatch(rule_id="sqli-002", attack_type="SQL Injection",
                  level="medium", score=35, field="query",
                  matched_value="union", reason="命中规则 sqli-002"),
        RuleMatch(rule_id="sqli-004", attack_type="SQL Injection",
                  level="low", score=15, field="query",
                  matched_value="select", reason="命中规则 sqli-004"),
        RuleMatch(rule_id="sqli-005", attack_type="SQL Injection",
                  level="low", score=10, field="query",
                  matched_value="from", reason="命中规则 sqli-005"),
    ]
    r3 = calculate_risk(case3)
    print(f"场景3 union select from: score={r3.score}, level={r3.level}, ai={r3.need_ai_filter}")

    # 场景4：正常请求 select=name&from=table（命中 sqli-004 + sqli-005）
    case4 = [
        RuleMatch(rule_id="sqli-004", attack_type="SQL Injection",
                  level="low", score=15, field="query",
                  matched_value="select", reason="命中规则 sqli-004"),
        RuleMatch(rule_id="sqli-005", attack_type="SQL Injection",
                  level="low", score=10, field="query",
                  matched_value="from", reason="命中规则 sqli-005"),
    ]
    r4 = calculate_risk(case4)
    print(f"场景4 正常请求 select&from: score={r4.score}, level={r4.level}, ai={r4.need_ai_filter}")

    # 场景5：无命中
    r5 = calculate_risk([])
    print(f"场景5 无命中: score={r5.score}, level={r5.level}, ai={r5.need_ai_filter}")
