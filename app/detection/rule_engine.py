"""规则检测模块：把结构化 HTTP 请求与 JSON 规则库做正则匹配，输出命中的攻击特征。

检测链位置：抓包 -> 协议解析 -> [规则检测(本模块)] -> 行为检测 -> 风险评分 -> AI 二次过滤 -> 写库

职责：
  - 本模块只回答"单个请求命中了哪些规则"。
  - 不做跨请求的行为统计（behavior_detector 负责）。
  - 不把多条命中汇总成最终风险分（risk_score 负责）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Rule:
    """一条规则数据类，对应规则库 JSON 里的一个对象。

    属性: id           - 规则唯一标识
         attack_type  - 攻击类型（如 SQL Injection、XSS）
         level        - 风险等级：low / medium / high / critical
         score        - 该规则的基础得分
         patterns     - 已编译的正则表达式列表（大小写不敏感）
         target_fields - 要扫描的请求字段列表，如 ["query", "body"]
         description  - 规则描述
    """

    id: str
    attack_type: str
    level: str
    score: float
    patterns: list[re.Pattern]
    target_fields: list[str]
    description: str = ""


@dataclass
class RuleMatch:
    """一次规则命中的结果数据类，供 risk_score 模块聚合、最终写入 alerts 表。

    属性: rule_id       - 命中的规则ID
         attack_type   - 攻击类型
         level         - 风险等级
         score         - 该规则的基础得分
         field         - 命中发生在哪个请求字段
         matched_value - 触发命中的原始文本片段（便于展示/排查）
         reason        - 人类可读的命中原因
    """

    rule_id: str
    attack_type: str
    level: str
    score: float
    field: str
    matched_value: str
    reason: str


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """该函数的作用为: 加载指定目录下所有 *.json 规则文件，编译正则后返回 Rule 列表。

    参数: rules_dir - 规则文件所在目录路径
    """
    rules: list[Rule] = []
    for path in sorted(Path(rules_dir).glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        for item in raw:
            compiled = [re.compile(p, re.IGNORECASE) for p in item["patterns"]]
            rules.append(
                Rule(
                    id=item["id"],
                    attack_type=item["attack_type"],
                    level=item["level"],
                    score=float(item.get("score", 0)),
                    patterns=compiled,
                    target_fields=item.get("target_fields", ["path", "query", "body"]),
                    description=item.get("description", ""),
                )
            )
    return rules


class RuleEngine:
    """规则引擎类：持有编译好的规则集，对每个请求做匹配。"""

    def __init__(self, rules: list[Rule]) -> None:
        """该函数的作用为: 初始化规则引擎实例。

        参数: rules - 编译好的 Rule 对象列表
        """
        self.rules = rules

    @classmethod
    def from_dir(cls, rules_dir: str | Path) -> "RuleEngine":
        """该函数的作用为: 从指定目录加载规则文件并创建 RuleEngine 实例。

        参数: rules_dir - 规则文件所在目录路径
        """
        return cls(load_rules(rules_dir))

    @staticmethod
    def _field_text(request: dict[str, Any], field_name: str) -> str:
        """该函数的作用为: 从结构化请求中提取指定字段的可扫描文本。

        参数: request    - 结构化 HTTP 请求字典
             field_name - 要提取的字段名（如 path/query/body/headers/user_agent）
        """
        if field_name == "user_agent":
            headers = request.get("headers") or {}
            return str(headers.get("User-Agent", ""))
        if field_name == "headers":
            headers = request.get("headers") or {}
            return " ".join(f"{k}: {v}" for k, v in headers.items())
        return str(request.get(field_name, ""))

    def match(self, request: dict[str, Any]) -> list[RuleMatch]:
        """该函数的作用为: 对单个请求执行全部规则匹配，返回所有命中结果（每条规则最多命中一次）。

        参数: request - 协议解析模块产出的结构化请求字典，
                       至少包含 method/path/query/body/headers 等键
        """
        matches: list[RuleMatch] = []
        for rule in self.rules:
            hit = self._first_match(request, rule)
            if hit is not None:
                matches.append(hit)
        return matches

    def _first_match(self, request: dict[str, Any], rule: Rule) -> RuleMatch | None:
        """该函数的作用为: 扫描单条规则的所有目标字段，首次命中即返回结果（天然去重）。

        参数: request - 结构化 HTTP 请求字典
             rule    - 要匹配的单条规则对象
        """
        for field in rule.target_fields:
            text = self._field_text(request, field)
            # user_agent 字段允许空匹配（用于检测空UA），其他字段为空时跳过
            if not text and field != "user_agent":
                continue
            for pattern in rule.patterns:
                m = pattern.search(text)
                if m:
                    return RuleMatch(
                        rule_id=rule.id,
                        attack_type=rule.attack_type,
                        level=rule.level,
                        score=rule.score,
                        field=field,
                        matched_value=m.group(0),
                        reason=f"命中规则 {rule.id}（{rule.description or rule.attack_type}）",
                    )
        return None


if __name__ == "__main__":
    # 实现完 match() 后，在仓库根目录执行：
    #   python -m app.detection.rule_engine
    # 就能看到下面两个请求各自命中了什么。
    from app.config import RULES_DIR

    engine = RuleEngine.from_dir(RULES_DIR)

    benign = {
        "method": "GET", "path": "/search",
        "query": "q=hello", "body": "",
        "headers": {"User-Agent": "Mozilla/5.0"},
    }
    sqli = {
        "method": "GET", "path": "/login",
        "query": "username=admin' or 1=1 --", "body": "",
        "headers": {"User-Agent": "Mozilla/5.0"},
    }

    for name, req in [("正常请求", benign), ("SQL注入请求", sqli)]:
        hits = engine.match(req)
        print(f"\n[{name}] 命中 {len(hits)} 条:")
        for h in hits:
            print(f"  - {h.rule_id} {h.attack_type}({h.level}) 字段={h.field} 片段={h.matched_value!r}")
