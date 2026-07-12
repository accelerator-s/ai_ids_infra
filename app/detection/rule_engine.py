"""规则检测模块：把结构化 HTTP 请求与 JSON 规则库做正则匹配，输出命中的攻击特征。

在整条检测链里的位置：
    抓包 -> 协议解析 -> [规则检测(本模块)] -> 行为检测 -> 风险评分 -> AI 二次过滤 -> 写库

职责单一，方便独立测试：
  - 本模块只回答"单个请求命中了哪些规则"。
  - 不做跨请求的行为统计（那是 behavior_detector 的事）。
  - 不把多条命中汇总成最终风险分（那是 risk_score 的事）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Rule:
    """一条规则，对应规则库 JSON 里的一个对象。"""

    id: str
    attack_type: str
    level: str                     # low / medium / high / critical
    score: float
    patterns: list[re.Pattern]     # 已编译的正则（大小写不敏感）
    target_fields: list[str]       # 要扫描的请求字段，如 ["query", "body"]
    description: str = ""


@dataclass
class RuleMatch:
    """一次命中的结果，供 risk_score 模块聚合、最终写入 alerts 表。"""

    rule_id: str
    attack_type: str
    level: str
    score: float
    field: str          # 命中发生在哪个字段
    matched_value: str  # 触发命中的原始文本片段（便于展示 / 排查）
    reason: str         # 人类可读的命中原因


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """加载 rules_dir 下所有 *.json 规则文件，编译正则后返回 Rule 列表。

    这部分是样板代码，已经帮你写好，可以直接用；重点放在下面的 RuleEngine.match()。
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
    """持有编译好的规则集，对每个请求做匹配。"""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def from_dir(cls, rules_dir: str | Path) -> "RuleEngine":
        return cls(load_rules(rules_dir))

    @staticmethod
    def _field_text(request: dict[str, Any], field_name: str) -> str:
        """从结构化请求里取出某个字段的可扫描文本。

        header / user_agent 的取值有点绕，这里也帮你写好了，
        这样你能专注在 match() 的匹配主逻辑上。
        """
        if field_name == "user_agent":
            headers = request.get("headers") or {}
            return str(headers.get("User-Agent", ""))
        if field_name == "headers":
            headers = request.get("headers") or {}
            return " ".join(f"{k}: {v}" for k, v in headers.items())
        return str(request.get(field_name, ""))

    def match(self, request: dict[str, Any]) -> list[RuleMatch]:
        """返回 request 命中的所有规则，每条规则最多命中一次。

        request 是协议解析模块产出的结构化请求（数据契约），
        至少包含 method / path / query / body / headers 等键。示例见文件末尾 __main__。
        """
        matches: list[RuleMatch] = []
        for rule in self.rules:
            hit = self._first_match(request, rule)
            if hit is not None:
                matches.append(hit)
        return matches

    def _first_match(self, request: dict[str, Any], rule: Rule) -> RuleMatch | None:
        """扫描单条规则的所有目标字段，命中即返回（return 会跳出全部循环，天然去重）。"""
        for field in rule.target_fields:
            text = self._field_text(request, field)
            if not text:
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
