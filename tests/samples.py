"""合成测试样本：结构化请求 / 请求流 + 标签，供单测与"召回率 / 误报率"评测使用。

分两类：
  RULE_SAMPLES     单条请求，测规则检测（内容型攻击）。
  BEHAVIOR_SAMPLES 请求流，测行为检测（跨请求）。

标签只区分"该不该告警"，不绑定具体规则 id，换规则库或改实现后样本仍可复用。
反例里特意放了"像攻击的正常流量"和"编码变形的攻击"，分别用来量化误报和检验归一化。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class RuleSample:
    name: str
    category: str                 # sqli/xss/cmdi/traversal/sensitive/scanner/benign
    request: dict[str, Any]
    variant: str = "plain"        # plain / encoded：编码变体用来检验规则①归一化
    note: str = ""

    @property
    def is_attack(self) -> bool:
        return self.category != "benign"


@dataclass
class BehaviorSample:
    name: str
    stream: list[dict[str, Any]]
    expect: set[str]              # 预期命中的行为 attack_type；正常流为空集
    note: str = ""

    @property
    def is_attack(self) -> bool:
        return bool(self.expect)


def _req(path: str = "/", query: str = "", body: str = "", ua: str = "Mozilla/5.0",
         method: str = "GET", status: int = 200) -> dict[str, Any]:
    """按数据契约拼一条结构化请求。"""
    return {"method": method, "path": path, "query": query, "body": body,
            "headers": {"User-Agent": ua}, "status": status}


RULE_SAMPLES: list[RuleSample] = [
    RuleSample("sqli-or", "sqli", _req("/login", "user=admin' or 1=1 --")),
    RuleSample("sqli-union", "sqli", _req("/item", "id=1 union select user,pw from users")),
    RuleSample("sqli-sleep", "sqli", _req("/item", "id=1 and sleep(5)")),
    RuleSample("sqli-encoded", "sqli", _req("/item", "id=1 uni%6fn%20sel%65ct 1"),
               variant="encoded", note="URL 编码的 union select"),

    RuleSample("xss-script", "xss", _req("/search", "q=<script>alert(1)</script>")),
    RuleSample("xss-onerror", "xss", _req("/p", "n=<img src=x onerror=alert(1)>")),
    RuleSample("xss-encoded", "xss", _req("/search", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
               variant="encoded", note="URL 编码的 <script>"),

    RuleSample("cmdi-semicolon", "cmdi", _req("/ping", "host=127.0.0.1;cat /etc/passwd")),
    RuleSample("cmdi-and", "cmdi", _req("/ping", "ip=1.1.1.1 && whoami")),

    RuleSample("trav-plain", "traversal", _req("/dl", "file=../../../../etc/passwd")),
    RuleSample("trav-encoded", "traversal", _req("/dl", "file=..%2f..%2f..%2fetc%2fpasswd"),
               variant="encoded", note="编码的 ../"),

    RuleSample("sensitive-env", "sensitive", _req("/.env")),
    RuleSample("sensitive-git", "sensitive", _req("/.git/config")),

    RuleSample("scanner-sqlmap", "scanner", _req("/", ua="sqlmap/1.5.2")),
    RuleSample("scanner-nikto", "scanner", _req("/", ua="Mozilla/5.00 (Nikto/2.1.6)")),

    # 正常（干净），不该告警
    RuleSample("benign-search", "benign", _req("/search", "q=running shoes")),
    RuleSample("benign-login", "benign", _req("/login", "user=alice&pw=hunter2", method="POST")),
    RuleSample("benign-article", "benign", _req("/blog/how-to-cook-rice")),

    # 误报诱饵：像攻击的正常流量（当前 sqli 关键词规则可能误报）
    RuleSample("benign-or", "benign", _req("/search", "q=shoes or boots"), note="含 ' or '"),
    RuleSample("benign-select", "benign", _req("/pricing", "q=select a plan from our list"),
               note="含 select/from"),
    RuleSample("benign-email", "benign", _req("/contact", "email=john.from@example.com"),
               note="含 from"),
]


def _stream(ip: str, n: int, path: str = "/x", status: int = 200,
            start: float = 1000.0, step: float = 1.0,
            path_fn: Callable[[int], str] | None = None) -> list[dict[str, Any]]:
    """造一条同 IP、时间递增的请求流。"""
    return [{"src_ip": ip, "path": (path_fn(i) if path_fn else path),
             "status": status, "timestamp": start + i * step} for i in range(n)]


_hf_shuffled = _stream("10.1.0.6", 120, step=0.4)

BEHAVIOR_SAMPLES: list[BehaviorSample] = [
    BehaviorSample("high-freq", _stream("10.1.0.1", 120, step=0.4), {"DDoS / 高频访问"}),
    BehaviorSample("brute-force", _stream("10.1.0.2", 12, path="/login", status=401, step=15.0),
                   {"暴力破解"}),
    BehaviorSample("scanner-paths",
                   _stream("10.1.0.3", 35, status=404, path_fn=lambda i: f"/p{i}"),
                   {"Web 扫描器"}),
    BehaviorSample("scanner-404", _stream("10.1.0.4", 50, path="/nope", status=404, step=0.5),
                   {"Web 扫描器"}),
    BehaviorSample("benign-user",
                   _stream("10.1.0.5", 20, step=3.0, path_fn=lambda i: f"/page{i % 3}"),
                   set(), note="慢速、少路径的正常浏览"),
    BehaviorSample("high-freq-shuffled", list(reversed(_hf_shuffled)), {"DDoS / 高频访问"},
                   note="同高频流但时间戳乱序，检验行为⑤"),
]


def make_load(n_requests: int, n_ips: int, step: float = 0.001) -> list[dict[str, Any]]:
    """造大流量给性能测试用（行为①②）：n_ips 个 IP 轮流发，共 n_requests 条。"""
    return [{"src_ip": f"10.9.{(i % n_ips) // 256}.{(i % n_ips) % 256}",
             "path": f"/p{i % 50}", "status": 200, "timestamp": 1000.0 + i * step}
            for i in range(n_requests)]
