"""行为检测模块：对同一来源 IP 的请求做滑动时间窗口统计，识别单条请求看不出的攻击。

    抓包 -> 协议解析 -> 规则检测 -> [行为检测(本模块)] -> 风险评分 -> AI 二次过滤 -> 写库

有状态：给每个 IP 维护一份最近请求的窗口，判断高频访问、暴力破解、Web 扫描。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


DEFAULT_BEHAVIOR_CONFIG: dict[str, dict[str, Any]] = {
    "high_freq":     {"attack_type": "DDoS / 高频访问", "metric": "请求数",     "window": 60,  "threshold": 100, "score": 30, "level": "high",   "cooldown": 60},
    "brute_force":   {"attack_type": "暴力破解",         "metric": "登录失败数", "window": 300, "threshold": 10,  "score": 30, "level": "high",   "cooldown": 300},
    "scanner_paths": {"attack_type": "Web 扫描器",       "metric": "不同路径数", "window": 60,  "threshold": 30,  "score": 30, "level": "medium", "cooldown": 60},
    "not_found":     {"attack_type": "Web 扫描器",       "metric": "404 响应数", "window": 60,  "threshold": 40,  "score": 30, "level": "medium", "cooldown": 60},
}

LOGIN_PATHS = ("/login", "/signin", "/api/login", "/user/login")


@dataclass
class Record:
    """窗口里保存的单条请求足迹。"""

    ts: float
    path: str
    status: int


@dataclass
class BehaviorMatch:
    """一次行为告警。字段与 risk_score / 告警表对齐，另带行为特有的 src_ip 和 evidence。"""

    attack_type: str
    level: str
    score: float
    src_ip: str
    reason: str
    evidence: dict = field(default_factory=dict)


class IpBehavior:
    """单个 IP 的行为状态：一条按时间递增的记录窗口，一张告警冷却表。"""

    def __init__(self, src_ip: str, config: dict[str, dict[str, Any]]) -> None:
        """为某个来源 IP 建立记录窗口和告警冷却表。"""
        self.src_ip = src_ip
        self.config = config
        self.records: deque[Record] = deque()
        self.alerted: dict[str, float] = {}
        self.fired: list[BehaviorMatch] = []

    @staticmethod
    def _to_epoch(value: Any) -> float:
        """把请求的 timestamp 转成 epoch 秒。"""
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value:
            try:
                return datetime.fromisoformat(value.replace(" ", "T")).timestamp()
            except ValueError:
                return 0.0
        return 0.0

    def feed(self, request: dict[str, Any]) -> None:
        """吃进一条请求：转成 Record 入窗，清理过期记录，再对每类规则判定一次。"""
        ts = self._to_epoch(request.get("timestamp", 0.0))
        self.records.append(
            Record(ts=ts, path=str(request.get("path", "")), status=int(request.get("status", 0) or 0))
        )
        self._evict_expired(ts)
        for kind in self.config:
            self._alert(kind, ts)

    def _evict_expired(self, now: float) -> None:
        """按最长窗口清理队首过期记录。"""
        lo = now - max(rule["window"] for rule in self.config.values())
        while self.records and self.records[0].ts < lo:
            self.records.popleft()

    def _count(self, kind: str, now: float) -> int:
        """统计 kind 规则在自己窗口内的度量值：高频数请求条数，暴破数登录失败，扫描数去重路径，404 数响应码。"""
        recent = [r for r in self.records if r.ts >= now - self.config[kind]["window"]]
        if kind == "brute_force":
            return sum(1 for r in recent if r.path in LOGIN_PATHS and r.status in (401, 403))
        if kind == "scanner_paths":
            return len({r.path for r in recent})
        if kind == "not_found":
            return sum(1 for r in recent if r.status == 404)
        return len(recent)

    def _alert(self, kind: str, now: float) -> None:
        """冷却未过就跳过；否则达到阈值就记一次告警并刷新冷却时间。"""
        cfg = self.config[kind]
        last = self.alerted.get(kind)
        if last is not None and now - last < cfg["cooldown"]:
            return
        n = self._count(kind, now)
        if n < cfg["threshold"]:
            return
        self.alerted[kind] = now
        self.fired.append(BehaviorMatch(
            attack_type=cfg["attack_type"],
            level=cfg["level"],
            score=cfg["score"],
            src_ip=self.src_ip,
            reason=f"IP {self.src_ip} 在 {cfg['window']}s 内{cfg['metric']} {n}，达到阈值 {cfg['threshold']}",
            evidence={"count": n, "window": cfg["window"], "threshold": cfg["threshold"]},
        ))

    def submit(self) -> list[BehaviorMatch]:
        """上交本 IP 累积到的告警。"""
        return list(self.fired)


class BehaviorDetector:
    """行为检测入口：按 src_ip 把请求分流到各自的 IpBehavior，再汇总告警。"""

    def __init__(self, config: dict[str, dict[str, Any]] | None = None) -> None:
        """载入行为规则配置，准备各 IP 的状态表。"""
        self.config = config or DEFAULT_BEHAVIOR_CONFIG
        self._ips: dict[str, IpBehavior] = {}

    def detect(self, requests: Iterable[dict[str, Any]]) -> list[BehaviorMatch]:
        """按时间顺序喂入一批请求，返回期间产生的所有行为告警。"""
        for request in requests:
            ip = str(request.get("src_ip", ""))
            if not ip:
                continue
            if ip not in self._ips:
                self._ips[ip] = IpBehavior(ip, self.config)
            self._ips[ip].feed(request)

        results: list[BehaviorMatch] = []
        for ip_behavior in self._ips.values():
            results.extend(ip_behavior.submit())
        return results


if __name__ == "__main__":
    stream_a = [{"src_ip": "10.0.0.1", "path": "/x", "status": 200, "timestamp": 1000.0 + i * 0.4}
                for i in range(120)]
    stream_b = [{"src_ip": "10.0.0.2", "path": "/login", "status": 401, "timestamp": 2000.0 + i * 15}
                for i in range(12)]
    stream_c = [{"src_ip": "10.0.0.3", "path": f"/p{i}", "status": 404, "timestamp": 3000.0 + i}
                for i in range(35)]
    stream_d = [{"src_ip": "10.0.0.4", "path": "/nope", "status": 404, "timestamp": 4000.0 + i * 0.5}
                for i in range(50)]

    for name, stream in [("高频", stream_a), ("暴破", stream_b), ("扫描", stream_c), ("404", stream_d)]:
        hits = BehaviorDetector().detect(stream)
        print(f"[{name}] 命中 {len(hits)} 条:")
        for h in hits:
            print(f"  - {h.attack_type}({h.level}) src={h.src_ip} {h.reason}")
