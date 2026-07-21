"""行为检测：四类行为命中、正常流不误报、冷却去重、窗口过期。"""

from app.detection.behavior_detector import BehaviorDetector
from tests.samples import BEHAVIOR_SAMPLES


def _detect(stream) -> set[str]:
    return {m.attack_type for m in BehaviorDetector().detect(stream)}


def test_behavior_samples():
    for s in BEHAVIOR_SAMPLES:
        got = _detect(s.stream)
        if s.is_attack:
            assert s.expect & got, f"{s.name} 应命中 {s.expect}，实得 {got}"
        else:
            assert not got, f"{s.name} 不应告警，实得 {got}"


def test_cooldown_no_duplicate():
    stream = [{"src_ip": "1.1.1.1", "path": "/x", "status": 200, "timestamp": 1000.0 + i * 0.1}
              for i in range(300)]
    ddos = [h for h in BehaviorDetector().detect(stream) if h.attack_type == "DDoS / 高频访问"]
    assert len(ddos) <= 3, f"冷却应抑制重复告警，实得 {len(ddos)} 条"


def test_slow_traffic_not_flagged():
    # 请求间隔大于窗口密度，任何 60s 窗口内都不足阈值 -> 不应告警
    stream = [{"src_ip": "2.2.2.2", "path": "/x", "status": 200, "timestamp": 1000.0 + i * 2.0}
              for i in range(200)]
    assert not BehaviorDetector().detect(stream), "低速流不应触发高频"
