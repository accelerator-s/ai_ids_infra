"""端到端离线分析集成测试：真读 pcap → tshark 解析 → 检测 → 告警。

覆盖全部 pcap 样本，走完整流程（读包 → 解析 → 规则/行为 → 评分 → 写告警）。
高置信攻击与行为告警是确定性的，直接断言；经典 SQLi 走 AI 门槛，用 mock 的 AI 研判
断言"判恶意 → 生成告警"，不依赖真实大模型。需要 pyshark + tshark，缺任一则整文件跳过。
"""

from pathlib import Path

import pytest

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.ai.request_analyzer import AnalysisResult
    from app.capture.pcap_analyzer import PcapAnalyzer
    from app.config import RULES_DIR
    from app.database import crud, models  # noqa: F401  注册数据表
    from app.database.db import Base
    from app.detection.rule_engine import RuleEngine
    from app.protocol.packet_parser import parse_http_request

    _DEPS_OK = True
except Exception:
    _DEPS_OK = False


def _tshark_ok() -> bool:
    try:
        from pyshark.tshark.tshark import get_process_path
        get_process_path()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not (_DEPS_OK and _tshark_ok()), reason="需要 pyshark + tshark")

PCAP_DIR = Path(__file__).resolve().parent / "pcaps"
NO_LLM = {"llm.base_url": "", "llm.api_key": "", "llm.model": "", "llm.temperature": 0.2}


def _run(pcap_name: str, ai_analyzer=None):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    kwargs = {"db": db, "packet_parser": parse_http_request,
              "rule_engine": RuleEngine.from_dir(RULES_DIR), "settings": NO_LLM}
    if ai_analyzer is not None:
        kwargs["ai_analyzer"] = ai_analyzer
    result = PcapAnalyzer(**kwargs).analyze(PCAP_DIR / pcap_name)
    return result, crud.list_alerts(db, task_id=result.task_id)


# 高置信内容攻击直接告警、行为攻击超阈值告警——都不依赖 AI，确定性断言
@pytest.mark.parametrize("pcap, expect_substr", [
    ("sample_xss.pcap", "XSS"),
    ("sample_cmdi.pcap", "Command Injection"),
    ("sample_traversal.pcap", "Traversal"),
    ("sample_sensitive.pcap", "Sensitive"),
    ("sample_scanner.pcap", "Scanner"),
    ("sample_scan404.pcap", "扫描"),
    ("sample_highfreq.pcap", "DDoS"),
    ("sample_bruteforce.pcap", "暴力破解"),
])
def test_pcap_detects(pcap, expect_substr):
    result, alerts = _run(pcap)
    assert result.status == "completed"
    assert any(expect_substr in a.attack_type for a in alerts), \
        f"{pcap} 应命中含「{expect_substr}」的告警，实得 {[a.attack_type for a in alerts]}"


def test_benign_pcap_no_alert():
    result, alerts = _run("sample_benign.pcap")
    assert result.http_count > 0
    assert alerts == []


def test_mixed_pcap_flags_multiple_attacks():
    result, alerts = _run("sample_mixed.pcap")
    types = {a.attack_type for a in alerts}
    assert any("XSS" in t for t in types)
    assert len(alerts) >= 3


def test_multi_ip_only_attacker_flagged():
    _, alerts = _run("sample_multi_ip.pcap")
    assert {a.src_ip for a in alerts} == {"192.168.1.66"}


def test_ai_review_generates_alert():
    """经典 SQLi 走 AI 门槛：mock 研判判恶意，应生成带 AI 结论的告警。"""
    def mock_ai(request, risk, settings):
        return AnalysisResult(ai_judgement="malicious", attack_type="SQL Injection",
                              confidence=0.9, reason="mock 判定注入", model="mock")

    _, alerts = _run("sample_sqli.pcap", ai_analyzer=mock_ai)
    ai_alerts = [a for a in alerts if a.ai_judgement == "malicious"]
    assert ai_alerts, "AI 判恶意后应生成告警"
    assert "SQL Injection" in ai_alerts[0].attack_type
