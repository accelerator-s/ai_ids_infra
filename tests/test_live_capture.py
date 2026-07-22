"""实时抓包 live_capture 的功能测试。

覆盖可 mock 的逻辑：纯函数（BPF 过滤、目标解析、网卡列表）、注入假 capture 的会话检测编排、
管理器 start/stop 生命周期。真实网卡抓包无法自动化，靠部署 + 模拟攻击验证，不在此。
"""

from types import SimpleNamespace

import pytest

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.ai.request_analyzer import AnalysisResult
    from app.capture import live_capture as lc
    from app.config import RULES_DIR
    from app.database import crud, models  # noqa: F401  注册数据表
    from app.database.db import Base
    from app.detection.rule_engine import RuleEngine

    _DEPS_OK = True
except Exception:
    _DEPS_OK = False

pytestmark = pytest.mark.skipif(not _DEPS_OK, reason="需要 pyshark / sqlalchemy 等依赖")


# ---------- 纯函数 ----------

def test_resolve_target_ip():
    assert lc.resolve_target("ip", "192.168.1.10") == ["192.168.1.10"]


def test_resolve_target_rejects_bad_ip():
    with pytest.raises(lc.CaptureConfigurationError):
        lc.resolve_target("ip", "not-an-ip")


def test_resolve_target_rejects_empty():
    with pytest.raises(lc.CaptureConfigurationError):
        lc.resolve_target("ip", "   ")


def test_resolve_target_domain(monkeypatch):
    import socket
    monkeypatch.setattr(lc.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))])
    assert lc.resolve_target("domain", "example.com") == ["93.184.216.34"]


def test_build_capture_filter_single():
    assert lc.build_capture_filter(["192.168.1.10"], 80) == "host 192.168.1.10 and tcp port 80"


def test_build_capture_filter_multiple_and_dedup():
    result = lc.build_capture_filter(["10.0.0.1", "10.0.0.2", "10.0.0.1"], 8080)
    assert result == "(host 10.0.0.1 or host 10.0.0.2) and tcp port 8080"


def test_build_capture_filter_rejects_bad_port():
    with pytest.raises(lc.CaptureConfigurationError):
        lc.build_capture_filter(["10.0.0.1"], 0)


def test_list_interfaces_parses_output(monkeypatch):
    fake = SimpleNamespace(stdout="1. eth0 (Ethernet)\n2. lo (Loopback)\n", stderr="", returncode=0)
    monkeypatch.setattr(lc.subprocess, "run", lambda *a, **k: fake)
    interfaces = lc.list_tshark_interfaces()
    assert {"name": "eth0", "description": "(Ethernet)"} in interfaces
    assert any(i["name"] == "lo" for i in interfaces)


def test_list_interfaces_without_tshark(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(lc.subprocess, "run", boom)
    with pytest.raises(lc.InterfaceDiscoveryError):
        lc.list_tshark_interfaces()


# ---------- 会话检测编排（注入假 capture，不碰真网卡）----------

class _FakeCapture:
    def __init__(self, packets):
        self._packets = packets

    def sniff_continuously(self):
        yield from self._packets

    def close(self):
        pass


def _in_memory_maker():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _new_task(maker):
    db = maker()
    task = crud.create_task(db, task_type="live", target="127.0.0.1", status="running")
    db.close()
    return task.id


def _req(query, path="/s", src_ip="1.1.1.1"):
    return {"src_ip": src_ip, "dst_ip": "9.9.9.9", "src_port": 5000, "dst_port": 80,
            "method": "GET", "path": path, "query": query, "body": "",
            "headers": {"User-Agent": "Mozilla/5.0"}, "status": 0}


def _run_session(maker, task_id, packets, ai=None):
    """假包就是请求 dict 本身；同步调用 run()（不起线程）。"""
    session = lc.LiveCaptureSession(
        task_id=task_id, interface="lo", target="127.0.0.1",
        capture_filter="host 127.0.0.1 and tcp port 80",
        session_factory=maker,
        packet_parser=lambda packet: packet,
        rule_engine=RuleEngine.from_dir(RULES_DIR),
        ai_analyzer=ai or (lambda req, risk, s: AnalysisResult(
            ai_judgement="malicious", attack_type="SQL Injection", confidence=0.9, reason="mock", model="mock")),
        settings={"llm.base_url": "", "llm.api_key": "", "llm.model": "", "llm.temperature": 0.2},
        capture_factory=lambda interface, bpf_filter: _FakeCapture(packets),
    )
    session.run()


def test_session_detects_high_confidence_attack():
    maker = _in_memory_maker()
    task_id = _new_task(maker)
    _run_session(maker, task_id, [_req("q=<script>alert(1)</script>")])
    alerts = crud.list_alerts(maker(), task_id=task_id)
    assert any("XSS" in a.attack_type for a in alerts)


def test_session_ai_path_generates_alert():
    maker = _in_memory_maker()
    task_id = _new_task(maker)
    _run_session(maker, task_id, [_req("q='")])   # 中危 -> AI 门槛，mock 判恶意
    alerts = crud.list_alerts(maker(), task_id=task_id)
    assert any(a.ai_judgement == "malicious" for a in alerts)


def test_session_benign_no_alert():
    maker = _in_memory_maker()
    task_id = _new_task(maker)
    _run_session(maker, task_id, [_req("q=running shoes", path="/search")])
    assert crud.list_alerts(maker(), task_id=task_id) == []


# ---------- 管理器生命周期（注入假 session_class）----------

class _FakeSession:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def request_stop(self):
        self.stopped = True
        return True


def test_manager_start_and_stop():
    maker = _in_memory_maker()
    manager = lc.LiveCaptureManager(session_factory=maker, session_class=_FakeSession)
    task = manager.start(maker(), interface="lo", target_type="ip", target="127.0.0.1", port=80)
    assert manager._sessions[task.id].started is True
    assert manager._sessions[task.id].capture_filter == "host 127.0.0.1 and tcp port 80"
    assert manager.stop(task.id) is True


def test_manager_start_requires_interface():
    maker = _in_memory_maker()
    manager = lc.LiveCaptureManager(session_factory=maker, session_class=_FakeSession)
    with pytest.raises(lc.CaptureConfigurationError):
        manager.start(maker(), interface="  ", target_type="ip", target="127.0.0.1", port=80)


def test_manager_stop_unknown_returns_none():
    manager = lc.LiveCaptureManager(session_factory=_in_memory_maker(), session_class=_FakeSession)
    assert manager.stop(999) is None
