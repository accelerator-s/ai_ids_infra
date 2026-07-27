"""API 接口返回格式：用 TestClient + 独立内存库，不污染开发数据库。

需在装好依赖的 venv 里运行：pytest tests/test_api.py
若 crud.get_settings 需要种子数据，/status 用例可能要按实际实现微调。
"""

from __future__ import annotations

import pytest

try:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.database import models  # noqa: F401  导入以注册数据表
    from app.database.db import Base, get_db
    from app.main import app

    _DEPS_OK = True
except Exception:  # 缺 fastapi / sqlalchemy 时优雅跳过
    _DEPS_OK = False

pytestmark = pytest.mark.skipif(not _DEPS_OK, reason="需要 fastapi / sqlalchemy 等依赖")


def _client() -> "TestClient":
    """每个用例一套独立内存库，互不干扰，也不碰 data/ids.db。"""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def _db():
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _db
    return TestClient(app)


def test_status_format():
    resp = _client().get("/api/status")
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"


def test_status_reports_missing_tshark_as_unavailable(monkeypatch):
    from app.api import routes

    monkeypatch.setattr(routes.shutil, "which", lambda name: None)
    modules = _client().get("/api/status").json()["modules"]
    assert modules["live_capture"]["ready"] is False
    assert modules["pcap_analyzer"]["ready"] is False
    assert "tshark" in modules["live_capture"]["reason"]
    assert modules["live_capture"]["state"] == "missing_dependency"
    assert modules["pcap_analyzer"]["dependency"] == "tshark"
    assert modules["risk_score"]["ready"] is True
    assert modules["behavior_detector"]["ready"] is True
    assert modules["packet_parser"]["ready"] is True
    assert modules["ai_analyzer"]["ready"] is False
    assert modules["ai_report"]["ready"] is False
    assert "大模型配置不完整" in modules["ai_analyzer"]["reason"]


def test_status_checks_capture_interfaces(monkeypatch):
    from app.api import routes

    monkeypatch.setattr(routes.shutil, "which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr(routes, "list_tshark_interfaces", lambda: [{"name": "eth0"}])
    modules = _client().get("/api/status").json()["modules"]
    assert modules["live_capture"] == {
        "ready": True,
        "tshark_path": "/usr/bin/tshark",
        "interface_count": 1,
    }
    assert modules["pcap_analyzer"]["ready"] is True


def test_capture_interfaces_reports_missing_dependency(monkeypatch):
    from app.api import routes

    def missing_tshark():
        raise routes.InterfaceDiscoveryError("缺少运行依赖 tshark，或 tshark 未加入 PATH")

    monkeypatch.setattr(routes, "list_tshark_interfaces", missing_tshark)
    response = _client().get("/api/capture/interfaces")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "missing_dependency"


def test_task_roundtrip():
    client = _client()
    created = client.post("/api/tasks", json={"task_type": "pcap", "target": "demo.pcap"})
    assert created.status_code == 200
    task = created.json()
    assert task["task_type"] == "pcap"
    assert "id" in task

    listed = client.get("/api/tasks")
    assert listed.status_code == 200
    assert any(t["id"] == task["id"] for t in listed.json()["items"])


def test_alerts_list_format():
    resp = _client().get("/api/alerts")
    assert resp.status_code == 200
    assert isinstance(resp.json().get("items"), list)


def test_stats_format():
    resp = _client().get("/api/stats")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


def test_manual_review_malicious_creates_linked_alert():
    client = _client()
    task = client.post("/api/tasks", json={"task_type": "pcap", "target": "review.pcap"}).json()

    from app.database import crud
    from app.database.db import get_db

    db = next(app.dependency_overrides[get_db]())
    review = crud.create_ai_review(
        db,
        task_id=task["id"],
        request_summary={"src_ip": "10.0.0.8", "dst_ip": "10.0.0.2", "method": "GET", "path": "/search", "query": "q='"},
        original_score=28,
        matched_rules=["sqli-003"],
        judgement="manual_review",
        attack_type="SQL Injection",
        reason="大模型服务尚未完整配置",
        status="pending_review",
    )
    response = client.post(
        f"/api/ai/reviews/{review.id}/decision",
        json={"judgement": "malicious", "attack_type": "SQL Injection", "reason": "请求中存在永真条件与注释符组合"},
    )
    assert response.status_code == 200
    decided = response.json()
    assert decided["status"] == "completed"
    assert decided["alert_id"] is not None
    alert = client.get(f"/api/alerts/{decided['alert_id']}").json()
    assert alert["risk_level"] == "low"
    assert alert["src_ip"] == "10.0.0.8"

    duplicate = client.post(
        f"/api/ai/reviews/{review.id}/decision",
        json={"judgement": "benign", "reason": "重复处理"},
    )
    assert duplicate.status_code == 409


def test_manual_review_benign_does_not_create_alert():
    client = _client()
    from app.database import crud
    from app.database.db import get_db

    db = next(app.dependency_overrides[get_db]())
    review = crud.create_ai_review(
        db,
        request_summary={"method": "GET", "path": "/health"},
        original_score=22,
        matched_rules=["generic-001"],
        judgement="manual_review",
        status="pending_review",
    )
    response = client.post(
        f"/api/ai/reviews/{review.id}/decision",
        json={"judgement": "benign", "reason": "已核对为内部健康检查请求"},
    )
    assert response.status_code == 200
    assert response.json()["alert_id"] is None
    assert response.json()["attack_type"] == "Normal"
