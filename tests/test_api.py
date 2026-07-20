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
