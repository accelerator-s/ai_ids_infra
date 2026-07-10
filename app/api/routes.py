from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import crud
from app.database.db import get_db

router = APIRouter(prefix="/api")


class TaskCreateRequest(BaseModel):
    """创建分析任务的请求体，后续供抓包和 pcap 分析模块调用。"""

    task_type: str = Field(..., examples=["pcap"])
    target: str = Field(default="", examples=["sample_http_attack.pcap"])
    status: str = Field(default="pending", examples=["pending"])


class TaskUpdateRequest(BaseModel):
    """更新分析任务状态和统计信息的请求体。"""

    status: str | None = None
    packet_count: int | None = None
    http_count: int | None = None
    alert_count: int | None = None
    finished: bool = False


class AlertCreateRequest(BaseModel):
    """创建告警记录的请求体，检测模块完成后会使用同样的数据结构写入告警。"""

    task_id: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    method: str = ""
    path: str = ""
    query: str = ""
    attack_type: str = "Unknown"
    risk_level: str = "low"
    score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    ai_judgement: str = ""
    ai_reason: str = ""
    reason: str = ""
    status: str = "new"


class ResetDatabaseRequest(BaseModel):
    """清空数据库测试数据的确认请求体。"""

    confirm: bool = False


@router.get("/status")
def get_status() -> dict[str, str]:
    """返回后端服务运行状态，用于 WebUI 健康检查。"""
    return {"status": "ok", "service": "ai-ids-infra"}


@router.post("/tasks")
def create_task(request: TaskCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """创建分析任务记录，便于后续 pcap 或实时抓包模块复用。"""
    task = crud.create_task(
        db,
        task_type=request.task_type,
        target=request.target,
        status=request.status,
    )
    return crud.task_to_dict(task)


@router.get("/tasks")
def list_tasks(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """查询分析任务列表。"""
    tasks = crud.list_tasks(db, limit=limit, offset=offset)
    return {"items": [crud.task_to_dict(task) for task in tasks]}


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: int,
    request: TaskUpdateRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """更新分析任务状态，供抓包停止或 pcap 分析结束时调用。"""
    from datetime import datetime

    task = crud.update_task(
        db,
        task_id,
        status=request.status,
        packet_count=request.packet_count,
        http_count=request.http_count,
        alert_count=request.alert_count,
        finished_at=datetime.utcnow() if request.finished else None,
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return crud.task_to_dict(task)


@router.post("/alerts")
def create_alert(request: AlertCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """创建告警记录，当前可用于接口联调，后续由检测模块自动调用。"""
    alert = crud.create_alert(db, **request.model_dump())
    if alert is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return crud.alert_to_dict(alert)


@router.get("/alerts")
def list_alerts(
    attack_type: str | None = None,
    risk_level: str | None = None,
    src_ip: str | None = None,
    task_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """查询告警列表，支持按攻击类型、风险等级、源 IP 和任务 ID 筛选。"""
    alerts = crud.list_alerts(
        db,
        attack_type=attack_type,
        risk_level=risk_level,
        src_ip=src_ip,
        task_id=task_id,
        limit=limit,
        offset=offset,
    )
    return {"items": [crud.alert_to_dict(alert) for alert in alerts]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """查询单条告警详情。"""
    alert = crud.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return crud.alert_to_dict(alert)


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    """查询 WebUI 仪表盘需要展示的告警和任务统计信息。"""
    return crud.get_stats(db)


@router.post("/dev/reset-database")
def reset_database(request: ResetDatabaseRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """清空开发测试数据，保留数据库文件和表结构。"""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")

    result = crud.reset_database(db)
    return {"status": "reset", **result}
