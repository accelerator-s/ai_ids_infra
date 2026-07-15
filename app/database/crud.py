import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import desc, func, text
from sqlalchemy.orm import Session

from app.config import DEFAULT_SETTINGS
from app.database.models import Alert, Report, Setting, Task


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def get_settings(db: Session) -> dict[str, Any]:
    """读取全部运行配置，数据库中没有的键回落到默认值。"""
    settings = dict(DEFAULT_SETTINGS)
    for row in db.query(Setting).all():
        if row.key not in DEFAULT_SETTINGS:
            continue
        try:
            settings[row.key] = json.loads(row.value)
        except json.JSONDecodeError:
            settings[row.key] = row.value
    return settings


def save_settings(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    """写入运行配置，只接受默认值表里已知的键。"""
    for key, value in values.items():
        if key not in DEFAULT_SETTINGS:
            continue
        row = db.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            db.add(row)
        row.value = _json_dumps(value)
    db.commit()
    return get_settings(db)


def create_task(db: Session, task_type: str, target: str = "", status: str = "pending") -> Task:
    """创建分析任务记录，供实时抓包和 pcap 分析模块复用。"""
    task = Task(task_type=task_type, target=target, status=status)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def update_task(
    db: Session,
    task_id: int,
    *,
    status: str | None = None,
    packet_count: int | None = None,
    http_count: int | None = None,
    alert_count: int | None = None,
    finished_at: datetime | None = None,
) -> Task | None:
    """更新分析任务状态和统计信息。"""
    task = db.get(Task, task_id)
    if task is None:
        return None

    if status is not None:
        task.status = status
    if packet_count is not None:
        task.packet_count = packet_count
    if http_count is not None:
        task.http_count = http_count
    if alert_count is not None:
        task.alert_count = alert_count
    if finished_at is not None:
        task.finished_at = finished_at

    db.commit()
    db.refresh(task)
    return task


def get_task(db: Session, task_id: int) -> Task | None:
    """根据任务 ID 查询单个分析任务。"""
    return db.get(Task, task_id)


def list_tasks(db: Session, limit: int = 100, offset: int = 0) -> list[Task]:
    """按创建时间倒序查询分析任务列表。"""
    return (
        db.query(Task)
        .order_by(desc(Task.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )


def create_alert(db: Session, **alert_data: Any) -> Alert | None:
    """创建告警记录，并自动同步所属任务的告警数量。"""
    matched_rules = alert_data.get("matched_rules")
    if matched_rules is not None and not isinstance(matched_rules, str):
        alert_data["matched_rules"] = _json_dumps(matched_rules)

    task_id = alert_data.get("task_id")
    task = None
    if task_id is not None:
        task = db.get(Task, task_id)
        if task is None:
            return None

    alert = Alert(**alert_data)
    db.add(alert)

    if task is not None:
        task.alert_count += 1

    db.commit()
    db.refresh(alert)
    return alert


def list_alerts(
    db: Session,
    *,
    attack_type: str | None = None,
    risk_level: str | None = None,
    src_ip: str | None = None,
    task_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    """查询告警列表，支持按攻击类型、风险等级、源 IP 和任务 ID 筛选。"""
    query = db.query(Alert)
    if attack_type:
        query = query.filter(Alert.attack_type == attack_type)
    if risk_level:
        query = query.filter(Alert.risk_level == risk_level)
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)
    if task_id is not None:
        query = query.filter(Alert.task_id == task_id)

    return query.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()


def get_alert(db: Session, alert_id: int) -> Alert | None:
    """根据告警 ID 查询单条告警详情。"""
    return db.get(Alert, alert_id)


def get_stats(db: Session) -> dict[str, Any]:
    """从告警和任务表动态计算 WebUI 需要展示的统计数据。"""
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_tasks = db.query(func.count(Task.id)).scalar() or 0

    attack_rows = db.query(Alert.attack_type, func.count(Alert.id)).group_by(Alert.attack_type).all()
    risk_rows = db.query(Alert.risk_level, func.count(Alert.id)).group_by(Alert.risk_level).all()
    ip_rows = (
        db.query(Alert.src_ip, func.count(Alert.id).label("count"))
        .filter(Alert.src_ip != "")
        .group_by(Alert.src_ip)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    task_rows = db.query(Task.status, func.count(Task.id)).group_by(Task.status).all()
    recent_alerts = list_alerts(db, limit=10)

    return {
        "total_alerts": total_alerts,
        "total_tasks": total_tasks,
        "attack_type_distribution": dict(Counter({key: count for key, count in attack_rows})),
        "risk_level_distribution": dict(Counter({key: count for key, count in risk_rows})),
        "top_source_ips": [{"src_ip": src_ip, "count": count} for src_ip, count in ip_rows],
        "task_status_distribution": dict(Counter({key: count for key, count in task_rows})),
        "recent_alerts": [alert_to_dict(alert) for alert in recent_alerts],
    }


def get_task_stats(db: Session, task_id: int) -> dict[str, Any]:
    """统计单个任务的告警分布和典型告警，供 AI 评测报告汇总输入。"""
    task_alerts = db.query(Alert).filter(Alert.task_id == task_id)
    total = task_alerts.count()

    attack_rows = (
        db.query(Alert.attack_type, func.count(Alert.id))
        .filter(Alert.task_id == task_id)
        .group_by(Alert.attack_type)
        .all()
    )
    risk_rows = (
        db.query(Alert.risk_level, func.count(Alert.id))
        .filter(Alert.task_id == task_id)
        .group_by(Alert.risk_level)
        .all()
    )
    ip_rows = (
        db.query(Alert.src_ip, func.count(Alert.id).label("count"))
        .filter(Alert.task_id == task_id, Alert.src_ip != "")
        .group_by(Alert.src_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    typical_alerts = task_alerts.order_by(desc(Alert.score), desc(Alert.created_at)).limit(5).all()

    return {
        "alert_total": total,
        "attack_type_distribution": dict(attack_rows),
        "risk_level_distribution": dict(risk_rows),
        "top_source_ips": [{"src_ip": src_ip, "count": count} for src_ip, count in ip_rows],
        "typical_alerts": [alert_to_dict(alert) for alert in typical_alerts],
    }


def create_report(db: Session, **report_data: Any) -> Report:
    """保存 AI 评测报告，key_findings 和 recommendations 存 JSON 文本。"""
    for field in ("key_findings", "recommendations"):
        value = report_data.get(field)
        if value is not None and not isinstance(value, str):
            report_data[field] = _json_dumps(value)

    report = Report(**report_data)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def list_reports(
    db: Session,
    *,
    task_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Report]:
    """按创建时间倒序查询报告列表，可按任务 ID 筛选。"""
    query = db.query(Report)
    if task_id is not None:
        query = query.filter(Report.task_id == task_id)
    return query.order_by(desc(Report.created_at), desc(Report.id)).offset(offset).limit(limit).all()


def get_report(db: Session, report_id: int) -> Report | None:
    """根据报告 ID 查询单份报告。"""
    return db.get(Report, report_id)


def reset_database(db: Session) -> dict[str, int]:
    """清空测试数据并保留数据库表结构。"""
    deleted_reports = db.query(Report).delete()
    deleted_alerts = db.query(Alert).delete()
    deleted_tasks = db.query(Task).delete()

    has_sequence = db.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'")
    ).first()
    if has_sequence is not None:
        db.execute(text("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'tasks', 'reports')"))

    db.commit()
    return {
        "deleted_alerts": deleted_alerts,
        "deleted_tasks": deleted_tasks,
        "deleted_reports": deleted_reports,
    }


def task_to_dict(task: Task) -> dict[str, Any]:
    """将任务模型转换为接口响应字典。"""
    return {
        "id": task.id,
        "task_type": task.task_type,
        "target": task.target,
        "status": task.status,
        "packet_count": task.packet_count,
        "http_count": task.http_count,
        "alert_count": task.alert_count,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
    }


def report_to_dict(report: Report) -> dict[str, Any]:
    """将报告模型转换为接口响应字典，并解析 JSON 列表字段。"""
    return {
        "id": report.id,
        "task_id": report.task_id,
        "status": report.status,
        "model": report.model,
        "prompt_version": report.prompt_version,
        "summary": report.summary,
        "risk_assessment": report.risk_assessment,
        "key_findings": _json_loads_list(report.key_findings),
        "recommendations": _json_loads_list(report.recommendations),
        "error_message": report.error_message,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }


def _json_loads_list(value: str) -> list[Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """将告警模型转换为接口响应字典，并解析 matched_rules JSON 字段。"""
    try:
        matched_rules = json.loads(alert.matched_rules)
    except json.JSONDecodeError:
        matched_rules = alert.matched_rules

    return {
        "id": alert.id,
        "task_id": alert.task_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "method": alert.method,
        "path": alert.path,
        "query": alert.query,
        "attack_type": alert.attack_type,
        "risk_level": alert.risk_level,
        "score": alert.score,
        "matched_rules": matched_rules,
        "ai_judgement": alert.ai_judgement,
        "ai_reason": alert.ai_reason,
        "reason": alert.reason,
        "status": alert.status,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    }
