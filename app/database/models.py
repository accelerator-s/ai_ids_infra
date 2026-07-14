from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.db import Base


class Task(Base):
    """分析任务表，记录实时抓包或 pcap 分析任务的执行状态。"""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    task_type: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    http_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(back_populates="task")


class Setting(Base):
    """配置表，保存 WebUI 面板里修改的运行配置，value 存 JSON 编码后的值。"""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class Alert(Base):
    """告警表，保存规则检测、行为检测和 AI 判断后的风险结果。"""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), default="")
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    method: Mapped[str] = mapped_column(String(16), default="")
    path: Mapped[str] = mapped_column(Text, default="")
    query: Mapped[str] = mapped_column(Text, default="")
    attack_type: Mapped[str] = mapped_column(String(64), default="Unknown", index=True)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    matched_rules: Mapped[str] = mapped_column(Text, default="[]")
    ai_judgement: Mapped[str] = mapped_column(String(64), default="")
    ai_reason: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    task: Mapped[Task | None] = relationship(back_populates="alerts")
