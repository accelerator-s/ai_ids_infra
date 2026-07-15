from __future__ import annotations

import logging
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pyshark
from sqlalchemy.orm import Session

from app.database import crud
from app.detection.risk_score import calculate_risk
from app.detection.rule_engine import RuleEngine
from app.protocol.packet_parser import get_tcp_stream_id, parse_http_response_status


PacketParser = Callable[[Any], dict[str, Any] | None]
logger = logging.getLogger(__name__)


@dataclass
class PcapAnalysisResult:
    """pcap 离线分析任务的统计结果。"""

    task_id: int
    status: str
    packet_count: int
    http_count: int
    alert_count: int
    error: str | None = None


class PcapAnalyzer:
    """读取离线 pcap 文件并将 HTTP 请求交给检测模块。"""

    def __init__(
        self,
        db: Session,
        packet_parser: PacketParser,
        rule_engine: RuleEngine,
    ) -> None:
        self.db = db
        self.packet_parser = packet_parser
        self.rule_engine = rule_engine

    def analyze(
        self,
        pcap_path: str | Path,
        task_target: str | None = None,
    ) -> PcapAnalysisResult:
        """分析单个 pcap 文件并返回任务与告警统计。"""
        path = Path(pcap_path)
        # 先创建运行中的任务，确保分析失败时也能保留任务记录。
        task = crud.create_task(
            self.db,
            task_type="pcap",
            target=task_target or path.name,
            status="running",
        )

        packet_count = 0
        http_count = 0
        alert_count = 0
        requests: list[dict[str, Any]] = []
        pending_requests: dict[str, deque[dict[str, Any]]] = defaultdict(deque)

        try:
            if not path.is_file():
                raise FileNotFoundError(f"pcap file not found: {path}")

            # 不保留已读取数据包，避免大文件分析持续占用内存。
            capture = pyshark.FileCapture(str(path), keep_packets=False)

            try:
                for packet in capture:
                    packet_count += 1

                    try:
                        request = self.packet_parser(packet)
                        response_status = parse_http_response_status(packet)
                        stream_id = get_tcp_stream_id(packet)
                    except Exception as exc:
                        logger.warning(
                            "Skipping packet %d after parsing error: %s",
                            packet_count,
                            exc,
                        )
                        continue

                    if request is not None:
                        http_count += 1
                        requests.append(request)
                        if stream_id is not None:
                            pending_requests[stream_id].append(request)
                        continue

                    if response_status is not None and stream_id is not None:
                        waiting = pending_requests.get(stream_id)
                        if waiting:
                            waiting.popleft()["status"] = response_status

                for request in requests:
                    alert_count += self._detect_request(task.id, request)

            finally:
                capture.close()

            # 所有数据包处理完成后写入最终统计与完成时间。
            crud.update_task(
                self.db,
                task.id,
                status="completed",
                packet_count=packet_count,
                http_count=http_count,
                alert_count=alert_count,
                finished_at=datetime.utcnow(),
            )

            return PcapAnalysisResult(
                task_id=task.id,
                status="completed",
                packet_count=packet_count,
                http_count=http_count,
                alert_count=alert_count,
            )

        except Exception as exc:
            # 文件读取或检测链异常时标记失败，并返回已完成的统计。
            crud.update_task(
                self.db,
                task.id,
                status="failed",
                packet_count=packet_count,
                http_count=http_count,
                alert_count=alert_count,
                finished_at=datetime.utcnow(),
            )

            return PcapAnalysisResult(
                task_id=task.id,
                status="failed",
                packet_count=packet_count,
                http_count=http_count,
                alert_count=alert_count,
                error=str(exc),
            )

    def _detect_request(self, task_id: int, request: dict[str, Any]) -> int:
        """将已完成状态关联的请求交给现有规则检测链。"""
        matches = self.rule_engine.match(request)
        risk = calculate_risk(matches)
        if risk.level == "normal":
            return 0

        attack_types = sorted({match.attack_type for match in risk.matches})
        matched_rules = [match.rule_id for match in risk.matches]
        reasons = [match.reason for match in risk.matches]
        alert = crud.create_alert(
            self.db,
            task_id=task_id,
            src_ip=str(request.get("src_ip", "")),
            dst_ip=str(request.get("dst_ip", "")),
            src_port=request.get("src_port"),
            dst_port=request.get("dst_port"),
            method=str(request.get("method", "")),
            path=str(request.get("path", "")),
            query=str(request.get("query", "")),
            attack_type=", ".join(attack_types) or "Unknown",
            risk_level=risk.level,
            score=risk.score,
            matched_rules=matched_rules,
            reason="；".join(reasons),
        )
        return int(alert is not None)
