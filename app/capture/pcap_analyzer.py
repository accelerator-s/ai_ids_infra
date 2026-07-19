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

from app.ai import request_analyzer
from app.database import crud
from app.detection.behavior_detector import BehaviorDetector
from app.detection.risk_score import calculate_risk
from app.detection.rule_engine import RuleEngine
from app.protocol.packet_parser import get_tcp_stream_id, parse_http_response_status


PacketParser = Callable[[Any], dict[str, Any] | None]
AiAnalyzer = Callable[[dict[str, Any], Any, dict[str, Any]], request_analyzer.AnalysisResult]
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
        ai_analyzer: AiAnalyzer = request_analyzer.analyze,
        settings: dict[str, Any] | None = None,
    ) -> None:
        self.db = db
        self.packet_parser = packet_parser
        self.rule_engine = rule_engine
        self.ai_analyzer = ai_analyzer
        self.settings = settings if settings is not None else crud.get_settings(db)

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

                # 规则检测完成后，将所有请求整体喂入行为检测
                alert_count += self._detect_behavior(task.id, requests)

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
        """该函数的作用为: 对单条请求执行规则检测，评分后写入告警表。

        参数: task_id - 所属任务ID
             request - 结构化 HTTP 请求字典
        """
        matches = self.rule_engine.match(request)
        risk = calculate_risk(matches)
        if risk.level == "normal":
            return 0

        if risk.need_ai_filter:
            return self._review_ambiguous_request(task_id, request, risk)

        return int(self._create_rule_alert(task_id, request, risk) is not None)

    def _review_ambiguous_request(self, task_id: int, request: dict[str, Any], risk: Any) -> int:
        """AI 判恶意才告警；正常和调用失败均保留独立研判记录。"""
        matched_rules = [match.rule_id for match in risk.matches]
        summary = request_analyzer.request_summary(request)
        try:
            result = self.ai_analyzer(request, risk, self.settings)
        except Exception as exc:
            logger.warning("AI review failed for task %s: %s", task_id, exc)
            crud.create_ai_review(
                self.db,
                task_id=task_id,
                request_summary=summary,
                original_score=risk.score,
                matched_rules=matched_rules,
                judgement="manual_review",
                attack_type=self._attack_types(risk),
                reason=str(exc),
                status="pending_review",
                model=str(self.settings.get("llm.model", "")),
                prompt_version=request_analyzer.PROMPT_VERSION,
            )
            return 0

        alert = None
        if result.ai_judgement == "malicious":
            alert = self._create_rule_alert(
                task_id,
                request,
                risk,
                attack_type=result.attack_type,
                ai_judgement=result.ai_judgement,
                ai_confidence=result.confidence,
                ai_reason=result.reason,
            )

        crud.create_ai_review(
            self.db,
            task_id=task_id,
            alert_id=alert.id if alert is not None else None,
            request_summary=summary,
            original_score=risk.score,
            matched_rules=matched_rules,
            judgement=result.ai_judgement,
            attack_type=result.attack_type,
            confidence=result.confidence,
            reason=result.reason,
            status="completed",
            model=result.model,
            prompt_version=result.prompt_version,
        )
        return int(alert is not None)

    def _create_rule_alert(
        self,
        task_id: int,
        request: dict[str, Any],
        risk: Any,
        *,
        attack_type: str | None = None,
        ai_judgement: str = "",
        ai_confidence: float | None = None,
        ai_reason: str = "",
    ) -> Any:
        """把规则评分结果及可选 AI 结论写入告警表。"""
        matched_rules = [match.rule_id for match in risk.matches]
        reasons = [match.reason for match in risk.matches]
        return crud.create_alert(
            self.db,
            task_id=task_id,
            src_ip=str(request.get("src_ip", "")),
            dst_ip=str(request.get("dst_ip", "")),
            src_port=request.get("src_port"),
            dst_port=request.get("dst_port"),
            method=str(request.get("method", "")),
            path=str(request.get("path", "")),
            query=str(request.get("query", "")),
            attack_type=attack_type or self._attack_types(risk),
            risk_level=risk.level,
            score=risk.score,
            matched_rules=matched_rules,
            ai_judgement=ai_judgement,
            ai_confidence=ai_confidence,
            ai_reason=ai_reason,
            reason="；".join(reasons),
        )

    @staticmethod
    def _attack_types(risk: Any) -> str:
        return ", ".join(sorted({match.attack_type for match in risk.matches})) or "Unknown"

    def _detect_behavior(self, task_id: int, requests: list[dict[str, Any]]) -> int:
        """该函数的作用为: 对所有请求整体执行行为检测，将超过阈值的行为告警写入告警表。

        参数: task_id  - 所属任务ID
             requests - 本次任务解析出的全部 HTTP 请求列表
        """
        detector = BehaviorDetector()
        behavior_matches = detector.detect(requests)
        count = 0
        for match in behavior_matches:
            alert = crud.create_alert(
                self.db,
                task_id=task_id,
                src_ip=match.src_ip,
                attack_type=match.attack_type,
                risk_level=match.level,
                score=match.score,
                matched_rules=[],
                reason=match.reason,
            )
            if alert is not None:
                count += 1
        return count
