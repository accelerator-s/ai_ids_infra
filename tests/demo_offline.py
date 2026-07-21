"""真·离线分析演示：读 pcap → tshark/pyshark 解析 → 规则+行为检测 → 打印告警。

    venv/Scripts/python.exe tests/demo_offline.py

用内存库，不改 data/ids.db。未配置 LLM 时，评分模糊(20-69)的请求走 manual_review、不出告警；
配好大模型后把 settings 换成 crud.get_settings(db) 即可让 AI 研判真正参与。
"""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import RULES_DIR
from app.capture.pcap_analyzer import PcapAnalyzer
from app.database import crud, models  # noqa: F401  注册数据表
from app.database.db import Base
from app.detection.rule_engine import RuleEngine
from app.protocol.packet_parser import parse_http_request

NO_LLM = {"llm.base_url": "", "llm.api_key": "", "llm.model": "", "llm.temperature": 0.2}


def main() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    rules = RuleEngine.from_dir(RULES_DIR)

    for pcap in sorted(Path("tests/pcaps").glob("*.pcap")):
        analyzer = PcapAnalyzer(db=db, packet_parser=parse_http_request,
                                rule_engine=rules, settings=NO_LLM)
        result = analyzer.analyze(pcap)
        print(f"\n[{pcap.name}] {result.status}  "
              f"packets={result.packet_count} http={result.http_count} alerts={result.alert_count}"
              + (f"  error={result.error}" if result.error else ""))
        for alert in crud.list_alerts(db, task_id=result.task_id):
            print(f"    - {alert.attack_type} ({alert.risk_level}, {alert.score}) "
                  f"src={alert.src_ip} {alert.method} {alert.path}")


if __name__ == "__main__":
    main()
