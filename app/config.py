from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "ids.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

# 规则库目录：rule_engine 从这里加载所有 *.json 规则文件
RULES_DIR = BASE_DIR / "rules"

DEFAULT_RISK_THRESHOLDS = {
    "low": 20,
    "medium": 40,
    "high": 70,
    "critical": 90,
}

# WebUI 面板可修改的运行配置，保存在 settings 表中，缺省时取这里的值
DEFAULT_SETTINGS = {
    "server.port": 8000,
    "llm.base_url": "",
    "llm.api_key": "",
    "llm.model": "",
    "llm.temperature": 0.2,
}
