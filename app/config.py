from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "ids.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

DEFAULT_RISK_THRESHOLDS = {
    "low": 20,
    "medium": 40,
    "high": 70,
    "critical": 90,
}
