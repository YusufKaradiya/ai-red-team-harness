
import os

API_BASE_URL = os.getenv(
    "REDTEAM_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

REQUEST_TIMEOUT = 20
MAX_SCENARIOS_PER_CAMPAIGN = 100
