"""Bounded readiness check for the local Nginx edge; no account data."""
import json
import time
from urllib.request import ProxyHandler, build_opener

opener = build_opener(ProxyHandler({}))
for attempt in range(10):
    try:
        with opener.open("http://127.0.0.1:8080/api/v1/health", timeout=2) as response:
            if response.status == 200 and json.load(response).get("status") == "ok":
                print("OK: Nginx -> Flask -> SQLite")
                break
    except (OSError, ValueError):
        pass
    time.sleep(1)
else:
    raise SystemExit("Server not ready. Run: bash scripts/server.sh logs")
