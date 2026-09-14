"""Target-side access logging for local tests; Nginx owns this role on Linux."""

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qsl, urlencode
from uuid import uuid4


def redact_target(target):
    """Only public search/category values survive. No body, cookie or auth header."""
    path, separator, query = target.partition("?")
    if not separator:
        return path
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=100)
    # Drop unknown names too: parameter names themselves could contain secrets.
    safe = [(key, value) for key, value in pairs if key in {"q", "category"}]
    return path + ("?" + urlencode(safe) if safe else "")


class AccessLogMiddleware:
    def __init__(self, app, path):
        self.app = app
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()

    def __call__(self, environ, start_response):
        status_code = 500
        request_id = uuid4().hex

        def capture(status, headers, exc_info=None):
            nonlocal status_code
            status_code = int(status.split(" ", 1)[0])
            return start_response(status, headers + [("X-Request-ID", request_id)], exc_info)

        try:
            result = self.app(environ, capture)
            try:
                yield from result
            finally:
                if hasattr(result, "close"):
                    result.close()
        finally:
            target = environ.get("REQUEST_URI")
            if target is None:
                target = environ.get("PATH_INFO", "/")
                if environ.get("QUERY_STRING"):
                    target += "?" + environ["QUERY_STRING"]
            try:
                target = redact_target(target)
            except ValueError:
                target = "/[query-rejected]"
            record = {
                "remote_addr": environ.get("REMOTE_ADDR", ""),
                "request_method": environ.get("REQUEST_METHOD", ""),
                "request_uri": target,
                "status": status_code,
                "http_user_agent": "",  # Avoid retaining arbitrary user-controlled headers.
                "request_id": request_id,
                "http_x_forwarded_for": environ.get("HTTP_X_FORWARDED_FOR", ""),
            }
            # Assign completion time under the write lock so the stream is ordered.
            with self.lock:
                record["time_iso8601"] = datetime.now(timezone.utc).isoformat()
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=True) + "\n")
