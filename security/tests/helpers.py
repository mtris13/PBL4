import json
from dataclasses import replace
from datetime import datetime, timezone, timedelta

from security.analyzer.models import Decision
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.configuration import load_settings


START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def line(uri="/products?page=1", seconds=0, **fields):
    data = {"time_iso8601": (START + timedelta(seconds=seconds)).isoformat(),
            "remote_addr": "198.51.100.23", "request_method": "GET", "request_uri": uri,
            "status": 200, "http_user_agent": "Lab browser", "request_id": "lab-1"}
    data.update(fields)
    return json.dumps(data)


def event(uri="/", seconds=0, **fields):
    return NginxJsonParser(load_settings().policy).parse(line(uri, seconds, **fields))


def block(address="198.51.100.23", **changes):
    return replace(Decision(address, 100, "temporary_block", 300, START,
                            ("sqli", "xss")), **changes)
