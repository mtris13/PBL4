"""Structured audit; intentionally excludes request target, headers and IDs."""

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime


def _encode(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError("Unsupported audit value")


def write_record(stream, record):
    stream.write(json.dumps(record, default=_encode, ensure_ascii=True) + "\n")
