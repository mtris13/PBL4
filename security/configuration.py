"""Config is JSON syntax, a YAML 1.2 subset; no third-party loader needed."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from security.response.base import AddressPolicy


@dataclass(frozen=True)
class Settings:
    rules: dict
    thresholds: dict
    policy: AddressPolicy


def _positive(value, name):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def load_settings(directory: Path | None = None) -> Settings:
    directory = directory or Path(__file__).parent / "config"
    def read(name):
        with (directory / name).open(encoding="utf-8") as stream:
            return json.load(stream)
    rules = read("detection-rules.yaml")
    thresholds = read("thresholds.yaml")
    allow = read("allowlist.yaml")
    for key in ("alert_score", "block_score", "block_duration_seconds", "max_line_bytes", "max_field_chars"):
        _positive(thresholds[key], key)
    if thresholds["alert_score"] > thresholds["block_score"]:
        raise ValueError("alert_score must be <= block_score")
    for key in ("window_seconds", "request_threshold", "score", "max_sources"):
        _positive(thresholds["flood"][key], key)
    if type(thresholds["flood"]["enabled"]) is not bool:
        raise ValueError("flood.enabled must be boolean")
    if type(rules["decode_passes"]) is not int or not 0 <= rules["decode_passes"] <= 4:
        raise ValueError("decode_passes must be between 0 and 4")
    for name in ("sqli", "xss", "path_traversal"):
        rule = rules["rules"][name]
        _positive(rule["score"], name)
        if type(rule["enabled"]) is not bool or not isinstance(rule["patterns"], list) or not rule["patterns"]:
            raise ValueError("Invalid rule configuration")
        for pattern in rule["patterns"]:
            re.compile(pattern, re.IGNORECASE)
    return Settings(rules, thresholds, AddressPolicy(**allow))
