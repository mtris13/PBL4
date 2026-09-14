from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source_ip: str
    method: str
    path: str
    query_string: str
    status_code: int
    user_agent: str
    request_id: str | None
    log_source: str
    peer_ip: str
    via_trusted_proxy: bool = False


@dataclass(frozen=True)
class Detection:
    attack_type: str
    score: int
    source_ip: str
    evidence: str
    detector_name: str
    recommended_action: str
    block_duration_seconds: int
    timestamp: datetime


@dataclass(frozen=True)
class Decision:
    source_ip: str
    score: int
    action: str
    block_duration_seconds: int
    timestamp: datetime
    reasons: tuple[str, ...]
    via_trusted_proxy: bool = False
