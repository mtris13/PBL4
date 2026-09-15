from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone

from security.response.base import validated_ip

from security.analyzer.models import Detection


class RequestFloodDetector:
    """Event-time window (t-window, t], threshold inclusive, bounded memory.

    Out-of-order events are rejected by Engine before any detector runs.
    LRU eviction under max_sources pressure can undercount; reported in audit.
    """
    def __init__(self, settings):
        self.config = settings.thresholds["flood"]
        self.health = settings.thresholds["trusted_health_check"]
        self.duration = settings.thresholds["block_duration_seconds"]
        self.windows = OrderedDict()
        self.evictions = 0

    def excludes_trusted_health_check(self, event):
        return (self.config["enabled"] and self.health["exclude_from_flood"]
                and event.via_trusted_proxy and not event.forwarded_for_present
                and event.method == self.health["method"] and event.path == self.health["path"]
                and not event.query_string)

    def detect(self, event):
        if not self.config["enabled"] or self.excludes_trusted_health_check(event):
            return []
        cutoff = event.timestamp - timedelta(seconds=self.config["window_seconds"])
        while self.windows and next(iter(self.windows.values()))[-1] <= cutoff:
            self.windows.popitem(last=False)
        window = self.windows.pop(event.source_ip, deque(maxlen=self.config["request_threshold"]))
        while window and window[0] <= cutoff:
            window.popleft()
        window.append(event.timestamp)
        if len(self.windows) >= self.config["max_sources"]:
            self.windows.popitem(last=False)
            self.evictions += 1
        self.windows[event.source_ip] = window
        if len(window) < self.config["request_threshold"]:
            return []
        return [Detection("request_flood", self.config["score"], event.source_ip,
                          "request_count_reached_configured_window_threshold", "request_flood",
                          "temporary_block", self.duration, event.timestamp)]

    def expire(self, now):
        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        removed = 0
        for address, window in list(self.windows.items()):
            while window and window[0] <= cutoff:
                window.popleft()
            if not window:
                del self.windows[address]
                removed += 1
        return removed

    def export_state(self):
        return {
            "version": 1,
            "configuration": {
                "enabled": self.config["enabled"],
                "window_seconds": self.config["window_seconds"],
                "request_threshold": self.config["request_threshold"],
                "max_sources": self.config["max_sources"],
            },
            "evictions": self.evictions,
            "windows": [[address, [timestamp.isoformat() for timestamp in window]]
                        for address, window in self.windows.items()],
        }

    def restore_state(self, payload, watermark):
        expected = {
            "enabled": self.config["enabled"],
            "window_seconds": self.config["window_seconds"],
            "request_threshold": self.config["request_threshold"],
            "max_sources": self.config["max_sources"],
        }
        if (not isinstance(payload, dict) or type(payload.get("version")) is not int
                or payload["version"] != 1
                or payload.get("configuration") != expected
                or type(payload.get("evictions")) is not int or payload["evictions"] < 0):
            raise ValueError("Invalid flood state")
        windows = payload.get("windows")
        if not isinstance(windows, list) or len(windows) > self.config["max_sources"]:
            raise ValueError("Invalid flood state")
        restored = OrderedDict()
        for item in windows:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("Invalid flood state")
            address = validated_ip(item[0])
            values = item[1]
            if (address in restored or not isinstance(values, list) or not values
                    or len(values) > self.config["request_threshold"]):
                raise ValueError("Invalid flood state")
            timestamps = []
            for value in values:
                if not isinstance(value, str):
                    raise ValueError("Invalid flood state")
                try:
                    timestamp = datetime.fromisoformat(value)
                except ValueError:
                    raise ValueError("Invalid flood state") from None
                if timestamp.tzinfo is None:
                    raise ValueError("Invalid flood state")
                timestamps.append(timestamp.astimezone(timezone.utc))
            if timestamps != sorted(timestamps) or watermark is None or timestamps[-1] > watermark:
                raise ValueError("Invalid flood state")
            restored[address] = deque(timestamps, maxlen=self.config["request_threshold"])
        self.windows = restored
        self.evictions = payload["evictions"]
