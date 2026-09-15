from collections import OrderedDict, deque
from datetime import timedelta

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
