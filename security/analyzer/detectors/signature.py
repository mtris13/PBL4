import html
import re
from urllib.parse import unquote_plus

from security.analyzer.models import Detection


class SignatureDetector:
    attack_type = ""

    def __init__(self, settings):
        self.rule = settings.rules["rules"][self.attack_type]
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.rule["patterns"]]
        self.decode_passes = settings.rules["decode_passes"]
        self.duration = settings.thresholds["block_duration_seconds"]

    def detect(self, event):
        if not self.rule["enabled"]:
            return []
        values = [event.path, event.query_string]
        variants = list(values)
        for _ in range(self.decode_passes):
            values = [html.unescape(unquote_plus(value)) for value in values]
            variants.extend(values)
        for index, pattern in enumerate(self.patterns, start=1):
            if any(pattern.search(value) for value in variants):
                # Evidence contains a fixed rule number, never matched text or URL.
                return [Detection(self.attack_type, self.rule["score"], event.source_ip,
                                  f"signature_{index}_matched_in_request_target", self.attack_type,
                                  "alert", self.duration, event.timestamp)]
        return []
