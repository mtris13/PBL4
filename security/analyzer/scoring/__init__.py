from security.analyzer.models import Decision


class RiskScorer:
    def __init__(self, settings):
        self.config = settings.thresholds

    def score(self, event, detections):
        total = sum(item.score for item in detections)
        action = "observe"
        if total >= self.config["block_score"]:
            action = "temporary_block"
        elif total >= self.config["alert_score"]:
            action = "alert"
        return Decision(event.source_ip, total, action,
                        self.config["block_duration_seconds"] if action == "temporary_block" else 0,
                        event.timestamp, tuple(item.attack_type for item in detections),
                        event.via_trusted_proxy)
