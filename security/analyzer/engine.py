from datetime import datetime, timezone

from security.analyzer.detectors.sqli import SqliDetector
from security.analyzer.detectors.xss import XssDetector
from security.analyzer.detectors.path_traversal import PathTraversalDetector
from security.analyzer.detectors.request_flood import RequestFloodDetector
from security.analyzer.parsers import ParseError
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.analyzer.scoring import RiskScorer
from security.response.dry_run import DryRunAdapter


class Engine:
    STATE_VERSION = 2

    def __init__(self, settings, adapter=None, parser=None):
        self.parser = parser or NginxJsonParser(settings.policy, settings.thresholds["max_line_bytes"],
                                                settings.thresholds["max_field_chars"])
        self.adapter = adapter or DryRunAdapter(settings.policy, settings.thresholds["max_active_leases"])
        self.state_configuration = {
            "trusted_proxies": sorted({str(network) for network in settings.policy.trusted}),
            "protected_networks": sorted({str(network) for network in settings.policy.protected}),
            "adapter": self.adapter.name,
            "max_active_leases": getattr(self.adapter, "max_active_leases", None),
        }
        self.state_upgraded = False
        self.flood = RequestFloodDetector(settings)
        self.detectors = [SqliDetector(settings), XssDetector(settings),
                          PathTraversalDetector(settings)]
        self.scorer = RiskScorer(settings)
        self.watermark = None

    def process(self, line, line_number=None):
        try:
            event = self.parser.parse(line)
        except ParseError as error:
            return [{"kind": "parse_error", "line_number": line_number, "reason": str(error)}]
        if self.watermark is not None and event.timestamp < self.watermark:
            return [{"kind": "rejected_event", "line_number": line_number,
                     "reason": "out_of_order_timestamp"}]
        self.watermark = event.timestamp
        records = [{"kind": "response", "response": r} for r in self.adapter.expire(event.timestamp)]
        evictions = self.flood.evictions
        detections = [item for detector in self.detectors for item in detector.detect(event)]
        if self.flood.excludes_trusted_health_check(event):
            records.append({"kind": "policy_skip", "policy": "trusted_health_check",
                            "scope": "request_flood", "line_number": line_number})
        else:
            detections.extend(self.flood.detect(event))
        if self.flood.evictions > evictions:
            records.append({"kind": "capacity_warning", "reason": "flood_source_evicted"})
        records.extend({"kind": "detection", "detection": item} for item in detections)
        decision = self.scorer.score(event, detections)
        records.append({"kind": "decision", "decision": decision, "line_number": line_number})
        records.append({"kind": "response", "response": self.adapter.respond(decision)})
        return records

    def export_state(self):
        if not hasattr(self.adapter, "export_state"):
            raise ValueError("Adapter does not support persistent state")
        return {"version": self.STATE_VERSION, "configuration": self.state_configuration,
                "watermark": self.watermark.isoformat() if self.watermark else None,
                "flood": self.flood.export_state(), "adapter": self.adapter.export_state()}

    def restore_state(self, payload):
        if (not isinstance(payload, dict) or type(payload.get("version")) is not int
                or payload["version"] not in (1, self.STATE_VERSION)):
            raise ValueError("Invalid engine state")
        if payload["version"] == self.STATE_VERSION:
            if payload.get("configuration") != self.state_configuration:
                raise ValueError("Engine state configuration mismatch")
        else:
            self.state_upgraded = True
        watermark_value = payload.get("watermark")
        if watermark_value is None:
            watermark = None
        elif isinstance(watermark_value, str):
            try:
                watermark = datetime.fromisoformat(watermark_value)
            except ValueError:
                raise ValueError("Invalid engine state") from None
            if watermark.tzinfo is None:
                raise ValueError("Invalid engine state")
            watermark = watermark.astimezone(timezone.utc)
        else:
            raise ValueError("Invalid engine state")
        self.flood.restore_state(payload.get("flood"), watermark)
        if not hasattr(self.adapter, "restore_state"):
            raise ValueError("Adapter does not support persistent state")
        self.adapter.restore_state(payload.get("adapter"))
        leases = getattr(self.adapter, "leases", {})
        if ((watermark is None and leases)
                or (watermark is not None and any(expires <= watermark for expires in leases.values()))):
            raise ValueError("Invalid engine state")
        self.watermark = watermark

    def reset_state(self):
        self.flood.windows.clear()
        self.flood.evictions = 0
        self.adapter.leases.clear()
        self.watermark = None

    def reconcile(self, now):
        if now.tzinfo is None:
            raise ValueError("Reconciliation time must include timezone")
        now = now.astimezone(timezone.utc)
        records = [{"kind": "response", "response": response}
                   for response in self.adapter.expire(now)]
        expired_sources = self.flood.expire(now)
        if expired_sources:
            records.append({"kind": "state_reconciled",
                            "expired_flood_sources": expired_sources})
        return records
