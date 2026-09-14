from security.analyzer.detectors.sqli import SqliDetector
from security.analyzer.detectors.xss import XssDetector
from security.analyzer.detectors.path_traversal import PathTraversalDetector
from security.analyzer.detectors.request_flood import RequestFloodDetector
from security.analyzer.parsers import ParseError
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.analyzer.scoring import RiskScorer
from security.response.dry_run import DryRunAdapter


class Engine:
    def __init__(self, settings, adapter=None, parser=None):
        self.parser = parser or NginxJsonParser(settings.policy, settings.thresholds["max_line_bytes"],
                                                settings.thresholds["max_field_chars"])
        self.adapter = adapter or DryRunAdapter(settings.policy)
        self.flood = RequestFloodDetector(settings)
        self.detectors = [SqliDetector(settings), XssDetector(settings),
                          PathTraversalDetector(settings), self.flood]
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
        if self.flood.evictions > evictions:
            records.append({"kind": "capacity_warning", "reason": "flood_source_evicted"})
        records.extend({"kind": "detection", "detection": item} for item in detections)
        decision = self.scorer.score(event, detections)
        records.append({"kind": "decision", "decision": decision, "line_number": line_number})
        records.append({"kind": "response", "response": self.adapter.respond(decision)})
        return records
