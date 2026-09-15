import unittest

from security.analyzer.detectors.sqli import SqliDetector
from security.analyzer.detectors.xss import XssDetector
from security.analyzer.detectors.path_traversal import PathTraversalDetector
from security.analyzer.detectors.request_flood import RequestFloodDetector
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.analyzer.scoring import RiskScorer
from security.configuration import load_settings
from security.response.base import AddressPolicy
from security.tests.helpers import event, line


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings()

    def test_sqli(self):
        detector = SqliDetector(self.settings)
        for uri in ("/?q=1+UNION+SELECT+name", "/?id=%27+OR+1%3D1--", "/?q=;DROP TABLE users", "/?q=sleep(5)"):
            with self.subTest(uri=uri):
                self.assertTrue(detector.detect(event(uri)))

    def test_xss(self):
        detector = XssDetector(self.settings)
        for uri in ("/?q=%3Cscript%3Ealert(1)", "/?q=<img src=x onerror=alert(1)>", "/?q=<a href=javascript:alert(1)>"):
            with self.subTest(uri=uri):
                self.assertTrue(detector.detect(event(uri)))

    def test_traversal_encoded(self):
        detector = PathTraversalDetector(self.settings)
        for uri in ("/../../etc/passwd", "/%2e%2e%2fetc/passwd", "/%252e%252e%252fetc/passwd",
                    "/?file=..%5c..%5cwindows", "/?file=../../private", "//../secret"):
            with self.subTest(uri=uri):
                self.assertTrue(detector.detect(event(uri)))

    def test_benign_requests(self):
        for cls in (SqliDetector, XssDetector, PathTraversalDetector):
            for uri in ("/products?q=union+jack", "/search?q=O%27Reilly", "/?q=select+a+book",
                        "/docs/javascript", "/?q=1%3C2", "/images/file..png", "/login", "/?q=drop+shipping"):
                with self.subTest(detector=cls.__name__, uri=uri):
                    self.assertEqual(cls(self.settings).detect(event(uri)), [])

    def test_rule_disabled(self):
        self.settings.rules["rules"]["sqli"]["enabled"] = False
        self.assertEqual(SqliDetector(self.settings).detect(event("/?q=union select")), [])

    def test_one_score_per_attack_type(self):
        self.assertEqual(len(SqliDetector(self.settings).detect(event("/?q=union select sleep(5)"))), 1)

    def test_scoring_levels_and_multiple_signals(self):
        request = event("/?q=<script> UNION SELECT password")
        detections = SqliDetector(self.settings).detect(request) + XssDetector(self.settings).detect(request)
        scorer = RiskScorer(self.settings)
        self.assertEqual(scorer.score(request, []).action, "observe")
        self.assertEqual(scorer.score(request, detections[:1]).action, "alert")
        result = scorer.score(request, detections)
        self.assertEqual((result.action, result.score, result.block_duration_seconds), ("temporary_block", 100, 300))

    def test_configurable_scoring_boundary(self):
        self.settings.thresholds["block_score"] = 50
        request = event("/?q=union select")
        self.assertEqual(RiskScorer(self.settings).score(request, SqliDetector(self.settings).detect(request)).action,
                         "temporary_block")


class FloodTests(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings()
        self.settings.thresholds["flood"]["request_threshold"] = 3
        self.detector = RequestFloodDetector(self.settings)

    def test_threshold_inclusive(self):
        self.assertFalse(self.detector.detect(event(seconds=0)))
        self.assertFalse(self.detector.detect(event(seconds=1)))
        self.assertTrue(self.detector.detect(event(seconds=2)))

    def test_window_left_boundary_excluded(self):
        self.detector.detect(event(seconds=0))
        self.detector.detect(event(seconds=1))
        self.assertFalse(self.detector.detect(event(seconds=10)))
        self.assertTrue(self.detector.detect(event(seconds=10)))

    def test_sources_separate(self):
        self.detector.detect(event())
        self.detector.detect(event())
        self.assertFalse(self.detector.detect(event(remote_addr="203.0.113.1")))

    def test_bounded_state(self):
        self.settings.thresholds["flood"]["max_sources"] = 2
        for address in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
            self.detector.detect(event(remote_addr=address))
        self.assertEqual(len(self.detector.windows), 2)
        self.assertEqual(self.detector.evictions, 1)
        for _ in range(100):
            self.detector.detect(event(remote_addr="203.0.113.3"))
        self.assertEqual(len(self.detector.windows["203.0.113.3"]), 3)

    def test_disabled(self):
        self.settings.thresholds["flood"]["enabled"] = False
        for _ in range(10):
            self.assertFalse(self.detector.detect(event()))

    def test_only_headerless_exact_health_from_trusted_peer_is_excluded(self):
        parser = NginxJsonParser(AddressPolicy(trusted_proxies=["10.0.0.0/24"]))
        health = parser.parse(line("/healthz", remote_addr="10.0.0.4"))
        self.assertTrue(self.detector.excludes_trusted_health_check(health))
        for _ in range(5):
            self.assertEqual(self.detector.detect(health), [])
        self.assertEqual(self.detector.windows, {})

        included = (
            parser.parse(line("/healthz", remote_addr="10.0.0.4",
                              http_x_forwarded_for="203.0.113.8")),
            parser.parse(line("/healthz?probe=1", remote_addr="10.0.0.4")),
            parser.parse(line("/healthz", remote_addr="10.0.0.4", request_method="POST")),
            NginxJsonParser(AddressPolicy()).parse(line("/healthz")),
        )
        for request in included:
            with self.subTest(request=request):
                detector = RequestFloodDetector(self.settings)
                self.assertFalse(detector.excludes_trusted_health_check(request))
                detector.detect(request)
                detector.detect(request)
                self.assertTrue(detector.detect(request))
