import unittest

from security.analyzer.parsers import ParseError
from security.analyzer.parsers.nginx_json import NginxJsonParser
from security.response.base import AddressPolicy
from security.tests.helpers import line


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = NginxJsonParser(AddressPolicy(trusted_proxies=["10.0.0.0/24"]))

    def test_normalization(self):
        result = self.parser.parse(line("/shop?q=book", status="201"), "test_stream")
        self.assertEqual((result.path, result.query_string, result.status_code), ("/shop", "q=book", 201))
        self.assertEqual(result.log_source, "test_stream")
        self.assertEqual(result.request_id, "lab-1")
        self.assertIsNotNone(result.timestamp.tzinfo)

    def test_timezone_normalized(self):
        result = self.parser.parse(line(time_iso8601="2026-01-01T07:00:00+07:00"))
        self.assertEqual(result.timestamp.hour, 0)

    def test_untrusted_forwarded_header_ignored(self):
        result = self.parser.parse(line(http_x_forwarded_for="127.0.0.1; bad"))
        self.assertEqual(result.source_ip, "198.51.100.23")
        self.assertFalse(result.via_trusted_proxy)

    def test_right_to_left_trust_chain(self):
        result = self.parser.parse(line(remote_addr="10.0.0.4",
                                        http_x_forwarded_for="127.0.0.1, 203.0.113.9, 10.0.0.5"))
        self.assertEqual(result.source_ip, "203.0.113.9")
        self.assertEqual(result.peer_ip, "10.0.0.4")
        self.assertTrue(result.via_trusted_proxy)

    def test_trusted_without_header_keeps_peer(self):
        self.assertEqual(self.parser.parse(line(remote_addr="10.0.0.4")).source_ip, "10.0.0.4")

    def test_ipv6(self):
        self.assertEqual(self.parser.parse(line(remote_addr="2001:db8::1")).source_ip, "2001:db8::1")

    def test_malformed_inputs(self):
        bad = ["{", "[]", "null", "{}", "[" * 2000,
               line(status=True), line(status=200.1), line(status=999),
               line(request_method=7), line(request_method="GET\n"),
               line(time_iso8601="2026-01-01T00:00:00"), line(time_iso8601="secret-invalid"),
               line(remote_addr="1.2.3.4; whoami"), line(remote_addr="fe80::1%eth0"),
               line(request_uri="http://example.test/"), line(request_uri="/\n"),
               line(http_user_agent=None), line(request_id=[]),
               line(remote_addr="10.0.0.4", http_x_forwarded_for="203.0.113.8:1234")]
        for value in bad:
            with self.subTest(value=value[:60]), self.assertRaises(ParseError) as error:
                self.parser.parse(value)
            self.assertNotIn("secret", str(error.exception))

    def test_limits(self):
        with self.assertRaises(ParseError):
            NginxJsonParser(AddressPolicy(), max_line_bytes=10).parse(line())
        with self.assertRaises(ParseError):
            self.parser.parse(line(request_uri="/" + "a" * 9000))

    def test_preserve_double_slashes(self):
        self.assertEqual(self.parser.parse(line("//../secret")).path, "//../secret")
