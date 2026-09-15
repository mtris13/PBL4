import json
from datetime import datetime, timezone

from security.analyzer.models import Event
from security.analyzer.parsers import ParseError
from security.response.base import AddressPolicy, validated_ip


class NginxJsonParser:
    def __init__(self, policy: AddressPolicy, max_line_bytes=65536, max_field_chars=8192):
        self.policy = policy
        self.max_line_bytes = max_line_bytes
        self.max_field_chars = max_field_chars

    def parse(self, line: str, log_source: str = "nginx_json") -> Event:
        try:
            if len(line.encode("utf-8")) > self.max_line_bytes:
                raise ParseError("line_too_large")
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ParseError("invalid_object")
            def field(name, default=None):
                value = data.get(name, default)
                if not isinstance(value, str) or len(value) > self.max_field_chars:
                    raise ParseError("invalid_field")
                return value
            timestamp = datetime.fromisoformat(field("time_iso8601").replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ParseError("timezone_required")
            peer = validated_ip(field("remote_addr"))
            source = peer
            trusted = self.policy.is_trusted(peer)
            forwarded_present = False
            if trusted:
                forwarded = field("http_x_forwarded_for", "")
                if forwarded and forwarded != "-":
                    forwarded_present = True
                    chain = [validated_ip(part.strip()) for part in forwarded.split(",")]
                    # Rightmost non-trusted hop; never blindly trust the leftmost value.
                    for address in reversed(chain):
                        source = address
                        if not self.policy.is_trusted(address):
                            break
            method = field("request_method")
            if not method.isascii() or not method.isalpha() or not method.isupper():
                raise ParseError("invalid_method")
            uri = field("request_uri")
            if not uri.startswith("/") or any(ord(c) < 32 for c in uri):
                raise ParseError("invalid_uri")
            # Origin-form: preserve leading // and encoded traversal for detectors.
            path, _, query = uri.partition("?")
            status_raw = data.get("status")
            if type(status_raw) not in (str, int):
                raise ParseError("invalid_status")
            status = int(status_raw)
            if not 100 <= status <= 599:
                raise ParseError("invalid_status")
            request_id = field("request_id", "") or None
            return Event(timestamp.astimezone(timezone.utc), source, method, path, query,
                         status, field("http_user_agent", ""), request_id, log_source, peer,
                         trusted, forwarded_present)
        except ParseError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise ParseError("malformed_log") from None
