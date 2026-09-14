from typing import Protocol

from security.analyzer.models import Event


class ParseError(ValueError):
    """Constant error codes only; never expose raw input in audit."""


class Parser(Protocol):
    def parse(self, line: str, log_source: str = "nginx_json") -> Event: ...
