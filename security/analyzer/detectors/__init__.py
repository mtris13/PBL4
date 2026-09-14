from typing import Protocol

from security.analyzer.models import Detection, Event


class Detector(Protocol):
    def detect(self, event: Event) -> list[Detection]: ...
