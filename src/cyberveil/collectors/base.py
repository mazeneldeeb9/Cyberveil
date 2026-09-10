from __future__ import annotations

from typing import Protocol

from cyberveil.domain import CapabilityReport, TelemetrySample


class TelemetryCollector(Protocol):
    @property
    def capabilities(self) -> CapabilityReport: ...

    def collect(self, session_id: str) -> list[TelemetrySample]: ...
