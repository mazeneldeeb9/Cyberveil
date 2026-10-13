from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from statistics import fmean, pstdev

from cyberveil.domain import FeatureWindow, TelemetrySample


class FeatureExtractor:
    def __init__(self, window_samples: int = 15, min_samples: int = 15) -> None:
        if min_samples < 2 or window_samples < min_samples:
            raise ValueError("window_samples must be >= min_samples >= 2")
        self.window_samples = window_samples
        self.min_samples = min_samples
        self._samples: dict[str, deque[TelemetrySample]] = defaultdict(lambda: deque(maxlen=self.window_samples))

    def ingest(self, sample: TelemetrySample, *, emit: bool = True) -> FeatureWindow | None:
        key = f"{sample.session_id}:{sample.process_key}"
        bucket = self._samples[key]
        if bucket and sample.observed_at <= bucket[-1].observed_at:
            return None
        bucket.append(sample)
        cutoff = sample.observed_at - timedelta(seconds=self.window_samples)
        while bucket and bucket[0].observed_at <= cutoff:
            bucket.popleft()
        if len(bucket) < self.min_samples or not emit:
            return None
        items = list(bucket)
        cpu = [item.cpu_percent for item in items]
        rss_mb = [item.rss_bytes / (1024 * 1024) for item in items]
        threads = [float(item.thread_count) for item in items]
        children = [float(item.child_count) for item in items]
        connections = [float(item.connection_count) for item in items if item.connection_count is not None]
        open_files = [float(item.open_file_count) for item in items if item.open_file_count is not None]
        read_values = [item.read_bytes for item in items if item.read_bytes is not None]
        write_values = [item.write_bytes for item in items if item.write_bytes is not None]
        hint = (items[-1].command_hint or "").lower()
        values = {
            "cpu_mean": fmean(cpu),
            "cpu_max": max(cpu),
            "cpu_std": pstdev(cpu),
            "rss_mean_mb": fmean(rss_mb),
            "rss_max_mb": max(rss_mb),
            "rss_growth_ratio": self._growth_ratio(rss_mb),
            "rss_delta_mb": rss_mb[-1] - rss_mb[0],
            "thread_mean": fmean(threads),
            "thread_max": max(threads),
            "thread_delta": threads[-1] - threads[0],
            "child_max": max(children),
            "child_delta": children[-1] - children[0],
            "connection_mean": fmean(connections) if connections else 0.0,
            "connection_max": max(connections) if connections else 0.0,
            "connection_delta": self._delta(connections),
            "open_file_max": max(open_files) if open_files else 0.0,
            "read_delta_mb": self._counter_delta(read_values),
            "write_delta_mb": self._counter_delta(write_values),
            "encoded_command_hint": float("encoded" in hint or "-enc" in hint),
            "process_age_seconds": max(0.0, items[-1].observed_at.timestamp() - items[-1].process_started_at),
        }
        missing: list[str] = []
        if not connections:
            missing.append("network_connections")
        if not open_files:
            missing.append("open_files")
        if not read_values or not write_values:
            missing.append("io")
        return FeatureWindow(
            session_id=sample.session_id,
            process_key=sample.process_key,
            pid=sample.pid,
            process_name=sample.name,
            started_at=sample.process_started_at,
            window_start=items[0].observed_at,
            window_end=items[-1].observed_at,
            values=values,
            missing_fields=tuple(missing),
        )

    def clear(self) -> None:
        self._samples.clear()

    def prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_samples)
        for key in list(self._samples):
            if self._samples[key][-1].observed_at <= cutoff:
                del self._samples[key]

    @staticmethod
    def _growth_ratio(values: list[float]) -> float:
        first = max(values[0], 1.0)
        return max(0.0, (values[-1] - values[0]) / first)

    @staticmethod
    def _delta(values: list[float]) -> float:
        return values[-1] - values[0] if len(values) >= 2 else 0.0

    @staticmethod
    def _counter_delta(values: list[int]) -> float:
        if len(values) < 2:
            return 0.0
        return max(0, values[-1] - values[0]) / (1024 * 1024)
