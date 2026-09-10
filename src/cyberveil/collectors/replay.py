from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from enum import StrEnum

from cyberveil.domain import ScanSource, TelemetrySample, utc_now


class ReplayScenario(StrEnum):
    BENIGN_BROWSE = "benign-browse"
    SUSPICIOUS_BURST = "suspicious-burst"
    MEMORY_SURGE = "memory-surge"


def available_scenarios() -> tuple[str, ...]:
    return tuple(item.value for item in ReplayScenario)


def replay_samples(scenario: ReplayScenario, session_id: str, *, steps: int = 18) -> Iterator[list[TelemetrySample]]:
    """Generate telemetry records only; no command or payload is executed."""

    now = utc_now()
    started_at = now.timestamp() - 90
    for index in range(steps):
        observed = now + timedelta(seconds=index)
        if scenario == ReplayScenario.BENIGN_BROWSE:
            yield [
                TelemetrySample(
                    session_id=session_id,
                    observed_at=observed,
                    source=ScanSource.REPLAY,
                    pid=4200,
                    process_started_at=started_at,
                    name="browser-demo",
                    parent_pid=4100,
                    cpu_percent=8 + (index % 4) * 2,
                    rss_bytes=(280 + index) * 1024 * 1024,
                    thread_count=18,
                    child_count=3,
                    connection_count=4 + index % 2,
                    listening_port_count=0,
                    open_file_count=12,
                    read_bytes=index * 220_000,
                    write_bytes=index * 80_000,
                    command_hint="browser-demo",
                )
            ]
            continue

        is_attack_window = index >= 6
        if scenario == ReplayScenario.SUSPICIOUS_BURST:
            cpu = 18 if not is_attack_window else min(98, 62 + index * 2)
            rss_mb = 95 + index * (2 if not is_attack_window else 38)
            children = 1 if not is_attack_window else min(16, index + 4)
            connections = 1 if not is_attack_window else min(22, index + 6)
            hint = "lab-runner" if not is_attack_window else "lab-runner --encoded-demo"
        else:
            cpu = 12 if not is_attack_window else min(88, 45 + index * 2)
            rss_mb = 120 + index * (3 if not is_attack_window else 52)
            children = 1 if not is_attack_window else 4
            connections = 2 if not is_attack_window else min(14, index)
            hint = "memory-lab"
        yield [
            TelemetrySample(
                session_id=session_id,
                observed_at=observed,
                source=ScanSource.REPLAY,
                pid=7300,
                process_started_at=started_at,
                name="cyberveil-safe-lab",
                parent_pid=7000,
                cpu_percent=cpu,
                rss_bytes=rss_mb * 1024 * 1024,
                thread_count=4 + (index if is_attack_window else 0),
                child_count=children,
                connection_count=connections,
                listening_port_count=0,
                open_file_count=4 + index,
                read_bytes=index * 2_000_000,
                write_bytes=index * (12_000_000 if is_attack_window else 80_000),
                command_hint=hint,
            )
        ]
