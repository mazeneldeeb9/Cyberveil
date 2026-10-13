from cyberveil.collectors import ReplayScenario
from cyberveil.collectors.replay import replay_samples
from cyberveil.detection import CompositeClassifier
from cyberveil.domain import AppSettings, ScanSource, ScanStatus
from cyberveil.engine import MonitoringEngine
from cyberveil.storage import Database


def test_replay_persists_detection_and_reportable_scan(database: Database) -> None:
    engine = MonitoringEngine(
        database,
        CompositeClassifier(),
        AppSettings(),
        source=ScanSource.REPLAY,
    )
    engine.start()
    emitted = []
    for batch in replay_samples(ReplayScenario.SUSPICIOUS_BURST, engine.session_id):
        emitted.extend(engine.ingest(batch))
    engine.finish(ScanStatus.COMPLETED)

    scan = database.get_scan(engine.session_id)
    assert scan is not None and scan.status == ScanStatus.COMPLETED
    assert scan.sample_count == 18
    assert emitted and database.list_detections(engine.session_id)
