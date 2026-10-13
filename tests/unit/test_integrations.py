from cyberveil.domain import IncidentReport, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.forensics import VolatilityAnalyzer, VolatilityUnavailable
from cyberveil.integrations import OllamaExplainer


def report() -> IncidentReport:
    return IncidentReport(
        scan=ScanRecord(
            session_id="scan",
            source=ScanSource.REPLAY,
            status=ScanStatus.COMPLETED,
            started_at=utc_now(),
            operating_system="TestOS",
        )
    )


def test_ollama_fallback_is_honest() -> None:
    result = OllamaExplainer("").explain(report())
    assert "academic" in result.impact.lower()
    assert result.generated_by == "CYBERVEIL template"


def test_volatility_missing_dependency_is_actionable(tmp_path) -> None:
    image = tmp_path / "memory.raw"
    image.write_bytes(b"not a real image")
    analyzer = VolatilityAnalyzer(executable="")
    analyzer.executable = None
    try:
        analyzer.analyze(image, "windows")
    except VolatilityUnavailable as exc:
        assert "forensics" in str(exc).lower()
    else:
        raise AssertionError("Expected missing Volatility to fail")
