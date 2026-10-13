import json

import httpx
import pytest

from cyberveil.domain import IncidentReport, ScanRecord, ScanSource, ScanStatus, utc_now
from cyberveil.integrations import OllamaExplainer


def report(status=ScanStatus.COMPLETED):
    return IncidentReport(
        scan=ScanRecord(
            session_id="test", source=ScanSource.REPLAY, status=status, started_at=utc_now(), operating_system="test"
        )
    )


def mock_client(monkeypatch, handler):
    real = httpx.Client
    settings = []

    def client(**kwargs):
        settings.append(kwargs)
        return real(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", client)
    return settings


def test_local_schema_and_transport_guards(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"model_info": {"general.architecture": "test"}})
        return httpx.Response(
            200,
            json={
                "done": True,
                "response": json.dumps(
                    {
                        "summary": "Observed events.",
                        "impact": "Lab only.",
                        "next_steps": ["Review evidence."],
                    }
                ),
            },
        )

    settings = mock_client(monkeypatch, handler)
    result = OllamaExplainer("local:test").explain(report())
    assert result.generated_by == "Ollama: local:test"
    assert all(s["trust_env"] is False and s["follow_redirects"] is False for s in settings)
    assert all(r.url.host == "127.0.0.1" for r in requests)
    body = json.loads(requests[-1].content)
    assert body["stream"] is False and isinstance(body["format"], dict)
    assert "untrusted data" in body["system"]


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"response": 5},
        {"done": False, "response": "{}"},
        {"done": True, "response": '{"summary":"ok","impact":"ok","next_steps":[4]}'},
        {"done": True, "response": "{"},
        {"done": True, "response": "x" * 140000},
    ],
)
def test_bad_response_falls_back(monkeypatch, payload):
    def handler(request):
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"model_info": {"architecture": "test"}})
        return httpx.Response(200, json=payload)

    mock_client(monkeypatch, handler)
    assert OllamaExplainer("test").explain(report()).generated_by == "CYBERVEIL template"


def test_remote_model_refused_before_evidence_is_sent(monkeypatch):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"remote_model": "remote", "remote_host": "https://example.com"})

    mock_client(monkeypatch, handler)
    assert OllamaExplainer("looks-local").explain(report()).fallback_reason == "local_model_required"
    assert paths == ["/api/show"]


@pytest.mark.parametrize("mode", ["timeout", "redirect", "unavailable"])
def test_optional_service_failure_is_safe(monkeypatch, mode):
    def handler(request):
        if mode == "timeout":
            raise httpx.ReadTimeout("timeout", request=request)
        return httpx.Response(302 if mode == "redirect" else 503, headers={"location": "https://example.com"})

    mock_client(monkeypatch, handler)
    assert OllamaExplainer("test").explain(report()).generated_by == "CYBERVEIL template"


@pytest.mark.parametrize("status", list(ScanStatus))
@pytest.mark.parametrize("language", ["en", "ar"])
def test_fallback_preserves_actual_scan_status(status, language):
    from cyberveil.ui.i18n import Translator

    result = OllamaExplainer("").explain(report(status), language=language)
    assert Translator(language).observation(status.value) in result.summary
    if status != ScanStatus.COMPLETED:
        assert "completed" not in result.summary and "اكتمل" not in result.summary
