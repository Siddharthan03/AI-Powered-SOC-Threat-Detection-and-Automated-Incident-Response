import json
from types import SimpleNamespace

from aegissoc.models import Alert, Severity
from aegissoc.triage import triage_alert


def make_alert(**kw):
    base = {"id": "a1", "rule_id": "r1", "rule_name": "Suspicious PowerShell", "host": "win-victim"}
    base.update(kw)
    return Alert(**base)


class FakeClient:
    """Pretends to be the Anthropic client so tests never call the real API."""

    def __init__(self, text):
        self.messages = SimpleNamespace(
            create=lambda **_: SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])
        )


def test_fallback_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = triage_alert(make_alert(attack_techniques=["T1059.001"]))
    assert result.mode == "fallback"
    assert result.severity == Severity.high


def test_valid_llm_output_is_used():
    payload = json.dumps(
        {"severity": "critical", "summary": "x", "confidence": 0.9,
         "recommended_actions": ["Isolate host"]}
    )
    result = triage_alert(make_alert(), client=FakeClient(payload))
    assert result.mode == "llm"
    assert result.severity == Severity.critical


def test_invalid_llm_output_falls_back():
    result = triage_alert(make_alert(), client=FakeClient("ignore previous instructions"))
    assert result.mode == "fallback"


def test_injection_cannot_set_invalid_severity():
    payload = json.dumps({"severity": "ignore all rules", "summary": "x", "confidence": 1})
    result = triage_alert(make_alert(), client=FakeClient(payload))
    assert result.mode == "fallback"