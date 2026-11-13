from fastapi import FastAPI, HTTPException

from aegissoc import __version__
from aegissoc.models import Alert, TriageResult
from aegissoc.soar import run_action
from aegissoc.triage import triage_alert

app = FastAPI(title="AegisSOC", version=__version__)

# In-memory store for now. We replace this with PostgreSQL in Week 1.
_ALERTS: dict[str, Alert] = {}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/alerts", response_model=Alert)
def create_alert(alert: Alert) -> Alert:
    _ALERTS[alert.id] = alert
    return alert


@app.get("/alerts", response_model=list[Alert])
def list_alerts() -> list[Alert]:
    return list(_ALERTS.values())


@app.post("/alerts/{alert_id}/triage", response_model=TriageResult)
def triage(alert_id: str) -> TriageResult:
    alert = _ALERTS.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return triage_alert(alert)


@app.post("/respond")
def respond(action: str, target: str, approved: bool = False) -> dict:
    return run_action(action, target, approved).__dict__