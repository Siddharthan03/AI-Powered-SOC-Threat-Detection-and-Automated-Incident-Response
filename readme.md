# AegisSOC

AI-powered SOC: intelligent threat detection and automated incident response.

A simplified SIEM + SOAR + AI analyst platform designed with enterprise practices:
untrusted-input handling, dry-run response actions and approval gates.

## Status
Day 1 of a daily-commit build. See docs/devlog.md.

## Quick start
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
uvicorn aegissoc.api.main:app --reload --app-dir src

Then open http://localhost:8000/docs