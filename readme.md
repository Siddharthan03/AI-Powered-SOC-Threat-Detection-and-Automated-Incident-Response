# AegisSOC

AI-powered SOC: intelligent threat detection and automated incident response.

A simplified SIEM + SOAR + AI analyst platform designed with enterprise practices:
untrusted-input handling, dry-run response actions and approval gates.

## Status
# Devlog

## Day 1: 2026-11-12

**Done**
- Created the repo structure and starter code
- Triage module with schema validation and an offline fallback
- Dry-run SOAR layer with an approval gate
- First Sigma rule (T1110)

**Learned**
- Log fields are attacker-controlled, so alert content has to be treated as untrusted input.

## Day 2: 2026-11-25

**Done**
- Installed UTM and created an Ubuntu 26.04 ARM64 VM (3 GB RAM, 2 CPU, 30 GB disk)
- Switched from desktop to text boot to save memory (usage dropped from ~70% to ~10%)
- Extended the LVM root volume from 13 GB to 27 GB
- Set up SSH access from the host and cloned a clean restore point

**Learned**
- Apple Silicon needs ARM64 images.
- The Ubuntu installer only allocates about half the disk to the root volume by default; `lvextend -r` fixes it online.
- On 8 GB RAM, a desktop environment costs about 1 GB that the lab needs.

## Day 3: 2026-11-25

**Done**
- Added the Wazuh apt repository and installed wazuh-manager 4.14.10 (ARM64) on Ubuntu 26.04
- Manager only, no indexer or dashboard, to fit 8 GB RAM; footprint is about 1 GB
- Verified all core daemons running
- Verified detection: rule 5710 fired on failed SSH logins

**Learned**
- Checking the package list for ARM64 builds before installing avoided a dead end.
- The optional daemons (cluster, email, integrator) being "not running" is expected.
- Wazuh alerts carry a rule ID, a severity level and compliance tags, and are also written as JSON, which our ingest service will read.

## Quick start
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
uvicorn aegissoc.api.main:app --reload --app-dir src

Then open http://localhost:8000/docs
