# Devlog

## Day 1: 2026-11-12

**Done**
- Created the repo structure and starter code
- Triage module with schema validation and an offline fallback
- Dry-run SOAR layer with an approval gate
- First Sigma rule (T1110)

**Learned**
- Log fields are attacker-controlled, so alert content has to be treated as untrusted input.

**Next**
- Day 2: build the lab VMs (Linux and Windows with Sysmon)