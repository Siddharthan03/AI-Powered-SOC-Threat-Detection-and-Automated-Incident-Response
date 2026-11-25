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

**Next**
- Day 3: install the Wazuh manager (manager only, no indexer or dashboard)