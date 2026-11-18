# Windows Post-Exploitation Threat Hunting

A lab-based investigation into Windows post-exploitation detection using Sysmon, Suricata, Wazuh, and Python log-processing utilities.

## Start here

Read [`blog.md`](blog.md) for the full technical write-up, including the original report screenshots, captions, investigation findings, detection queries, and lessons learned.

## Repository layout

- `blog.md` — detailed technical article
- `images/` — screenshots and MITRE ATT&CK mapping extracted from the original report
- `scripts/` — CSV normalization, CSV-to-JSON conversion, and a data-preparation wrapper

## Scope and safety

This material documents a controlled lab investigation. Do not run tests against systems you do not own or have explicit permission to assess. The scripts are examples and should be reviewed and tested against copies of log files before use.

The additional datasets discussed in the article were shared by other participants and are identified separately from the primary lab environment.
