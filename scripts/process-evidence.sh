#!/usr/bin/env bash
# Example data-preparation pipeline from the investigation.
# Review paths, permissions, and the destination before running in your own lab.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <pcap_filename> <csv_filename>" >&2
  exit 1
fi

PCAP_FILE="$1"
CSV_FILE="$2"

echo "Running Suricata against the supplied capture..."
sudo suricata -r "$PCAP_FILE"

echo "Normalizing Sysmon CSV..."
python3 scripts/changeCSV.py "$CSV_FILE"
PROCESSED_CSV="${CSV_FILE%.csv}_processed.csv"
[[ -f "$PROCESSED_CSV" ]] || { echo "Processed CSV not found" >&2; exit 1; }

echo "Converting normalized CSV to newline-delimited JSON..."
python3 scripts/conver2.py "$PROCESSED_CSV"
PROCESSED_JSON="${PROCESSED_CSV%.csv}.json"
[[ -f "$PROCESSED_JSON" ]] || { echo "Processed JSON not found" >&2; exit 1; }

echo "Pipeline complete. Review the JSON output before ingesting it into your SIEM."
# The original workflow appended records to a local Suricata custom log.
# That destination and ingestion method are environment-specific, so this
# portable version leaves ingestion as an explicit, reviewed next step.
