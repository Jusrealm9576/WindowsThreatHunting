#!/usr/bin/env python3
"""Convert a processed CSV into newline-delimited JSON records."""
import csv
import json
import os
import sys


def convert_csv_to_json(csv_filename):
    if not os.path.isfile(csv_filename):
        raise SystemExit(f"Error: File '{csv_filename}' not found.")
    json_filename = os.path.splitext(csv_filename)[0] + ".json"
    with open(csv_filename, mode="r", encoding="utf-8-sig", newline="") as csv_file, \
         open(json_filename, "w", encoding="utf-8") as json_file:
        for row in csv.DictReader(csv_file):
            json_file.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Converted '{csv_filename}' to '{json_filename}'")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python conver2.py processed_sysmon.csv")
    convert_csv_to_json(sys.argv[1])
