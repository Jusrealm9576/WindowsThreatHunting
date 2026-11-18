#!/usr/bin/env python3
"""Normalize Sysmon CSV exports whose event details are packed into one cell."""
import csv
import os
import sys

POSSIBLE_FIELDS = [
    "Process Create", "Network connection detected", "RuleName", "UtcTime",
    "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description",
    "Product", "Company", "OriginalFileName", "CommandLine",
    "CurrentDirectory", "User", "LogonGuid", "LogonId",
    "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid",
    "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser",
    "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
    "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp",
    "DestinationHostname", "DestinationPort", "DestinationPortName",
]
BASE_HEADERS = ["Information", "Timestamp", "Source", "EventID", "EventType"]


def process_sysmon_csv(input_file):
    base, ext = os.path.splitext(input_file)
    output_file = f"{base}_processed{ext}"
    with open(input_file, "r", newline="", encoding="utf-8-sig") as infile, \
         open(output_file, "w", newline="", encoding="utf-8") as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        writer.writerow(BASE_HEADERS + POSSIBLE_FIELDS)
        for row in reader:
            if not row:
                continue
            base_fields = row[:-1]
            details = row[-1]
            data_dict = {}
            for line in details.strip().splitlines():
                line = line.strip()
                if line and ":" in line:
                    key, value = line.split(":", 1)
                    data_dict[key.strip()] = value.strip()
                elif line:
                    data_dict[line] = line
            writer.writerow(
                base_fields + [data_dict.get(field, "-") for field in POSSIBLE_FIELDS]
            )
    print(f"Processed file saved as: {output_file}")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python changeCSV.py input_file.csv")
    if not os.path.exists(sys.argv[1]):
        raise SystemExit(f"Error: File '{sys.argv[1]}' not found")
    process_sysmon_csv(sys.argv[1])


if __name__ == "__main__":
    main()
