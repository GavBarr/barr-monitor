import argparse
import tempfile
import time
import os
import re
import psutil
import signal
import subprocess
import sys


PID_FILE = os.path.join(tempfile.gettempdir(), "barr-monitor.pid")  # Cross-platform temp directory


# Default keywords for searching errors
DEFAULT_KEYWORDS = ["ERROR", "WARNING", "CRITICAL"]


def analyze_logs(log_path, export_path=None, keywords=None):
    """Scans the given log file or directory for errors and writes results to a file if needed."""
    results = []
    
    if os.path.isdir(log_path):
        print(f"\n[INFO] Scanning directory: {log_path}")
        for file in os.listdir(log_path):
            if file.endswith(".log") or file.endswith(".txt"):
                results.extend(scan_file(os.path.join(log_path, file), keywords))
    elif os.path.isfile(log_path):
        print(f"\n[INFO] Scanning file: {log_path}")
        results.extend(scan_file(log_path, keywords))
    else:
        print(f"[ERROR] Invalid path: {log_path}")
        return

    if export_path:
        save_report(results, export_path)

def scan_file(file_path, keywords):
    """Reads a log file, finds errors based on keywords, and returns a list of formatted results."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[ERROR] Could not read {file_path}: {e}")
        return []

    found_errors = []
    print(f"\n[LOG ERRORS] - {file_path}")
    
    # Create a regex pattern from the provided keywords
    pattern = "|".join([re.escape(keyword) for keyword in keywords])

    for line_num, line in enumerate(lines, start=1):
        if re.search(pattern, line, re.IGNORECASE):
            error_msg = f"Line {line_num}: {line.strip()}"
            print(error_msg)
            found_errors.append(f"{file_path} - {error_msg}")

    if not found_errors:
        print(f"[OK] No errors found in {file_path}")

    return found_errors

def save_report(results, export_path):
    """Writes the log analysis results to a specified file."""
    try:
        with open(export_path, 'w', encoding='utf-8') as f:
            for line in results:
                f.write(line + "\n")
        print(f"\n[INFO] Report saved to {export_path}")
    except Exception as e:
        print(f"[ERROR] Could not write to {export_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Barr Monitor - Log Analyzer CLI")
    parser.add_argument("command", help="log path")
    parser.add_argument("export_path", nargs="?", help="Path to export the report (optional)")
    parser.add_argument("--keywords", type=str, help="Comma-separated list of custom keywords to search for in logs")

    args = parser.parse_args()

    keywords = DEFAULT_KEYWORDS
    
    if args.keywords:
        keywords = [keyword.strip() for keyword in args.keywords.split(",")]

    analyze_logs(args.command, args.export_path, keywords)

if __name__ == "__main__":
    main()
