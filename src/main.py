import argparse
import time
import os
import re
import psutil
import signal
import subprocess
import sys

PID_FILE = "/tmp/barr-monitor.pid"  # Stores running processes

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

def watch_logs(log_path, interval, run_time, export_path=None, keywords=None):
    """Reprocesses logs at a set interval and terminates after the specified run-time."""
    pid = os.getpid()
    start_time = time.time()

    with open(PID_FILE, "a") as f:
        f.write(f"{pid}\n")

    print(f"[WATCH MODE] Running in the background (PID: {pid})")

    while True:
        analyze_logs(log_path, export_path, keywords)
        elapsed_time = (time.time() - start_time) / 3600  # Convert seconds to hours
        if elapsed_time >= run_time:
            print(f"[INFO] Run-time of {run_time} hours reached. Stopping process {pid}.")
            stop_process(pid)
            break
        print(f"\n[INFO] Sleeping for {interval} minutes before next check...")
        time.sleep(interval * 60)

def list_processes():
    """Lists running barr-monitor processes."""
    if not os.path.exists(PID_FILE):
        print("[INFO] No active barr-monitor processes found.")
        return

    print("[ACTIVE PROCESSES]")
    with open(PID_FILE, "r") as f:
        pids = f.readlines()
    
    for pid in pids:
        pid = pid.strip()
        if pid and psutil.pid_exists(int(pid)):
            print(f"barr-monitor (PID: {pid})")
        else:
            remove_stale_pid(pid)

def remove_stale_pid(pid):
    """Removes a stale PID from the PID file if it no longer exists."""
    with open(PID_FILE, "r") as f:
        pids = f.readlines()

    with open(PID_FILE, "w") as f:
        for p in pids:
            if p.strip() != pid:
                f.write(p)

def stop_process(pid):
    """Stops a barr-monitor process by PID."""
    if not psutil.pid_exists(int(pid)):
        print(f"[ERROR] Process {pid} not found.")
        return

    os.kill(int(pid), signal.SIGTERM)
    print(f"[INFO] Stopped barr-monitor process {pid}")
    remove_stale_pid(pid)

def main():
    parser = argparse.ArgumentParser(description="Barr Monitor - Log Analyzer CLI")
    parser.add_argument("command", help="log path OR 'listing'/'stop'")
    parser.add_argument("--watch", type=int, help="Time interval (in minutes) for reprocessing logs")
    parser.add_argument("--run-time", type=int, help="Time limit (in hours) for process execution")
    parser.add_argument("export_path", nargs="?", help="Path to export the report (optional)")
    parser.add_argument("pid", nargs="?", help="Process ID to stop (used with 'stop')")
    parser.add_argument("--keywords", type=str, help="Comma-separated list of custom keywords to search for in logs")


    args = parser.parse_args()

    keywords = DEFAULT_KEYWORDS
    if args.keywords:
        keywords = [keyword.strip() for keyword in args.keywords.split(",")]

    if args.command == "stop":
        if not args.export_path:
            print("[ERROR] Please provide a process ID to stop.")
        else:
            stop_process(args.export_path)  # Use export_path to store the PID for 'stop'
    elif args.command == "listing":
        list_processes()
    elif args.command == "stop":
        if args.pid:
            stop_process(args.pid)
        else:
            print("[ERROR] Please provide a process ID to stop.")
    elif args.watch:
        if not args.run_time:
            print("[ERROR] --run-time is required when using --watch.")
            sys.exit(1)

        print(f"[INFO] Watch mode enabled - Running every {args.watch} minutes for up to {args.run_time} hours.")
            
        if "BARR_MONITOR_DAEMON" not in os.environ:
            cmd = [sys.executable, __file__, args.command, "--watch", str(args.watch), "--run-time", str(args.run_time)]
            if args.export_path:
                cmd.append(args.export_path)
            
            env = os.environ.copy()
            env["BARR_MONITOR_DAEMON"] = "1"
            
            subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True
            )
            
            print("[INFO] Process started in the background. You can now close the terminal.")
            sys.exit(0)
        
        watch_logs(args.command, args.watch, args.run_time, args.export_path, keywords)
    else:
        analyze_logs(args.command, args.export_path, keywords)

if __name__ == "__main__":
    main()
