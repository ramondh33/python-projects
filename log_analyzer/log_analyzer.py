#!/usr/bin/env python3
import re
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def main():
    '''Module for analyzing log files and extracting error messages.'''

    # Function to add filtering logic.
    def print_top(tittle, data, top_n):
        print(f"\n--- {tittle} ---\n")
        for key, value in sorted(data.items(), key=lambda x: x[1], reverse=True)[:top_n]:
            print(f"  {key}: {value}")

    # Define helper function for timestamp parsing.
    def parse_timestamp(timestamp):
        return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")

    # CLI argument parsing for log files.
    parser = argparse.ArgumentParser(
        description = "Analyze Apache access logs and generate summary reports."
    )

    # CLI argument to export results to CSV.
    parser.add_argument(
        "--export-csv",
        help = "Export the analysis results to a CSV file."
    )

    # CLI argument to filter start time.
    parser.add_argument(
        "--start-time",
        help = "Start time for log filtering (format: 'DD/MMM/YYYY:HH:MM:SS +ZZZZ')."
    )

    # CLI argument to filter end time.
    parser.add_argument(
        "--end-time",
        help = "End time for log filtering (format: 'DD/MMM/YYYY:HH:MM:SS +ZZZZ')."
    )

    # CLI argument to export results to JSON.
    parser.add_argument(
        "--export-json",
        help = "Export the analysis results to a JSON file."
    )

    # Add arguments for log file path and options.
    parser.add_argument(
        'logfile',
        type = str,
        help = 'Path to the Apache access log file to analyze.'
    )

    # Optional argument to limit number of results shown.
    parser.add_argument(
        '--top',
        type = int,
        default = 5,
        help = "Show top N results (default: 5)."
    )

    # Optional argument to filter only error-related statistics.
    parser.add_argument(
        '--errors-only',
        action = 'store_true',
        help = "Show only error-related statistics."
    )

    # CLI filter for malicious IPs.
    parser.add_argument(
        '--suspicious-threshold',
        type = int,
        default = 0,
        help = "Flag IPs with request count >= threshold."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Validate log file path
    try:
        log_path = Path(args.logfile).expanduser()

    except PermissionError:
        print(f"Error: Permission denied for log file '{args.logfile}'.")
        exit(1)

    if not log_path.exists():
        print(f"Error: Log file '{args.logfile}' does not exist.")
        exit(1)

    if not log_path.is_file():
        print(f"Error: '{args.logfile}' is not a file.")
        exit(1)

    # Counters
    total_requests = 0
    total_bytes = 0

    requests_per_ip = defaultdict(int)
    status_code_counts = defaultdict(int)
    path_counts = defaultdict(int)
    error_counts = defaultdict(int)

    # Regular expressions for log parsing
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS) '
        r'(?P<path>[^ ]+) '
        r'(?P<protocol>HTTP\/[0-9.]+)" '
        r'(?P<status>\d{3}) '
        r'(?P<size>\d+)'
    )

    # Apply time filtering if specified
    start_time = parse_timestamp(args.start_time) if args.start_time else None
    end_time = parse_timestamp(args.end_time) if args.end_time else None

    # Open and read log file
    with log_path.open(mode='r') as log_file:
        for line in log_file:
            # Process and strip each line of file and strip whitespace
            line = line.strip()
            # Search and find matches using regex.
            match = log_pattern.search(line)
            # If matches are found return the matched in groups (dictionary).
            if not match:
                continue

            data = match.groupdict()

            # Parse timestamp
            log_time = parse_timestamp(data['timestamp'])

            if start_time and log_time < start_time:
                continue
            if end_time and log_time > end_time:
                continue

            # Extract data from matched groups

            ip = data['ip']
            timestamp = data['timestamp']
            method = data['method']
            path = data['path']
            protocol = data['protocol']
            status = int(data['status'])
            size = int(data['size'])

            # Update counters
            total_requests += 1
            total_bytes += size

            requests_per_ip[ip] += 1
            status_code_counts[status] += 1
            path_counts[path] += 1

            # Track errors (4xx and 5xx status codes)
            if status >= 400 and status < 600:
                error_counts[status] += 1

    # Detect suspicions IPs
    suspicious_ips = {}

    if args.suspicious_threshold > 0:
        for ip, count in requests_per_ip.items():
            if count >= args.suspicious_threshold:
                suspicious_ips[ip] = count

    # Summary Data
    summary = {
        "total_requests": total_requests,
        "total_bytes": total_bytes,
        "requests_per_ip": dict(requests_per_ip),
        "status_code_counts": dict(status_code_counts),
        "path_counts": dict(path_counts),
        "error_counts": dict(error_counts)
    }

    # Export to JSON
    if args.export_json:
        with log_path.open(mode='w') as file:
            json.dump(summary, file, indent=2)
        print(f"\nJSON report written to {args.export_json}")

    # Export to CSV
    if args.export_csv:
        with log_path.open(mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Metric", " Key ", "Value"])

            # Write metrics to CSV
            for ip, count in requests_per_ip.items():
                writer.writerow(["requests_per_ip", ip, count])

            for status, count in status_code_counts.items():
                writer.writerow(["status_code_counts", status, count])

            for path, count in path_counts.items():
                writer.writerow(["path_counts", path, count])
            
        print(f"\nCSV report written to {args.export_csv}")

    # Print summary of analysis in a nice template
    print("\n--- Log Analysis Summary ---\n")

    print(f"Total requests: {total_requests}")
    print(f"Total bytes transferred: {total_bytes}\n")
    if suspicious_ips:
            print("\n--- Suspicious IPs ---\n")
            for ip, count in suspicious_ips.items():
                print(f"  {ip}: {count} requests")


    if args.errors_only:
        print_top("Error Status Codes", error_counts, args.top)
    else:
        print_top("Top IP addresses", requests_per_ip, args.top)
        print("\nStatus codes:")
        for status, count in sorted(status_code_counts.items()):
            print(f"  {status}: {count}")
        print_top("Top Requested Paths", path_counts, args.top)
        print_top("Error Status Codes", error_counts, args.top)
    
if __name__ == "__main__":
    main()