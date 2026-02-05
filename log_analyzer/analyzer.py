import re
from collections import defaultdict
import argparse

'''Module for analyzing log files and extracting error messages.'''

# Function to add filtering logic.
def print_top(tittle, data, top_n):
    print(f"\n--- {tittle} ---\n")
    for key, value in sorted(data.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"  {key}: {value}")

# CLI argument parsing for log files.
parser = argparse.ArgumentParser(
    description = "Analyze Apache access logs and generate summary reports."
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

# Parse the arguments
args = parser.parse_args()

# Counters
total_requests = 0
total_bytes = 0

requests_per_ip = defaultdict(int)
status_code_counts = defaultdict(int)
path_counts = defaultdict(int)
error_counts = defaultdict(int)

# Variables to hold extracted data
protocol = ""
method = ""
status = 0
size = 0
ip = ""
timestamp = ""
path = ""

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

# Open and read log file
with open(args.logfile, 'r') as log_file:
    for line in log_file:
        # Process and strip each line of file and strip whitespace
        line = line.strip()
        # Search and find matches using regex.
        match = log_pattern.search(line)
        # If matches are found return the matched in groups (dictionary).
        if not match:
            continue

        data = match.groupdict()

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

# Print summary of analysis in a nice template
print("\n--- Log Analysis Summary ---\n")

print(f"Total requests: {total_requests}")
print(f"Total bytes transferred: {total_bytes}\n")

if args.errors_only:
    print_top("Error Status Codes", error_counts, args.top)
else:
    print_top("Top IP addresses", requests_per_ip, args.top)
    print("\nStatus codes:")
    for status, count in sorted(status_code_counts.items()):
        print(f"  {status}: {count}")
    print_top("Top Requested Paths", path_counts, args.top)
    print_top("Error Status Codes", error_counts, args.top)