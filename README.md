# Log Analyzer

A Python command-line tool that analyzes Apache access logs using regular expressions, aggregates useful metrics, detects errors and suspicions activity, and exports reports in multiple formats.

This tool is designed to work with real-world log files and supports filtering, reporting, and automation-friendly outputs.

## Features

- Parse Apache access logs using regex.
- Aggregate traffic and error statistics.
- Identify top IP addresses and endpoints.
- Detect suspicios IP activity by request volume.
- Filter logs by time range.
- Export reports to JSON and CSV.
- Flexible CLI interface (works with any file path).

## Requirements

- Python 3.8+
  
## Usage

```cli
./log_analyzer.py access.log 
```

or 

```cli
python log_analyzer.py access.log
```

Works with:

- relative paths
- absolute paths

Example:

```cli
python log_analyzer.py /var/log/apache2/access.log
```

### Show Top N Results:

Limit output to the top N entries (Default is 5):

```cli
python log_analyzerpython log_analyzer.py access.log
 --top 3
```

### Detect Suspicious IPs

Flag IP addresses with a high number of requests:

```cli
python log_analyzerpython log_analyzer.py access.log --suspicious-threshold 100
```

This is useful for identifying:

- brute-force attempts.
- scrapping behavior.
- abnormal traffic spikes.

### Filter by Time Range

Analyze logs only within a specific time window:

```cli
python log_analyzerpython log_analyzer.py access.log --start-time "10/Oct/2024:13:55:00 -0700" --end-time "10/Oct/2024:14:00:00 -0700"
```

Time format must match the Apache log timestamp exactly.

### Export Results

Export to JSON

```cli
python log_analyzer.py access.log --export-json report.json
```

Export to CSV

```cli
python log_analyzer.py access.log --export-csv report.csv
```

These exports are useful for:

- Dashboards.
- Spreadsheets.
- Further automated analysis.

### Example Output

```cli
--- Log Analysis Summary ---
Total requests: 10482
Total bytes: 18923422

--- Top IPs ---
192.168.1.10: 1203
203.0.113.45: 984

--- Errors ---
404: 821
500: 47
```

### Project Structure

```text
log_analyzer/
├── log_analyzer.py
├── sample_logs/
│   └── access.log
├── README.md
```

### Design Notes

- Uses named regex groups for readability.
- Processes logs line by line for memeory efficiency.
- Separates parsing, aggregation, and reporting logic.
- Built as a CLI-first tool for automation and scripting.

## Future Improvements

- Support for additional log formats. (Nginx, app logs)
- Unit tests.
- Packaging as a pip-installable CLI tool.
