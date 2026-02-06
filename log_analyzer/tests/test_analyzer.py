import re # Regular expression module
from log_analyzer.analyzer import ( # Importing functions from log_analyzer module
    parse_log_line,
    is_error_status,
    detect_suspicious_ips,
)

# Regular expression pattern for log parsing test.
LOG_PATTERN = re.compile(
     r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS) '
    r'(?P<path>[^ ]+) '
    r'(?P<protocol>HTTP\/[0-9.]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\d+)'
)

# Test for line parsing function with a valid log line.
def test_parse_log_line_valid():
    line = (
        '127.0.0.1 - - [10/Oct/2024:13:55:36 -0700] '
        '"GET /index.html HTTP/1.1" 200 2326'
    )

    data = parse_log_line(line, LOG_PATTERN)

# Assertions to verify correct parsing.
    assert data is not None
    assert data['ip'] == "127.0.0.1"
    assert data['method'] == "GET"
    assert data['path'] == "/index.html"
    assert data['status'] == "200"

# Test for line parsing function with an invalid log line.
def test_parse_log_line_invalid():
    line = "this is not a log line"
    data = parse_log_line(line, LOG_PATTERN)
    
    assert data is None

# Test for error status code detection function.
def test_is_error_status():
    assert is_error_status(404) is True
    assert is_error_status(500) is True
    assert is_error_status(200) is False

# Test for detecting suspicious IPs based on request counts.
def test_detect_suspicious_ips():
    requests = {
        "192.168.1.1": 10,
        "10.0.0.1": 2,
        "203.0.113.5": 7
    }

    suspicious = detect_suspicious_ips(requests, threshold=5)

    assert "192.168.1.1" in suspicious
    assert "203.0.113.5" in suspicious
    assert "10.0.0.1" not in suspicious