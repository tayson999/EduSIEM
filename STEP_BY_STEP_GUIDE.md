# SIEM Project - Step-by-Step Learning Guide

## Overview

This project teaches you how to build a **Log Analysis & Lightweight SIEM** system from scratch. SIEM stands for Security Information and Event Management—basically a system that collects logs, analyzes them for threats, and generates alerts.

---

## Step 1: Understanding Logs

**What is a log?**
A log is a record of an event. Example:

```
192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234
```

This Apache web server log says:
- **IP**: 192.168.1.10 (who made the request?)
- **Time**: 05/Dec/2025 14:32:10 (when?)
- **Action**: GET /index.html (what did they request?)
- **Status**: 200 (did it succeed? 200 = yes)
- **Size**: 1234 bytes (how much data was sent?)

**Your goal**: Parse raw log text into structured data (dictionaries/DataFrames).

---

## Step 2: Log Parsing with Regex

**File**: `parsers.py`

Regular expressions (regex) find patterns in text.

### Example: Extract IP Address

```python
import re

# Regex pattern
pattern = r'(?P<ip>[\d.]+)'  # Find something like 192.168.1.10

# Test string
line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html"'

# Extract
match = re.search(pattern, line)
if match:
    print(match.group('ip'))  # Output: 192.168.1.10
```

### What the regex means:
- `[\d.]+` = One or more digits or dots
- `(?P<ip>...)` = Create a named group called "ip"

### Apache Log Parser

The `ApacheAccessLogParser` class uses a big regex to extract all fields at once:

```python
from parsers import ApacheAccessLogParser

line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234'
parser = ApacheAccessLogParser()
result = parser.parse(line)

print(result)
# {
#   'source_ip': '192.168.1.10',
#   'timestamp': datetime(2025, 12, 5, 14, 32, 10),
#   'method': 'GET',
#   'path': '/index.html',
#   'status': 200,
#   'bytes_sent': 1234
# }
```

**Key takeaway**: Regex lets you extract structured data from unstructured text.

---

## Step 3: Aggregating Events Over Time

**File**: `anomaly_detector.py` → `TimeSeriesAggregator`

Raw logs are noisy. We need to group them into time buckets.

### Example:

**Raw**: 1000 login attempts in 1 hour from one IP
```
14:00:01 - login
14:00:02 - login
14:00:03 - login
...
```

**Aggregated** (5-minute buckets):
```
14:00-14:05: 120 logins
14:05-14:10: 105 logins
14:10-14:15: 110 logins
...
```

Now we can see patterns: **mean = 105, std = 5**

### Code:

```python
import pandas as pd
from anomaly_detector import TimeSeriesAggregator

# Create DataFrame with logs
df = pd.DataFrame({
    'timestamp': pd.date_range('2025-12-05', periods=100, freq='1min'),
    'source_ip': '192.168.1.10',
    'action': 'login'
})

# Aggregate by source IP in 5-min windows
aggregator = TimeSeriesAggregator(df, window_minutes=5)
aggregated = aggregator.aggregate_by_source_ip()

# aggregated now has columns: timestamp, source_ip, event_count
```

**Key takeaway**: Grouping events reveals patterns invisible in raw data.

---

## Step 4: Detecting Anomalies

**File**: `anomaly_detector.py`

Three methods:

### Method 1: Z-Score (Statistical)

**Formula**: `z_score = (value - mean) / standard_deviation`

**Rule**: Flag if |z_score| > 3 (more than 3 standard deviations from mean)

**Example**:
- Normal logins per 5 min: mean=100, std=5
- One spike: 200 logins
- z_score = (200 - 100) / 5 = 20 → **ANOMALY!**

```python
from anomaly_detector import StatisticalAnomalyDetector

detector = StatisticalAnomalyDetector(df, method='zscore', threshold=3)
result = detector.detect()

anomalies = result[result['is_anomaly']]
print(anomalies)  # Shows events with |z_score| > 3
```

### Method 2: Machine Learning (Isolation Forest)

**Idea**: Randomly split the data. Outliers isolate faster.

```python
from anomaly_detector import MLAnomalyDetector

detector = MLAnomalyDetector(df, contamination=0.05)  # Expect 5% anomalies
result = detector.detect()
```

**Pros**: Works with multiple features (time of day, day of week, event count)
**Cons**: Harder to explain "why it's anomalous"

### Method 3: Rule-Based

**Idea**: Write explicit rules for known attacks.

```python
from anomaly_detector import RuleBasedDetector

detector = RuleBasedDetector(df)
brute_force_alerts = detector.detect_brute_force()
# Flags: >10 failed logins from same IP in 5 minutes
```

**Pros**: Easy to explain, tuned to your environment
**Cons**: Requires domain knowledge

**Key takeaway**: Combine multiple methods for better detection.

---

## Step 5: Generating Alerts

**File**: `alerting.py`

An alert tells humans "something happened, here's what to do."

### Alert Structure:

```python
from alerting import Alert, Severity
from datetime import datetime

alert = Alert(
    alert_type='brute_force_login',
    severity=Severity.CRITICAL,
    timestamp=datetime.now(),
    details={
        'source_ip': '192.168.1.100',
        'failed_attempts': 47,
        'threshold': 10
    },
    context={
        'recommendation': 'Block IP at firewall'
    }
)
```

### Severity Levels:

- **INFO**: Normal event (user logged in successfully)
- **WARNING**: Suspicious (unusual traffic pattern)
- **CRITICAL**: Immediate threat (brute-force attack)

### Alert Deduplication:

**Problem**: Same attack triggers 1000 alerts (alert storm)
**Solution**: Only alert once per alert type + IP in 5-minute window

```python
from alerting import AlertManager

manager = AlertManager(dedup_window_seconds=300)  # 5 min window

# Add alert (if not duplicate)
alert = manager.add_alert(
    alert_type='brute_force',
    severity=Severity.CRITICAL,
    timestamp=datetime.now(),
    details={'source_ip': '192.168.1.100'}
)

# Result: 1 alert instead of 1000
```

**Key takeaway**: Alerts inform action; deduplication prevents alert fatigue.

---

## Step 6: Outputting Alerts

**File**: `alerting.py` → `AlertFormatter`

Format alerts for different audiences.

### Text Format (for console):

```
[CRITICAL] BRUTE FORCE LOGIN
  Alert ID: ALERT_000001
  Time: 2025-12-05 14:32:10
  Source IP: 192.168.1.100
  Failed Attempts: 47
  Recommendation: Block IP at firewall
```

### JSON Format (for machines):

```json
{
  "alert_id": "ALERT_000001",
  "alert_type": "brute_force_login",
  "severity": "CRITICAL",
  "timestamp": "2025-12-05T14:32:10",
  "details": {
    "source_ip": "192.168.1.100",
    "failed_attempts": 47
  }
}
```

### Email Format:

Group alerts by severity, send via email.

```python
from alerting import AlertFormatter

formatter = AlertFormatter()
email_text = formatter.format_email(alerts)
```

**Key takeaway**: Same data, different formats for different use cases.

---

## Step 7: The Full Pipeline

**File**: `siem_engine.py`

Orchestrates all components:

1. **Parse** logs → Extract structured data
2. **Aggregate** → Group into time windows
3. **Detect** anomalies → Statistical, ML, rule-based
4. **Alert** → Generate alerts
5. **Report** → Output in different formats

### Run the full pipeline:

```bash
python siem_engine.py
```

Output:
```
STARTING SIEM ENGINE
Parsing apache log: sample_logs/apache_access.log
Parsed 16 entries
Running statistical anomaly detection...
Found 0 anomalies
Running ML anomaly detection...
Found 1 anomaly
Running rule-based detection...
Found 0 alerts
Alerts saved to ./siem_alerts.json
SIEM ENGINE COMPLETE
```

---

## Step 8: Hands-On Practice

### Exercise 1: Parse a New Log Format

**Goal**: Add Windows Event Log parser

```python
# In parsers.py, create WindowsEventLogParser class
class WindowsEventLogParser(LogParser):
    def parse(self, line: str) -> Optional[Dict]:
        # Extract: timestamp, event_id, account, action
        # Return dict with parsed fields
        pass
```

### Exercise 2: Custom Detection Rule

**Goal**: Detect unusual API calls

```python
# In anomaly_detector.py
class APIAnomalyDetector(RuleBasedDetector):
    def detect_unusual_endpoints(self) -> List[Dict]:
        # Find APIs called >100 times in 5 min
        # Return alerts
        pass
```

### Exercise 3: Export to CSV

**Goal**: Save alerts to CSV for Excel analysis

```python
# In alerting.py
alerts_csv = formatter.format_csv(alerts, filepath='alerts.csv')
# Open in Excel, pivot, visualize
```

### Exercise 4: Slack Integration

**Goal**: Send critical alerts to Slack

```python
import requests

slack_payload = formatter.format_slack(critical_alerts)
requests.post(SLACK_WEBHOOK_URL, json=slack_payload)
```

---

## Step 9: Configuration & Tuning

**File**: `config.yaml`

Adjust detection thresholds:

```yaml
detection:
  statistical:
    zscore_threshold: 3.0    # Increase = fewer alerts
    window_minutes: 5        # Shorter = more sensitive
  
  rules:
    brute_force:
      failed_login_threshold: 10  # Adjust based on your environment
```

**Tuning process**:
1. Run on historical logs
2. Check alerts: are they real threats or false positives?
3. Adjust thresholds
4. Repeat until good balance

---

## Step 10: Next Steps to Extend

### Real-Time Processing
Stream logs with Kafka, process with Spark Streaming

### Dashboard
Build a web UI with Flask/Dash to explore alerts

### Database
Store logs and alerts in PostgreSQL or Elasticsearch

### ML Classification
Train model to identify attack *type* (DDoS vs brute-force vs SQL injection)

### Automation
Auto-block IPs, create tickets, send notifications

---

## Summary

**You learned**:
1. Parse logs with regex
2. Aggregate events over time
3. Detect anomalies (statistical, ML, rule-based)
4. Generate alerts with context
5. Output alerts in multiple formats
6. Orchestrate components into a SIEM pipeline

**You can now**:
- Analyze real logs from your environment
- Detect suspicious patterns
- Alert security teams
- Build toward enterprise SIEM (ELK Stack, Splunk)

---

## Running Examples

```bash
# Install dependencies
pip install -r requirements.txt

# Run quick examples
python quick_examples.py

# Run full SIEM pipeline
python siem_engine.py

# Run unit tests
python test_siem.py
```

---

## Files Reference

| File | Purpose |
|------|---------|
| `parsers.py` | Log parsing with regex |
| `anomaly_detector.py` | Anomaly detection (3 methods) |
| `alerting.py` | Alert generation & formatting |
| `siem_engine.py` | Main orchestration |
| `config.yaml` | Configuration & thresholds |
| `test_siem.py` | Unit tests |
| `quick_examples.py` | Hands-on examples |
| `sample_logs/` | Sample log files |

---

Good luck learning SIEM! 🚀
