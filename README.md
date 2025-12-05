# Log Analysis & Lightweight SIEM Project

A step-by-step Python project to build a Security Information and Event Management (SIEM) system focused on log parsing, anomaly detection, and alert generation.

## What You'll Learn

1. **Log Parsing**: Extract structured data from unstructured log files (Apache, SSH, Windows Event logs).
2. **Time-Series Analysis**: Group events by time windows and detect anomalies.
3. **Pattern Matching**: Use regex to identify suspicious patterns (failed logins, port scans, etc.).
4. **Anomaly Detection**: Apply statistical methods (z-score, isolation forest) to flag unusual activity.
5. **Alerting System**: Generate actionable alerts with severity levels.
6. **Data Visualization**: Plot trends and anomalies over time.

## Project Structure

```
siem_project/
├── requirements.txt           # Python dependencies
├── config.yaml               # Configuration file (rules, thresholds)
├── parsers.py               # Log parsing modules
├── anomaly_detector.py       # Anomaly detection logic
├── alerting.py              # Alert generation & formatting
├── siem_engine.py           # Main orchestration
├── sample_logs/             # Test log files
│   ├── apache_access.log
│   ├── ssh_auth.log
│   └── windows_events.log
└── test_siem.py             # Unit tests
```

## Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Understand the Flow
- **Parse**: Convert raw logs → structured data (pandas DataFrame)
- **Detect**: Apply statistical/ML anomaly detection
- **Alert**: Flag anomalies with severity & context
- **Visualize**: Plot patterns and trends

### 3. Run the Main Engine
```bash
python siem_engine.py --log-file sample_logs/apache_access.log --config config.yaml
```

### 4. Run Tests
```bash
python -m pytest test_siem.py -v
```

## Key Concepts (Step-by-Step Teaching)

### Phase 1: Log Parsing
- Learn regex patterns for different log formats.
- Extract timestamp, source IP, action, status.
- Handle edge cases (malformed lines, timezones).

### Phase 2: Time-Series Aggregation
- Group events by time window (5-min, 1-hour buckets).
- Count events per source, per action type.
- Calculate statistics (mean, std dev, percentiles).

### Phase 3: Anomaly Detection
- **Statistical**: z-score (detect events > 3 std devs from mean).
- **Isolation Forest**: unsupervised ML to find outliers.
- **Rule-Based**: flag specific patterns (brute-force, port scans).

### Phase 4: Alerting & Visualization
- Assign severity (info, warning, critical).
- Generate reports (CSV, JSON).
- Plot time series with anomalies highlighted.

## Example Output

```
[CRITICAL] Brute-force SSH login attempt
  Time: 2025-12-05 14:32:10
  Source IP: 192.168.1.100
  Failed attempts: 47 (threshold: 10)
  Severity: CRITICAL
  Action: Review access controls
```

## Extensions (Advanced)

- **ML-based Classification**: Train a model to classify attack types.
- **Real-time Processing**: Use streaming (Kafka, Redis) for live log ingestion.
- **Integration**: Connect to Slack, email, or SOAR platforms for alerts.
- **Dashboard**: Build a web UI with Flask/Dash for interactive exploration.

---

Happy learning!
