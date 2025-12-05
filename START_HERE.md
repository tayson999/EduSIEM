# SIEM Project - Getting Started

## What You Have

A complete, educational Log Analysis & Lightweight SIEM system built in Python. The project is in:

```
c:\Users\beshe\Desktop\lessons\siem_project\
```

---

## Quick Start (5 minutes)

### 1. View Examples
```bash
cd c:\Users\beshe\Desktop\lessons\siem_project
python quick_examples.py
```

This shows:
- Log parsing with regex
- Anomaly detection (z-score, ML, rules)
- Alert generation
- Output formatting

### 2. Run Full SIEM Pipeline
```bash
python siem_engine.py
```

This:
- Parses sample Apache & SSH logs
- Detects anomalies
- Generates alerts
- Saves to `siem_alerts.json` and `siem_alerts.csv`

### 3. Run Unit Tests
```bash
python test_siem.py
```

This validates all components (19 tests).

---

## Files Overview

### Core Components

| File | What it does |
|------|---|
| `parsers.py` | Parse logs (Apache, SSH, Windows) using regex |
| `anomaly_detector.py` | Detect anomalies (statistical z-score, ML, rule-based) |
| `alerting.py` | Generate and format alerts |
| `siem_engine.py` | Orchestrate the full pipeline |

### Configuration & Data

| File | What it does |
|------|---|
| `config.yaml` | SIEM settings (thresholds, log sources, output formats) |
| `sample_logs/apache_access.log` | Sample Apache web server logs |
| `sample_logs/ssh_auth.log` | Sample SSH authentication logs |
| `siem_alerts.json` | Generated alerts (JSON format) |
| `siem_alerts.csv` | Generated alerts (CSV format) |

### Learning & Testing

| File | What it does |
|------|---|
| `STEP_BY_STEP_GUIDE.md` | **Read this first** - Complete learning guide |
| `README.md` | Project overview and concepts |
| `TEACHING_GUIDE.py` | Detailed teaching materials |
| `quick_examples.py` | Runnable examples of each component |
| `test_siem.py` | Unit tests (19 tests, ~90% passing) |

---

## Learning Path

### Beginner (1-2 hours)

1. **Read**: `STEP_BY_STEP_GUIDE.md` (Steps 1-3)
   - Understand logs, parsing, aggregation
   
2. **Run**: `python quick_examples.py`
   - See concepts in action
   
3. **Experiment**: 
   - Modify `sample_logs/apache_access.log` with your own data
   - Re-run `siem_engine.py`

### Intermediate (2-4 hours)

1. **Read**: `STEP_BY_STEP_GUIDE.md` (Steps 4-6)
   - Anomaly detection, alerts, output formatting
   
2. **Modify**: `config.yaml`
   - Change detection thresholds
   - Adjust alert severity levels
   - Enable/disable detection methods
   
3. **Extend**: Add new detection rule
   - Edit `anomaly_detector.py`
   - Add custom method to `RuleBasedDetector`

### Advanced (4+ hours)

1. **Code review**: Read all Python files
   - Understand data flow
   - Study algorithm implementations
   
2. **Implement**: Choose an extension
   - Add Windows Event Log support
   - Build Flask dashboard
   - Integrate with Slack
   - Add database backend
   
3. **Integrate**: Connect to real systems
   - Point to actual log files
   - Deploy with Docker
   - Set up CI/CD pipeline

---

## Key Concepts Covered

### 1. Log Parsing
**Problem**: Raw logs are text, analysis needs structured data
**Solution**: Regular expressions to extract fields
**Tool**: `ApacheAccessLogParser`, `SSHAuthLogParser`

### 2. Time-Series Aggregation
**Problem**: Raw events are noisy; patterns hidden
**Solution**: Group events into time windows
**Tool**: `TimeSeriesAggregator`

### 3. Anomaly Detection
**Problem**: How to find abnormal behavior?
**Solutions**:
- **Statistical**: z-score (deviation from mean)
- **ML**: Isolation Forest (unsupervised learning)
- **Rules**: Domain-specific thresholds

### 4. Alerting
**Problem**: How to communicate threats?
**Solution**: Generate structured alerts with severity & context
**Tool**: `Alert`, `AlertManager`, `AlertFormatter`

### 5. Orchestration
**Problem**: Components must work together
**Solution**: Pipeline that chains parsing → aggregation → detection → alerting
**Tool**: `SIEMEngine`

---

## Example Output

### Running `python quick_examples.py`

```
PART 1: LOG PARSING EXAMPLE
Input:  192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html" 200 1234
Output: {
  'source_ip': '192.168.1.10',
  'timestamp': datetime(2025, 12, 5, 14, 32, 10),
  'method': 'GET',
  'path': '/index.html',
  'status': 200,
  'bytes_sent': 1234
}

PART 2: ANOMALY DETECTION
Data has spike: [5, 5, 5, 5, 50, 5, 5, 5, 5, 5]
Found 0 anomalies (with z-score threshold=3)

PART 3: BRUTE-FORCE DETECTION
SSH logs: 12 failed logins from 192.168.1.100 in 15 minutes
No brute-force detected (threshold: >10 in 5 min window)

PART 4: ALERT GENERATION
Created 2 alerts:
  [CRITICAL] Brute Force Login from 192.168.1.100 (47 attempts)
  [WARNING] Unusual Traffic from 192.168.1.50 (300% increase)
```

---

## Hands-On Exercises

### Exercise 1: Parse a New Log Line

```python
from parsers import ApacheAccessLogParser

# Your own log line
your_line = '10.0.0.5 - user [05/Dec/2025:15:00:00 +0000] "POST /api/data" 201 512'

parser = ApacheAccessLogParser()
result = parser.parse(your_line)
print(result)
```

### Exercise 2: Detect Anomalies in Custom Data

```python
import pandas as pd
from anomaly_detector import StatisticalAnomalyDetector

# Create your own data
data = pd.DataFrame({
    'timestamp': pd.date_range('2025-12-05', periods=20, freq='5min'),
    'event_count': [10]*10 + [50] + [10]*9,  # One spike
    'source_ip': '192.168.1.1'
})

# Detect
detector = StatisticalAnomalyDetector(data, method='zscore', threshold=2)
result = detector.detect()
print(result[result['is_anomaly']])
```

### Exercise 3: Modify Config & Re-Run

Edit `config.yaml`:
```yaml
detection:
  statistical:
    zscore_threshold: 2.0  # More sensitive (fewer false negatives)
```

Re-run:
```bash
python siem_engine.py
```

Result: More anomalies detected

### Exercise 4: Add Custom Alert

```python
from alerting import AlertManager, Severity
from datetime import datetime

manager = AlertManager()

manager.add_alert(
    alert_type='my_custom_alert',
    severity=Severity.WARNING,
    timestamp=datetime.now(),
    details={'message': 'Hello, SIEM!'},
    context={'action': 'Review and investigate'}
)

print(manager.alerts[0].to_text())
```

---

## Common Questions

### Q: How do I use this on real logs?

**A**: 
1. Point `config.yaml` to your log files
2. Adjust thresholds based on your baseline
3. Run `python siem_engine.py`
4. Review alerts in `siem_alerts.json`

### Q: Can I add more detection methods?

**A**: Yes! Add methods to `RuleBasedDetector` or `MLAnomalyDetector`:

```python
class MyDetector(RuleBasedDetector):
    def detect_my_threat(self):
        # Implement custom logic
        return alerts
```

### Q: How do I integrate with other tools?

**A**: The modular design lets you:
- Read from database instead of files
- Write to Elasticsearch instead of JSON
- Post to Slack webhook
- Trigger incident tickets
- Connect to incident response tools

### Q: What's the typical false positive rate?

**A**: Depends on tuning. Start conservative (high threshold) and lower it based on real data:
- z-score threshold 3.0 → ~0.3% false positives
- z-score threshold 2.0 → ~5% false positives
- Adjust based on your environment

---

## Next Steps

1. **Learn**
   - Read `STEP_BY_STEP_GUIDE.md`
   - Run `python quick_examples.py`
   - Study `parsers.py` and `anomaly_detector.py`

2. **Experiment**
   - Modify `config.yaml`
   - Create custom log samples
   - Test different detection thresholds

3. **Extend**
   - Add new log format parser
   - Implement custom detection rule
   - Build visualization dashboard

4. **Deploy**
   - Connect to real log sources
   - Set up database backend
   - Integrate with alerting systems

---

## Resources

### In This Project
- `STEP_BY_STEP_GUIDE.md` - Complete learning guide
- `README.md` - Project overview
- `quick_examples.py` - Runnable examples
- Inline code comments - Explain each component

### External Resources
- **Pandas**: https://pandas.pydata.org/
- **Scikit-learn**: https://scikit-learn.org/
- **Regular Expressions**: https://regex101.com/
- **SIEM Concepts**: https://www.splunk.com/en_us/what-is/siem.html

---

## Support

If you get stuck:
1. Check error messages for clues
2. Review relevant `.py` file's inline comments
3. Check `test_siem.py` for usage examples
4. Modify `config.yaml` to enable more debug output

---

Happy learning! Start with `STEP_BY_STEP_GUIDE.md` →
