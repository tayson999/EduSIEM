"""
STEP-BY-STEP TEACHING GUIDE: LOG ANALYSIS & LIGHTWEIGHT SIEM
=============================================================

This guide walks through the SIEM project from beginner to advanced concepts.

PART 1: UNDERSTANDING THE PROJECT
==================================

What is SIEM?
  SIEM = Security Information and Event Management
  - Collect logs from multiple sources (servers, apps, firewalls)
  - Parse and normalize data
  - Detect anomalies and suspicious patterns
  - Generate alerts for security teams
  
Real-world use:
  - Company receives 10 million log entries per day
  - SIEM parses them, finds 100 anomalies
  - Alerts team to 5 critical threats
  - Team investigates and blocks attackers

Our project:
  - Parse Apache & SSH logs
  - Detect brute-force attacks, unusual traffic patterns
  - Alert with severity levels
  - Output reports in JSON/CSV


PART 2: THE PIPELINE (5 PHASES)
================================

Phase 1: LOG PARSING
  Goal: Convert raw, unstructured text into structured data
  
  Example input:
    192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234
  
  Example output (as dict):
    {
      'source_ip': '192.168.1.10',
      'timestamp': datetime(2025, 12, 5, 14, 32, 10),
      'method': 'GET',
      'path': '/index.html',
      'status': 200,
      'bytes_sent': 1234
    }
  
  Key technique: Regular expressions (regex)
    - Pattern: r'(?P<ip>[\d.]+)' matches an IP address
    - Extracts the IP into named group 'ip'
    - Parser does this for all fields
  
  Files involved:
    - parsers.py: LogParser, ApacheAccessLogParser, SSHAuthLogParser
  
  Learn this to:
    - Extract data from any log format
    - Build custom parsers for your environment
    - Handle edge cases (malformed lines, timezones)


Phase 2: TIME-SERIES AGGREGATION
  Goal: Group raw events into time buckets for analysis
  
  Example:
    Raw events: 1000 login attempts in 1 hour from IP 192.168.1.10
    Aggregated (5-min buckets):
      14:00-14:05: 120 logins
      14:05-14:10: 105 logins
      14:10-14:15: 110 logins
      ...
  
  Why?
    - Raw logs are noisy; patterns emerge in aggregation
    - Can compute statistics: mean, std dev, percentiles
    - Easier to detect anomalies
  
  Files involved:
    - anomaly_detector.py: TimeSeriesAggregator class
  
  Learn this to:
    - Group data by time windows (5-min, 1-hour)
    - Calculate rolling averages and trends
    - Understand baseline vs anomaly


Phase 3: ANOMALY DETECTION
  Goal: Find unusual events
  
  Three methods:
  
  A) STATISTICAL (z-score):
     Formula: z_score = (value - mean) / std_dev
     Rule: Flag if |z_score| > 3 (i.e., >3 std devs from mean)
     
     Example:
       - Normal logins: 100-110 per 5 min (mean=105, std=3)
       - Spike: 500 logins in one 5-min bucket
       - z_score = (500 - 105) / 3 = 131.7
       - Alert: ANOMALY!
     
     Pros: Fast, interpretable
     Cons: Assumes normal distribution
  
  B) MACHINE LEARNING (Isolation Forest):
     Algorithm: Randomly splits data to "isolate" points
     Outliers isolate faster = flagged as anomalies
     
     Pros: Works with multivariate data, no assumptions
     Cons: Harder to interpret, needs tuning
     
     Features we use:
       - event_count: number of events
       - hour_of_day: 0-23 (when did it happen?)
       - day_of_week: 0-6 (Monday-Sunday)
       
     Why features? Pattern: "3am spike on Sunday" is normal
                           "3am spike on Tuesday" is suspicious
  
  C) RULE-BASED:
     Hand-written rules based on domain knowledge
     
     Example rule: "Brute-force SSH"
       - Source IP has > 10 failed logins in 5 minutes
       - Action: Alert with CRITICAL severity
     
     Pros: Explainable, tuned to your environment
     Cons: Requires expertise, needs maintenance
  
  Files involved:
    - anomaly_detector.py: StatisticalAnomalyDetector,
                           MLAnomalyDetector,
                           RuleBasedDetector
  
  Learn this to:
    - Apply multiple detection strategies
    - Tune detection sensitivity
    - Combine methods for better results


Phase 4: ALERT GENERATION
  Goal: Create actionable alerts with context
  
  Alert structure:
    {
      'alert_id': 'ALERT_000001',
      'alert_type': 'brute_force_login',
      'severity': 'CRITICAL',
      'timestamp': datetime(...),
      'details': {
        'source_ip': '192.168.1.100',
        'failed_attempts': 47,
        'threshold': 10
      },
      'context': {
        'recommendation': 'Block IP at firewall',
        'previous_incidents': 3
      }
    }
  
  Severity levels:
    - INFO: Normal but notable (e.g., user password reset)
    - WARNING: Suspicious, needs review (e.g., policy violation)
    - CRITICAL: Immediate threat (e.g., brute-force attack)
  
  Deduplication:
    - Problem: Same attack triggers 1000 alerts (alert storm)
    - Solution: Deduplicate within 5-min window
    - Result: 1 alert instead of 1000
  
  Files involved:
    - alerting.py: Alert, AlertManager, AlertFormatter
  
  Learn this to:
    - Prioritize alerts for triage
    - Avoid alert fatigue
    - Communicate risks clearly


Phase 5: REPORTING & OUTPUT
  Goal: Present findings to humans
  
  Output formats:
    - TEXT: Human-readable console output
    - JSON: Machine-readable, easy to parse
    - CSV: Excel-friendly for analysis
    - SLACK: Direct notifications
  
  Example JSON alert:
    [
      {
        "alert_id": "ALERT_000001",
        "alert_type": "brute_force_login",
        "severity": "CRITICAL",
        "timestamp": "2025-12-05T14:32:10",
        ...
      }
    ]
  
  Files involved:
    - alerting.py: AlertFormatter class
  
  Learn this to:
    - Export data for downstream analysis
    - Integrate with incident response workflows
    - Create audit trails


PART 3: HANDS-ON EXAMPLES
==========================

Example 1: Parse a Single Log Line
---

from parsers import ApacheAccessLogParser

line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234'
parser = ApacheAccessLogParser()
result = parser.parse(line)

print(result)
# Output:
# {
#   'source_ip': '192.168.1.10',
#   'timestamp': datetime(2025, 12, 5, 14, 32, 10),
#   'method': 'GET',
#   'path': '/index.html',
#   'status': 200,
#   ...
# }

Key takeaway: Regex + string matching = structured data


Example 2: Detect Statistical Anomalies
---

import pandas as pd
from anomaly_detector import StatisticalAnomalyDetector

# Create sample data: mostly 5 events, one spike of 50
data = {
    'timestamp': pd.date_range('2025-12-05', periods=10, freq='5min'),
    'event_count': [5, 5, 5, 5, 50, 5, 5, 5, 5, 5],  # Spike at index 4
    'source_ip': '192.168.1.10'
}
df = pd.DataFrame(data)

# Detect anomalies
detector = StatisticalAnomalyDetector(df, method='zscore', threshold=3)
result = detector.detect()

# Look at anomalies
print(result[result['is_anomaly']])
# Shows: index 4 flagged with z_score=9.8 (spike of 50 vs normal 5)

Key takeaway: z-score captures deviation from baseline


Example 3: Detect Brute-Force Attack
---

import pandas as pd
from anomaly_detector import RuleBasedDetector

# SSH logs with brute-force attempt
logs = pd.DataFrame({
    'timestamp': pd.date_range('2025-12-05 14:00', periods=15, freq='1min'),
    'source_ip': ['192.168.1.100'] * 12 + ['192.168.1.20'] * 3,
    'action': ['failed_login'] * 12 + ['accepted_login'] * 3,
    'user': 'admin',
    'port': range(54321, 54336)
})

# Apply rule: >10 failed logins in 5 min = brute-force
detector = RuleBasedDetector(logs)
alerts = detector.detect_brute_force(window_minutes=5)

for alert in alerts:
    print(f"[{alert['severity']}] {alert['description']}")
    # Output: [CRITICAL] Detected 12 failed logins from 192.168.1.100 in 5 min

Key takeaway: Simple thresholds work well for domain-specific attacks


Example 4: Generate Alerts
---

from alerting import Alert, AlertManager, Severity, AlertFormatter
from datetime import datetime

# Create alert manager
manager = AlertManager()

# Add an alert
alert = manager.add_alert(
    alert_type='brute_force_login',
    severity=Severity.CRITICAL,
    timestamp=datetime.now(),
    details={
        'source_ip': '192.168.1.100',
        'failed_attempts': 47,
        'threshold': 10
    },
    context={'recommendation': 'Block IP'}
)

# Format for email
formatter = AlertFormatter()
email_text = formatter.format_email(manager.alerts)
print(email_text)
# Output: [CRITICAL] BRUTE FORCE LOGIN
#         Source IP: 192.168.1.100
#         Failed Attempts: 47
#         ...

Key takeaway: Alerts bridge data analysis and human action


PART 4: EXTENDING THE PROJECT
==============================

Ideas to implement:
  
  1. REAL-TIME STREAMING
     - Use Kafka or Redis to ingest logs live
     - Process with Spark Streaming or Flink
     - Alert within seconds
  
  2. MACHINE LEARNING MODELS
     - Train classifier to predict attack type
     - Use features from log data
     - Deploy as microservice
  
  3. WEB DASHBOARD
     - Flask/Dash UI to explore logs
     - Real-time charts and alerts
     - User investigation interface
  
  4. THREAT INTELLIGENCE
     - Query IP reputation databases
     - Cross-correlate with known threats
     - Enrich alerts with external data
  
  5. INCIDENT RESPONSE AUTOMATION
     - Auto-block malicious IPs
     - Isolate compromised servers
     - Trigger incident ticket creation
  
  6. COMPLIANCE REPORTING
     - Generate SOC 2, PCI-DSS reports
     - Audit trail of all events
     - Retention policies


PART 5: BEST PRACTICES
======================

Security:
  ✓ Sanitize log inputs (avoid injection attacks)
  ✓ Encrypt stored alerts and logs
  ✓ Restrict access to SIEM data
  ✓ Use TLS for log transmission
  
Performance:
  ✓ Index large log datasets
  ✓ Use time-based retention (e.g., 30 days)
  ✓ Batch process, don't analyze live
  ✓ Use efficient data structures (pandas, NumPy)
  
Usability:
  ✓ Make alerts actionable (include remediation steps)
  ✓ Adjust thresholds based on false positives
  ✓ Use color/icons for severity
  ✓ Provide historical context
  
Testing:
  ✓ Unit test each component
  ✓ Use realistic log samples
  ✓ Simulate attacks to validate detection
  ✓ Monitor false positives vs true positives


NEXT STEPS
==========

1. Run the project:
   cd siem_project
   pip install -r requirements.txt
   python siem_engine.py

2. Explore the code:
   - Read parsers.py to understand regex patterns
   - Study anomaly_detector.py for detection logic
   - Review alerting.py for alert lifecycle

3. Modify and experiment:
   - Change thresholds in config.yaml
   - Add new log source (Windows, firewall)
   - Write custom detection rules
   - Create visualization of alerts

4. Learn related topics:
   - Time-series forecasting (predict next 1000 logins)
   - Machine learning (random forest classifier)
   - Database optimization (indexing, query tuning)
   - Distributed systems (scale to 1 billion logs/day)

5. Build toward production:
   - Add database (PostgreSQL, Elasticsearch)
   - Implement message queue (RabbitMQ, Kafka)
   - Deploy with Docker/Kubernetes
   - Set up monitoring & alerting for SIEM itself

Good luck learning!
"""

if __name__ == "__main__":
    print(__doc__)
