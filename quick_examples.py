"""
QUICK START: HANDS-ON SIEM EXAMPLES
====================================

Run this file to see practical examples.
"""

print("=" * 70)
print("PART 1: LOG PARSING EXAMPLE")
print("=" * 70 + "\n")

from parsers import ApacheAccessLogParser, SSHAuthLogParser

# Example 1: Parse Apache access log
print("Parsing Apache log line...")
apache_line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234'
apache_parser = ApacheAccessLogParser()
apache_result = apache_parser.parse(apache_line)

print(f"Input:  {apache_line}")
print(f"Output: {apache_result}\n")

# Example 2: Parse SSH log
print("Parsing SSH authentication log...")
ssh_line = 'Dec  5 14:32:10 server sshd[1234]: Failed password for user admin from 192.168.1.10 port 54321 ssh2'
ssh_parser = SSHAuthLogParser()
ssh_result = ssh_parser.parse(ssh_line)

print(f"Input:  {ssh_line}")
print(f"Output: {ssh_result}\n")

print("=" * 70)
print("PART 2: ANOMALY DETECTION EXAMPLE")
print("=" * 70 + "\n")

import pandas as pd
from anomaly_detector import StatisticalAnomalyDetector, RuleBasedDetector

# Create sample data with a spike
print("Creating sample time-series data (5-event baseline + 1 spike)...")
data = {
    'timestamp': pd.date_range('2025-12-05 14:00', periods=10, freq='5min'),
    'event_count': [5, 5, 5, 5, 50, 5, 5, 5, 5, 5],  # Spike at index 4
    'source_ip': '192.168.1.10',
    'action': 'login'
}
df = pd.DataFrame(data)

print(f"\nData:\n{df}\n")

# Detect anomalies using z-score
print("Detecting anomalies (z-score method)...")
detector = StatisticalAnomalyDetector(df, method='zscore', threshold=3)
result = detector.detect()

anomalies = result[result['is_anomaly']]
print(f"\nFound {len(anomalies)} anomalies:")
print(anomalies[['timestamp', 'event_count', 'z_score']].to_string())
print()

# Rule-based detection example
print("=" * 70)
print("PART 3: BRUTE-FORCE ATTACK DETECTION")
print("=" * 70 + "\n")

print("Creating SSH logs with brute-force attempt...")
ssh_logs = pd.DataFrame({
    'timestamp': pd.date_range('2025-12-05 14:00', periods=15, freq='1min'),
    'source_ip': ['192.168.1.100'] * 12 + ['192.168.1.20'] * 3,
    'action': ['failed_login'] * 12 + ['accepted_login'] * 3,
    'user': 'admin',
    'port': range(54321, 54336)
})

print(f"Logs (showing first 5):\n{ssh_logs.head()}\n")

# Detect brute-force
print("Checking for brute-force attacks (threshold: >10 failed logins in 5 min)...")
rule_detector = RuleBasedDetector(ssh_logs)
alerts = rule_detector.detect_brute_force(window_minutes=5)

if alerts:
    print(f"\nFound {len(alerts)} alert(s):")
    for alert in alerts:
        print(f"\n  Alert Type: {alert['alert_type']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Source IP: {alert['source_ip']}")
        print(f"  Failed Attempts: {alert['event_count']}")
        print(f"  Description: {alert['description']}")
else:
    print("\nNo brute-force attacks detected.")

print("\n" + "=" * 70)
print("PART 4: ALERT GENERATION")
print("=" * 70 + "\n")

from alerting import Alert, AlertManager, Severity, AlertFormatter
from datetime import datetime

# Create alert manager
manager = AlertManager()

print("Creating sample alerts...")

# Add critical alert
manager.add_alert(
    alert_type='brute_force_login',
    severity=Severity.CRITICAL,
    timestamp=datetime.now(),
    details={
        'source_ip': '192.168.1.100',
        'failed_attempts': 47,
        'threshold': 10
    },
    context={
        'recommendation': 'Block IP at firewall immediately',
        'previous_incidents': 3
    }
)

# Add warning alert
manager.add_alert(
    alert_type='unusual_traffic_pattern',
    severity=Severity.WARNING,
    timestamp=datetime.now(),
    details={
        'source_ip': '192.168.1.50',
        'event_count': 200,
        'baseline': 50,
        'deviation': '300%'
    },
    context={
        'recommendation': 'Review user activity'
    }
)

print(f"Created {len(manager.alerts)} alerts\n")

# Display alerts in text format
formatter = AlertFormatter()
email_format = formatter.format_email(manager.alerts)
print("Formatted for email:")
print("-" * 70)
print(email_format)
print("-" * 70)
print()

# Display JSON format
print("\nJSON format:")
print("-" * 70)
json_format = formatter.format_json(manager.alerts)
print(json_format)
print("-" * 70)

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
You've seen:
1. LOG PARSING: Converting raw text to structured data
2. ANOMALY DETECTION: Finding unusual patterns with statistics
3. RULE-BASED DETECTION: Identifying known attack signatures
4. ALERTING: Generating actionable alerts

Next steps:
  1. Run: python siem_engine.py (full pipeline)
  2. Modify: Edit config.yaml to change thresholds
  3. Extend: Add new log sources or detection rules
  4. Explore: Read the code in parsers.py, anomaly_detector.py, alerting.py

For more details, read TEACHING_GUIDE.py
""")
