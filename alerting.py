"""
PHASE 4: ALERTING MODULE
========================
Generate, format, and output alerts from detected anomalies.

Key Concepts:
- Severity classification (INFO, WARNING, CRITICAL).
- Alert enrichment (add context, recommendations).
- Output formats (text, JSON, CSV).
- Deduplication (avoid alert storms).
"""

import json
import csv
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    """Alert severity levels."""
    INFO = 1
    WARNING = 2
    CRITICAL = 3
    
    def __str__(self):
        return self.name


class Alert:
    """
    Represents a single security alert.
    
    Attributes:
        alert_id: Unique identifier
        alert_type: Type of alert (brute_force, port_scan, etc.)
        severity: Severity level
        timestamp: When the alert was generated
        details: Dictionary with alert-specific details
        context: Additional context (IP reputation, similar past events, etc.)
    """
    
    _counter = 0  # Simple counter for alert IDs
    
    def __init__(
        self,
        alert_type: str,
        severity: Severity,
        timestamp: datetime,
        details: Dict,
        context: Optional[Dict] = None
    ):
        Alert._counter += 1
        self.alert_id = f"ALERT_{Alert._counter:06d}"
        self.alert_type = alert_type
        self.severity = severity
        self.timestamp = timestamp
        self.details = details
        self.context = context or {}
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': str(self.severity),
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'context': self.context,
        }
    
    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_text(self) -> str:
        """Convert alert to human-readable text format."""
        lines = [
            f"[{self.severity}] {self.alert_type.upper().replace('_', ' ')}",
            f"  Alert ID: {self.alert_id}",
            f"  Time: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        
        for key, value in self.details.items():
            lines.append(f"  {key.replace('_', ' ').title()}: {value}")
        
        if self.context:
            lines.append("  Context:")
            for key, value in self.context.items():
                lines.append(f"    - {key}: {value}")
        
        return '\n'.join(lines)
    
    def __repr__(self):
        return f"Alert({self.alert_id}, {self.alert_type}, {self.severity})"


class AlertManager:
    """
    Manage alert generation, deduplication, and output.
    
    Features:
    - Severity-based filtering
    - Alert deduplication (avoid duplicates within time window)
    - Multiple output formats
    - Alert statistics
    """
    
    def __init__(self, dedup_window_seconds: int = 300):
        """
        Args:
            dedup_window_seconds: Deduplication window (ignore alerts of same type
                                  from same IP within this window).
        """
        self.alerts: List[Alert] = []
        self.dedup_window_seconds = dedup_window_seconds
    
    def add_alert(
        self,
        alert_type: str,
        severity: Severity,
        timestamp: datetime,
        details: Dict,
        context: Optional[Dict] = None
    ) -> Optional[Alert]:
        """
        Add a new alert, checking for duplicates.
        
        Returns:
            Alert object if added, None if filtered as duplicate.
        """
        # Check for duplicates
        if self._is_duplicate(alert_type, details.get('source_ip'), timestamp):
            return None
        
        alert = Alert(alert_type, severity, timestamp, details, context)
        self.alerts.append(alert)
        return alert
    
    def _is_duplicate(self, alert_type: str, source_ip: Optional[str], timestamp: datetime) -> bool:
        """Check if similar alert was recently generated."""
        time_threshold = datetime.now()
        
        # This is simplified; in production, you'd use a proper deduplication key
        for existing_alert in reversed(self.alerts[-100:]):  # Check last 100 alerts
            if existing_alert.alert_type == alert_type and \
               existing_alert.details.get('source_ip') == source_ip:
                time_diff = (timestamp - existing_alert.timestamp).total_seconds()
                if time_diff < self.dedup_window_seconds:
                    return True
        
        return False
    
    def filter_by_severity(self, min_severity: Severity) -> List[Alert]:
        """Get alerts with severity >= min_severity."""
        return [a for a in self.alerts if a.severity.value >= min_severity.value]
    
    def get_stats(self) -> Dict:
        """Get alert statistics."""
        severity_counts = {}
        for alert in self.alerts:
            sev = str(alert.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': severity_counts,
            'by_type': {}  # TODO: add count by alert type
        }


class AlertFormatter:
    """Format alerts for different output channels."""
    
    @staticmethod
    def format_email(alerts: List[Alert], recipient: str = "security@example.com") -> str:
        """Format alerts for email delivery."""
        if not alerts:
            return ""
        
        lines = [
            f"Security Alert Summary ({len(alerts)} alert{'s' if len(alerts) != 1 else ''})",
            "=" * 50,
            ""
        ]
        
        # Group by severity
        by_severity = {}
        for alert in alerts:
            sev = str(alert.severity)
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(alert)
        
        # Output high severity first
        for severity in ['CRITICAL', 'WARNING', 'INFO']:
            if severity in by_severity:
                lines.append(f"\n{severity} ({len(by_severity[severity])}):")
                lines.append("-" * 30)
                for alert in by_severity[severity]:
                    lines.append(alert.to_text())
                    lines.append("")
        
        lines.append("\nEnd of Report")
        return '\n'.join(lines)
    
    @staticmethod
    def format_csv(alerts: List[Alert], filepath: str = None) -> str:
        """Format alerts as CSV."""
        if not alerts:
            return ""
        
        # Flatten alerts to CSV rows
        rows = []
        for alert in alerts:
            row = {
                'alert_id': alert.alert_id,
                'alert_type': alert.alert_type,
                'severity': str(alert.severity),
                'timestamp': alert.timestamp.isoformat(),
            }
            # Add details as separate columns
            row.update({f"detail_{k}": v for k, v in alert.details.items()})
            rows.append(row)
        
        if not rows:
            return ""
        
        # Get all unique keys
        keys = set()
        for row in rows:
            keys.update(row.keys())
        keys = sorted(keys)
        
        # Format as CSV
        lines = [','.join(keys)]
        for row in rows:
            values = [str(row.get(k, '')) for k in keys]
            lines.append(','.join(values))
        
        csv_text = '\n'.join(lines)
        
        if filepath:
            with open(filepath, 'w', newline='') as f:
                f.write(csv_text)
        
        return csv_text
    
    @staticmethod
    def format_json(alerts: List[Alert]) -> str:
        """Format alerts as JSON."""
        return json.dumps([a.to_dict() for a in alerts], indent=2)
    
    @staticmethod
    def format_slack(alerts: List[Alert]) -> Dict:
        """
        Format alerts for Slack webhook.
        
        Returns:
            Dictionary ready for json.dumps() and POST to Slack webhook URL.
        """
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Security Alert Summary* ({len(alerts)} alert{'s' if len(alerts) != 1 else ''})"
                }
            },
            {"type": "divider"}
        ]
        
        for alert in alerts[:10]:  # Limit to 10 alerts per message
            color_map = {'INFO': '#36a64f', 'WARNING': '#ff9900', 'CRITICAL': '#ff0000'}
            color = color_map.get(str(alert.severity), '#cccccc')
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*[{alert.severity}]* {alert.alert_type}\n{alert.to_text()}"
                }
            })
        
        return {
            "blocks": blocks,
            "text": f"SIEM Alert: {len(alerts)} new alerts"
        }


class SimpleNotifier:
    """Simple in-memory notification system."""
    
    def __init__(self):
        self.notifications = []
    
    def notify(self, message: str, channel: str = 'default'):
        """Add a notification."""
        self.notifications.append({
            'timestamp': datetime.now(),
            'channel': channel,
            'message': message
        })
        print(f"[{channel.upper()}] {message}")
    
    def get_notifications(self) -> List[Dict]:
        """Retrieve all notifications."""
        return self.notifications


if __name__ == "__main__":
    # Example: Create and format alerts
    print("=== Alert Generation Example ===\n")
    
    manager = AlertManager()
    
    # Add sample alerts
    manager.add_alert(
        alert_type='brute_force_login',
        severity=Severity.CRITICAL,
        timestamp=datetime.now(),
        details={
            'source_ip': '192.168.1.100',
            'failed_attempts': 47,
            'threshold': 10,
            'target_service': 'SSH'
        },
        context={
            'ip_reputation': 'Malicious (known botnet)',
            'previous_incidents': 3,
            'recommended_action': 'Block IP at firewall'
        }
    )
    
    manager.add_alert(
        alert_type='port_scan',
        severity=Severity.HIGH,
        timestamp=datetime.now(),
        details={
            'source_ip': '192.168.1.50',
            'unique_ports': 128,
            'protocol': 'TCP',
            'target_host': '10.0.0.5'
        }
    )
    
    # Format and output
    print("Text Format:")
    print(manager.alerts[0].to_text())
    print("\n" + "="*50 + "\n")
    
    print("JSON Format:")
    print(manager.alerts[0].to_json())
    print("\n" + "="*50 + "\n")
    
    print("Email Format:")
    formatter = AlertFormatter()
    print(formatter.format_email(manager.alerts))
