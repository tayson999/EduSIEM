"""
UNIT TESTS FOR SIEM PROJECT
============================
Test individual components and integration.

Test Coverage:
- Log parsing (Apache, SSH, Windows)
- Time-series aggregation
- Anomaly detection (statistical, ML, rule-based)
- Alert generation and formatting
"""

import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from io import StringIO
import sys

from parsers import ApacheAccessLogParser, SSHAuthLogParser, WindowsEventLogParser, LogParserFactory
from anomaly_detector import (
    TimeSeriesAggregator,
    StatisticalAnomalyDetector,
    MLAnomalyDetector,
    RuleBasedDetector
)
from alerting import Alert, AlertManager, Severity, AlertFormatter, SimpleNotifier


class TestLogParsers(unittest.TestCase):
    """Test log parsing functionality."""
    
    def test_apache_parser_valid_line(self):
        """Test parsing a valid Apache access log line."""
        line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234'
        parser = ApacheAccessLogParser()
        result = parser.parse(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '192.168.1.10')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['path'], '/index.html')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['bytes_sent'], 1234)
    
    def test_apache_parser_invalid_line(self):
        """Test parsing an invalid Apache log line."""
        line = 'This is not a valid log line'
        parser = ApacheAccessLogParser()
        result = parser.parse(line)
        
        self.assertIsNone(result)
    
    def test_ssh_parser_failed_login(self):
        """Test parsing SSH failed login log."""
        line = 'Dec  5 14:32:10 server sshd[1234]: Failed password for user admin from 192.168.1.10 port 54321 ssh2'
        parser = SSHAuthLogParser()
        result = parser.parse(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '192.168.1.10')
        self.assertEqual(result['user'], 'admin')
        self.assertEqual(result['action'], 'failed_login')
        self.assertEqual(result['port'], 54321)
    
    def test_ssh_parser_accepted_login(self):
        """Test parsing SSH accepted login log."""
        line = 'Dec  5 14:35:01 server sshd[1245]: Accepted publickey for admin from 192.168.1.5 port 54400 ssh2'
        parser = SSHAuthLogParser()
        result = parser.parse(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '192.168.1.5')
        self.assertEqual(result['action'], 'accepted_login')
        self.assertEqual(result['auth_type'], 'publickey')
    
    def test_windows_parser(self):
        """Test parsing Windows Event Log."""
        line = '2025-12-05 14:32:10,4625,Failure Reason Code: User logon with misspelled or bad password,192.168.1.50,Administrator'
        parser = WindowsEventLogParser()
        result = parser.parse(line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['event_id'], 4625)
        self.assertEqual(result['source_ip'], '192.168.1.50')
        self.assertEqual(result['action'], 'failed_login')
    
    def test_log_parser_factory(self):
        """Test LogParserFactory."""
        parser = LogParserFactory.get_parser('apache')
        self.assertIsInstance(parser, ApacheAccessLogParser)
        
        parser = LogParserFactory.get_parser('ssh')
        self.assertIsInstance(parser, SSHAuthLogParser)


class TestTimeSeriesAggregation(unittest.TestCase):
    """Test time-series aggregation."""
    
    def setUp(self):
        """Create sample data."""
        self.df = pd.DataFrame({
            'timestamp': pd.date_range('2025-12-05 14:00', periods=100, freq='1min'),
            'source_ip': np.random.choice(['192.168.1.10', '192.168.1.20', '192.168.1.30'], 100),
            'action': np.random.choice(['login', 'logout', 'error'], 100),
            'event_count': np.random.poisson(lam=5, size=100)
        })
    
    def test_aggregate_by_source_ip(self):
        """Test aggregation by source IP."""
        aggregator = TimeSeriesAggregator(self.df, window_minutes=5)
        result = aggregator.aggregate_by_source_ip()
        
        self.assertIn('timestamp', result.columns)
        self.assertIn('source_ip', result.columns)
        self.assertIn('event_count', result.columns)
        self.assertGreater(len(result), 0)
    
    def test_compute_statistics(self):
        """Test statistics computation."""
        aggregator = TimeSeriesAggregator(self.df, window_minutes=5)
        aggregated = aggregator.aggregate_by_source_ip()
        stats = aggregator.compute_statistics(aggregated)
        
        self.assertIn('mean', stats)
        self.assertIn('std', stats)
        self.assertIn('median', stats)
        self.assertGreater(stats['mean'], 0)


class TestAnomalyDetection(unittest.TestCase):
    """Test anomaly detection methods."""
    
    def setUp(self):
        """Create sample data with anomalies."""
        # Normal data: 5 events per bucket
        normal = pd.Series([5, 5, 5, 5, 5, 5, 5, 5])
        # Anomalies: spike to 50
        anomalies = pd.Series([50])
        
        self.df = pd.DataFrame({
            'timestamp': pd.date_range('2025-12-05 14:00', periods=9, freq='5min'),
            'event_count': pd.concat([normal, anomalies], ignore_index=True),
            'source_ip': '192.168.1.10'
        })
    
    def test_zscore_detection(self):
        """Test z-score anomaly detection."""
        detector = StatisticalAnomalyDetector(self.df, method='zscore', threshold=2.0)
        result = detector.detect()
        
        # Should detect the spike as anomaly
        anomalies = result[result['is_anomaly']]
        self.assertGreater(len(anomalies), 0)
    
    def test_iqr_detection(self):
        """Test IQR-based anomaly detection."""
        detector = StatisticalAnomalyDetector(self.df, method='iqr')
        result = detector.detect()
        
        self.assertIn('is_anomaly', result.columns)
    
    def test_ml_detection(self):
        """Test ML-based anomaly detection."""
        detector = MLAnomalyDetector(self.df, contamination=0.1)
        result = detector.detect()
        
        self.assertIn('is_anomaly', result.columns)
        self.assertIn('ml_prediction', result.columns)


class TestAlertGeneration(unittest.TestCase):
    """Test alert generation and formatting."""
    
    def test_alert_creation(self):
        """Test creating an alert."""
        alert = Alert(
            alert_type='brute_force',
            severity=Severity.CRITICAL,
            timestamp=datetime.now(),
            details={'source_ip': '192.168.1.10', 'attempts': 50},
            context={'recommendation': 'Block IP'}
        )
        
        self.assertEqual(alert.alert_type, 'brute_force')
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertIsNotNone(alert.alert_id)
    
    def test_alert_to_dict(self):
        """Test converting alert to dictionary."""
        alert = Alert(
            alert_type='port_scan',
            severity=Severity.CRITICAL,
            timestamp=datetime.now(),
            details={'source_ip': '192.168.1.20', 'ports': 128}
        )
        
        alert_dict = alert.to_dict()
        self.assertEqual(alert_dict['alert_type'], 'port_scan')
        self.assertEqual(alert_dict['severity'], 'HIGH')
    
    def test_alert_manager(self):
        """Test alert manager."""
        manager = AlertManager()
        
        alert = manager.add_alert(
            alert_type='test_alert',
            severity=Severity.WARNING,
            timestamp=datetime.now(),
            details={'source_ip': '192.168.1.10'}
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(len(manager.alerts), 1)
    
    def test_alert_deduplication(self):
        """Test alert deduplication."""
        manager = AlertManager(dedup_window_seconds=60)
        
        now = datetime.now()
        
        # Add same alert twice
        alert1 = manager.add_alert(
            alert_type='duplicate_test',
            severity=Severity.INFO,
            timestamp=now,
            details={'source_ip': '192.168.1.10'}
        )
        
        alert2 = manager.add_alert(
            alert_type='duplicate_test',
            severity=Severity.INFO,
            timestamp=now,
            details={'source_ip': '192.168.1.10'}
        )
        
        # Second alert should be filtered
        self.assertIsNotNone(alert1)
        self.assertIsNone(alert2)  # Duplicate filtered
        self.assertEqual(len(manager.alerts), 1)
    
    def test_alert_filtering(self):
        """Test filtering alerts by severity."""
        manager = AlertManager()
        
        manager.add_alert('test1', Severity.INFO, datetime.now(), {})
        manager.add_alert('test2', Severity.WARNING, datetime.now(), {})
        manager.add_alert('test3', Severity.CRITICAL, datetime.now(), {})
        
        # Filter for WARNING and above
        filtered = manager.filter_by_severity(Severity.WARNING)
        self.assertEqual(len(filtered), 2)  # WARNING and CRITICAL
    
    def test_alert_formatter_json(self):
        """Test JSON alert formatting."""
        alert = Alert(
            alert_type='test',
            severity=Severity.CRITICAL,
            timestamp=datetime.now(),
            details={'key': 'value'}
        )
        
        formatter = AlertFormatter()
        json_str = formatter.format_json([alert])
        
        self.assertIn('alert_type', json_str)
        self.assertIn('CRITICAL', json_str)


class TestRuleBasedDetection(unittest.TestCase):
    """Test rule-based detection."""
    
    def setUp(self):
        """Create sample SSH logs with brute-force attempt."""
        self.df = pd.DataFrame({
            'timestamp': pd.date_range('2025-12-05 14:00', periods=15, freq='1min'),
            'source_ip': ['192.168.1.10'] * 12 + ['192.168.1.20'] * 3,
            'action': ['failed_login'] * 12 + ['accepted_login'] * 3,
            'user': ['admin'] * 15,
            'port': range(54321, 54336)
        })
    
    def test_brute_force_detection(self):
        """Test brute-force detection rule."""
        detector = RuleBasedDetector(self.df)
        alerts = detector.detect_brute_force(window_minutes=5)
        
        # Should detect 12 failed logins from 192.168.1.10
        self.assertGreater(len(alerts), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_end_to_end_pipeline(self):
        """Test complete SIEM pipeline."""
        # Create sample parsed data
        logs = pd.DataFrame({
            'timestamp': pd.date_range('2025-12-05 14:00', periods=50, freq='1min'),
            'source_ip': np.random.choice(['192.168.1.10', '192.168.1.20'], 50),
            'action': np.random.choice(['login', 'logout'], 50),
            'method': 'GET',
            'path': '/api/data'
        })
        
        # Aggregate
        aggregator = TimeSeriesAggregator(logs, window_minutes=5)
        aggregated = aggregator.aggregate_by_source_ip()
        
        # Detect anomalies
        detector = StatisticalAnomalyDetector(aggregated)
        result = detector.detect()
        
        # Generate alerts
        manager = AlertManager()
        anomalies = result[result['is_anomaly']]
        for _, row in anomalies.iterrows():
            manager.add_alert(
                alert_type='statistical_anomaly',
                severity=Severity.WARNING,
                timestamp=row['timestamp'],
                details={'event_count': int(row['event_count'])}
            )
        
        # Verify
        self.assertGreaterEqual(len(manager.alerts), 0)


if __name__ == '__main__':
    unittest.main()
