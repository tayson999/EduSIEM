"""
MAIN SIEM ENGINE
================
Orchestrates all components: parsing, detection, and alerting.

Workflow:
1. Load config and initialize components
2. Parse log files using appropriate parsers
3. Aggregate events into time series
4. Run anomaly detection (statistical, ML, rule-based)
5. Generate alerts
6. Format and output alerts
7. Generate reports
"""

import os
import sys
import yaml
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# Import modules
from parsers import LogParserFactory
from anomaly_detector import (
    TimeSeriesAggregator,
    StatisticalAnomalyDetector,
    MLAnomalyDetector,
    RuleBasedDetector
)
from alerting import Alert, AlertManager, Severity, AlertFormatter, SimpleNotifier


class SIEMEngine:
    """Main SIEM orchestration engine."""
    
    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialize SIEM engine with config.
        
        Args:
            config_file: Path to YAML config file.
        """
        self.config = self._load_config(config_file)
        self.alert_manager = AlertManager(
            dedup_window_seconds=self.config['alerting'].get('dedup_window_seconds', 300)
        )
        self.notifier = SimpleNotifier()
        self.parsed_data: Dict[str, pd.DataFrame] = {}
        self.anomalies: Dict[str, pd.DataFrame] = {}
    
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file."""
        if not os.path.exists(config_file):
            print(f"Warning: Config file not found: {config_file}")
            print("Using default configuration.")
            return self._default_config()
        
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        return config if config else self._default_config()
    
    @staticmethod
    def _default_config() -> Dict:
        """Return default configuration."""
        return {
            'detection': {
                'statistical': {'enabled': True, 'method': 'zscore', 'zscore_threshold': 3.0, 'window_minutes': 5},
                'ml': {'enabled': True, 'contamination': 0.05},
                'rules': {'enabled': True}
            },
            'alerting': {
                'dedup_window_seconds': 300,
                'min_severity_to_report': 'WARNING',
                'output_formats': ['text', 'json'],
                'destinations': {'console': True, 'file': 'siem_alerts.json'}
            },
            'log_sources': {}
        }
    
    def parse_logs(self, log_file: str, log_type: str) -> Optional[pd.DataFrame]:
        """
        Parse a log file.
        
        Args:
            log_file: Path to log file.
            log_type: Type of log (apache, ssh, windows).
        
        Returns:
            DataFrame with parsed entries, or None if parsing fails.
        """
        if not os.path.exists(log_file):
            self.notifier.notify(f"Log file not found: {log_file}", "error")
            return None
        
        self.notifier.notify(f"Parsing {log_type} log: {log_file}")
        
        try:
            entries = LogParserFactory.parse_file(log_file, log_type)
            if not entries:
                self.notifier.notify(f"No entries parsed from {log_file}", "warning")
                return None
            
            df = pd.DataFrame(entries)
            self.notifier.notify(f"Parsed {len(df)} entries from {log_file}")
            return df
        except Exception as e:
            self.notifier.notify(f"Error parsing {log_file}: {str(e)}", "error")
            return None
    
    def run_statistical_detection(self, df: pd.DataFrame, name: str = "data") -> pd.DataFrame:
        """
        Run statistical anomaly detection.
        
        Args:
            df: DataFrame with parsed log entries.
            name: Name for this dataset (for logging).
        
        Returns:
            DataFrame with anomaly flags.
        """
        config = self.config['detection']['statistical']
        
        if not config.get('enabled', True):
            return None
        
        self.notifier.notify(f"Running statistical anomaly detection on {name}...")
        
        # Aggregate by source IP
        aggregator = TimeSeriesAggregator(df, window_minutes=config.get('window_minutes', 5))
        aggregated = aggregator.aggregate_by_source_ip()
        
        # Detect anomalies
        detector = StatisticalAnomalyDetector(
            aggregated,
            method=config.get('method', 'zscore'),
            threshold=config.get('zscore_threshold', 3.0)
        )
        result = detector.detect()
        
        anomalies = result[result['is_anomaly']]
        self.notifier.notify(f"Found {len(anomalies)} statistical anomalies")
        
        return result
    
    def run_ml_detection(self, df: pd.DataFrame, name: str = "data") -> pd.DataFrame:
        """Run ML-based anomaly detection."""
        config = self.config['detection']['ml']
        
        if not config.get('enabled', True):
            return None
        
        self.notifier.notify(f"Running ML anomaly detection on {name}...")
        
        # Aggregate by source IP
        aggregator = TimeSeriesAggregator(df, window_minutes=5)
        aggregated = aggregator.aggregate_by_source_ip()
        
        # Detect using Isolation Forest
        detector = MLAnomalyDetector(aggregated, contamination=config.get('contamination', 0.05))
        result = detector.detect()
        
        anomalies = result[result['is_anomaly']]
        self.notifier.notify(f"Found {len(anomalies)} ML anomalies")
        
        return result
    
    def run_rule_based_detection(self, df: pd.DataFrame, name: str = "data") -> List[Dict]:
        """Run rule-based detection."""
        config = self.config['detection']['rules']
        
        if not config.get('enabled', True):
            return []
        
        self.notifier.notify(f"Running rule-based detection on {name}...")
        
        detector = RuleBasedDetector(df, config)
        alerts = detector.detect_all()
        
        self.notifier.notify(f"Found {len(alerts)} rule-based alerts")
        
        return alerts
    
    def process_rule_alerts(self, rule_alerts: List[Dict]):
        """Convert rule-based alerts to Alert objects."""
        for alert_data in rule_alerts:
            severity_map = {
                'CRITICAL': Severity.CRITICAL,
                'HIGH': Severity.CRITICAL,
                'WARNING': Severity.WARNING,
                'INFO': Severity.INFO
            }
            
            severity = severity_map.get(alert_data.get('severity', 'INFO'), Severity.INFO)
            
            self.alert_manager.add_alert(
                alert_type=alert_data['alert_type'],
                severity=severity,
                timestamp=alert_data['timestamp'],
                details={k: v for k, v in alert_data.items() 
                        if k not in ['alert_type', 'severity', 'timestamp', 'description']},
                context={'description': alert_data.get('description', '')}
            )
    
    def generate_report(self, output_dir: str = ".") -> Dict:
        """
        Generate and output alerts in configured formats.
        
        Args:
            output_dir: Directory to save reports.
        
        Returns:
            Dictionary with output file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        
        formatter = AlertFormatter()
        alert_config = self.config['alerting']
        output_formats = alert_config.get('output_formats', [])
        outputs = {}
        
        # Filter alerts by minimum severity
        min_severity_str = alert_config.get('min_severity_to_report', 'INFO')
        min_severity = Severity[min_severity_str]
        filtered_alerts = self.alert_manager.filter_by_severity(min_severity)
        
        self.notifier.notify(f"Generating report with {len(filtered_alerts)} alerts...")
        
        # Text format
        if 'text' in output_formats:
            text_output = formatter.format_email(filtered_alerts)
            if alert_config['destinations'].get('console'):
                print("\n" + "="*70)
                print("SIEM ALERT REPORT")
                print("="*70)
                print(text_output)
        
        # JSON format
        if 'json' in output_formats:
            output_file = os.path.join(output_dir, alert_config['destinations'].get('file', 'siem_alerts.json'))
            json_output = formatter.format_json(filtered_alerts)
            with open(output_file, 'w') as f:
                f.write(json_output)
            outputs['json'] = output_file
            self.notifier.notify(f"Alerts saved to {output_file}")
        
        # CSV format
        if 'csv' in output_formats:
            output_file = os.path.join(output_dir, 'siem_alerts.csv')
            formatter.format_csv(filtered_alerts, filepath=output_file)
            outputs['csv'] = output_file
            self.notifier.notify(f"Alerts saved to {output_file}")
        
        return outputs
    
    def run(self, output_dir: str = "."):
        """
        Run the complete SIEM pipeline.
        
        Args:
            output_dir: Directory for output reports.
        """
        print("\n" + "="*70)
        print("STARTING SIEM ENGINE")
        print("="*70 + "\n")
        
        # Parse all configured log sources
        for source_name, source_config in self.config.get('log_sources', {}).items():
            if not source_config.get('enabled', True):
                continue
            
            log_file = source_config.get('path')
            log_type = source_config.get('type')
            
            if not log_file or not log_type:
                continue
            
            # Parse logs
            df = self.parse_logs(log_file, log_type)
            if df is None or df.empty:
                continue
            
            self.parsed_data[source_name] = df
            
            # Run detections
            stat_result = self.run_statistical_detection(df, source_name)
            if stat_result is not None:
                self.anomalies[f"{source_name}_statistical"] = stat_result
            
            ml_result = self.run_ml_detection(df, source_name)
            if ml_result is not None:
                self.anomalies[f"{source_name}_ml"] = ml_result
            
            # Run rule-based detection and convert to alerts
            rule_alerts = self.run_rule_based_detection(df, source_name)
            self.process_rule_alerts(rule_alerts)
        
        # Generate and output reports
        self.generate_report(output_dir)
        
        print("\n" + "="*70)
        print("SIEM ENGINE COMPLETE")
        print("="*70 + "\n")


if __name__ == "__main__":
    # Usage: python siem_engine.py [--config config.yaml] [--output output_dir]
    
    config_file = "config.yaml"
    output_dir = "."
    
    # Parse command-line arguments
    for i, arg in enumerate(sys.argv[1:]):
        if arg == "--config" and i + 1 < len(sys.argv) - 1:
            config_file = sys.argv[i + 2]
        elif arg == "--output" and i + 1 < len(sys.argv) - 1:
            output_dir = sys.argv[i + 2]
    
    # Initialize and run
    engine = SIEMEngine(config_file=config_file)
    engine.run(output_dir=output_dir)
