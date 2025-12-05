"""
PHASE 2 & 3: ANOMALY DETECTION MODULE
======================================
Learn how to identify unusual patterns in log data.

Key Concepts:
- Time-series aggregation (group events into time buckets).
- Statistical anomaly detection (z-score, IQR).
- Machine learning (Isolation Forest).
- Rule-based detection (thresholds on specific events).
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class TimeSeriesAggregator:
    """
    Group events into time windows and compute statistics.
    
    Example:
    - Raw events: 1000 logins over 1 hour
    - 5-min buckets: [100, 95, 110, 105, ...] logins per 5 min
    - Statistics: mean=103, std=8, max=150
    """
    
    def __init__(self, df: pd.DataFrame, window_minutes: int = 5):
        """
        Args:
            df: DataFrame with parsed log entries (must have 'timestamp' column).
            window_minutes: Time bucket size in minutes.
        """
        self.df = df.copy()
        self.window_minutes = window_minutes
        self._ensure_datetime()
    
    def _ensure_datetime(self):
        """Convert timestamp column to datetime if needed."""
        if not pd.api.types.is_datetime64_any_dtype(self.df['timestamp']):
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
    
    def aggregate_by_source_ip(self) -> pd.DataFrame:
        """
        Count events per source IP per time window.
        
        Returns:
            DataFrame with columns: timestamp, source_ip, event_count
        """
        self.df['time_bucket'] = self.df['timestamp'].dt.floor(f'{self.window_minutes}min')
        
        aggregated = self.df.groupby(['time_bucket', 'source_ip']).size().reset_index(name='event_count')
        aggregated.rename(columns={'time_bucket': 'timestamp'}, inplace=True)
        
        return aggregated
    
    def aggregate_by_action(self) -> pd.DataFrame:
        """
        Count events per action (e.g., failed_login, successful_login) per time window.
        
        Returns:
            DataFrame with columns: timestamp, action, event_count
        """
        self.df['time_bucket'] = self.df['timestamp'].dt.floor(f'{self.window_minutes}min')
        
        aggregated = self.df.groupby(['time_bucket', 'action']).size().reset_index(name='event_count')
        aggregated.rename(columns={'time_bucket': 'timestamp'}, inplace=True)
        
        return aggregated
    
    def compute_statistics(self, aggregated_df: pd.DataFrame) -> Dict:
        """
        Compute basic statistics on aggregated counts.
        
        Returns:
            Dictionary with mean, std, min, max, percentiles.
        """
        counts = aggregated_df['event_count']
        
        return {
            'mean': counts.mean(),
            'std': counts.std(),
            'median': counts.median(),
            'min': counts.min(),
            'max': counts.max(),
            'q25': counts.quantile(0.25),
            'q75': counts.quantile(0.75),
            'iqr': counts.quantile(0.75) - counts.quantile(0.25),
        }


class StatisticalAnomalyDetector:
    """
    Detect anomalies using statistical methods (z-score, IQR).
    
    Z-score method:
    - Flag events where |z_score| > threshold (typically 3)
    - z_score = (value - mean) / std
    
    IQR method:
    - Flag events outside [Q1 - 1.5*IQR, Q3 + 1.5*IQR]
    - More robust to outliers than z-score
    """
    
    def __init__(self, df: pd.DataFrame, method: str = 'zscore', threshold: float = 3.0):
        """
        Args:
            df: DataFrame with aggregated counts (e.g., from TimeSeriesAggregator).
            method: 'zscore' or 'iqr'.
            threshold: Number of standard deviations (for z-score).
        """
        self.df = df.copy()
        self.method = method
        self.threshold = threshold
    
    def detect_zscore(self) -> pd.DataFrame:
        """
        Detect anomalies using z-score method.
        
        Returns:
            DataFrame with anomaly flags and z-scores.
        """
        counts = self.df['event_count']
        
        # Handle edge case: std = 0
        std = counts.std()
        if std == 0:
            self.df['z_score'] = 0
            self.df['is_anomaly'] = False
            return self.df
        
        mean = counts.mean()
        self.df['z_score'] = (counts - mean) / std
        self.df['is_anomaly'] = abs(self.df['z_score']) > self.threshold
        
        return self.df
    
    def detect_iqr(self) -> pd.DataFrame:
        """
        Detect anomalies using Interquartile Range (IQR) method.
        
        Returns:
            DataFrame with anomaly flags and IQR bounds.
        """
        counts = self.df['event_count']
        
        q1 = counts.quantile(0.25)
        q3 = counts.quantile(0.75)
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        self.df['lower_bound'] = lower_bound
        self.df['upper_bound'] = upper_bound
        self.df['is_anomaly'] = (counts < lower_bound) | (counts > upper_bound)
        
        return self.df
    
    def detect(self) -> pd.DataFrame:
        """Detect anomalies using the configured method."""
        if self.method == 'zscore':
            return self.detect_zscore()
        elif self.method == 'iqr':
            return self.detect_iqr()
        else:
            raise ValueError(f"Unknown method: {self.method}")


class MLAnomalyDetector:
    """
    Detect anomalies using Isolation Forest (unsupervised ML).
    
    Isolation Forest:
    - Works well for multivariate anomaly detection.
    - No need for labeled training data.
    - Fast and scalable.
    
    Features:
    - event_count: Number of events in time bucket
    - hour_of_day: Time of day (cyclical feature)
    - day_of_week: Day of week (cyclical feature)
    """
    
    def __init__(self, df: pd.DataFrame, contamination: float = 0.05):
        """
        Args:
            df: DataFrame with aggregated counts and timestamp.
            contamination: Proportion of expected anomalies (0.0-1.0).
        """
        self.df = df.copy()
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self._ensure_datetime()
    
    def _ensure_datetime(self):
        """Convert timestamp to datetime if needed."""
        if not pd.api.types.is_datetime64_any_dtype(self.df['timestamp']):
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
    
    def _extract_features(self) -> pd.DataFrame:
        """
        Extract features for ML model.
        
        Features:
        - event_count: Raw count
        - hour_of_day: Hour (0-23)
        - day_of_week: Day of week (0=Monday, 6=Sunday)
        """
        features = pd.DataFrame()
        features['event_count'] = self.df['event_count']
        features['hour_of_day'] = self.df['timestamp'].dt.hour
        features['day_of_week'] = self.df['timestamp'].dt.dayofweek
        
        return features
    
    def detect(self) -> pd.DataFrame:
        """
        Train Isolation Forest and detect anomalies.
        
        Returns:
            DataFrame with anomaly predictions (-1 = anomaly, 1 = normal).
        """
        features = self._extract_features()
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        predictions = self.model.fit_predict(features_scaled)
        
        # Add predictions to dataframe (-1 = anomaly, 1 = normal)
        self.df['ml_prediction'] = predictions
        self.df['is_anomaly'] = (predictions == -1)
        
        return self.df


class RuleBasedDetector:
    """
    Detect anomalies based on hardcoded rules and thresholds.
    
    Examples:
    - More than 10 failed SSH logins from same IP in 5 min: brute-force
    - HTTP response status 403/404 spike: reconnaissance
    - Multiple 5xx errors: service compromise or DoS
    """
    
    def __init__(self, df: pd.DataFrame, config: Dict = None):
        """
        Args:
            df: Original parsed log DataFrame.
            config: Dictionary with rule thresholds.
        """
        self.df = df.copy()
        self.config = config or self._default_config()
        self.alerts = []
    
    @staticmethod
    def _default_config() -> Dict:
        """Default detection rules and thresholds."""
        return {
            'failed_login_threshold': 10,      # Failed logins in 5 min
            'failed_login_window': 5,          # Time window (minutes)
            'http_error_spike_threshold': 50,  # HTTP 4xx/5xx responses in 1 min
            'unique_ips_threshold': 100,       # Unique source IPs in 1 hour (port scan?)
        }
    
    def detect_brute_force(self, window_minutes: int = 5) -> List[Dict]:
        """
        Detect brute-force SSH/login attacks.
        
        Returns:
            List of alerts with details.
        """
        alerts = []
        
        # Filter for failed login events
        if 'action' not in self.df.columns:
            return alerts
        
        failed_logins = self.df[self.df['action'] == 'failed_login'].copy()
        if failed_logins.empty:
            return alerts
        
        # Ensure datetime
        if not pd.api.types.is_datetime64_any_dtype(failed_logins['timestamp']):
            failed_logins['timestamp'] = pd.to_datetime(failed_logins['timestamp'])
        
        # Group by time window and source IP
        failed_logins['time_bucket'] = failed_logins['timestamp'].dt.floor(f'{window_minutes}min')
        grouped = failed_logins.groupby(['time_bucket', 'source_ip']).size().reset_index(name='count')
        
        # Flag if count exceeds threshold
        threshold = self.config.get('brute_force', {}).get('failed_login_threshold', 10)
        anomalies = grouped[grouped['count'] > threshold]
        
        for _, row in anomalies.iterrows():
            alerts.append({
                'alert_type': 'brute_force_login',
                'severity': 'CRITICAL' if row['count'] > threshold * 2 else 'HIGH',
                'timestamp': row['time_bucket'],
                'source_ip': row['source_ip'],
                'event_count': int(row['count']),
                'threshold': threshold,
                'description': f"Detected {int(row['count'])} failed logins from {row['source_ip']} in {window_minutes} min"
            })
        
        return alerts
    
    def detect_port_scan(self, window_minutes: int = 60) -> List[Dict]:
        """
        Detect potential port scanning (many unique connections from single IP).
        
        Returns:
            List of alerts.
        """
        alerts = []
        
        # Only works for logs with source_ip and port
        if 'source_ip' not in self.df.columns or 'port' not in self.df.columns:
            return alerts
        
        # Ensure datetime
        df = self.df.copy()
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by source IP and time window
        df['time_bucket'] = df['timestamp'].dt.floor(f'{window_minutes}min')
        grouped = df.groupby(['time_bucket', 'source_ip']).agg({
            'port': 'nunique',  # Count unique ports
            'timestamp': 'count'  # Total connections
        }).reset_index()
        grouped.rename(columns={'port': 'unique_ports', 'timestamp': 'total_connections'}, inplace=True)
        
        # Flag if many unique ports
        threshold = 50  # Arbitrary; adjust based on your environment
        suspicious = grouped[grouped['unique_ports'] > threshold]
        
        for _, row in suspicious.iterrows():
            alerts.append({
                'alert_type': 'port_scan',
                'severity': 'HIGH',
                'timestamp': row['time_bucket'],
                'source_ip': row['source_ip'],
                'unique_ports': int(row['unique_ports']),
                'total_connections': int(row['total_connections']),
                'description': f"Potential port scan: {int(row['unique_ports'])} unique ports from {row['source_ip']}"
            })
        
        return alerts
    
    def detect_all(self) -> List[Dict]:
        """Run all rule-based detections."""
        all_alerts = []
        all_alerts.extend(self.detect_brute_force())
        all_alerts.extend(self.detect_port_scan())
        return all_alerts


if __name__ == "__main__":
    # Example: Create sample time-series data
    print("=== Time Series Aggregation Example ===")
    sample_data = {
        'timestamp': pd.date_range('2025-12-05', periods=100, freq='1min'),
        'source_ip': np.random.choice(['192.168.1.10', '192.168.1.20', '192.168.1.30'], 100),
        'event_count': np.random.poisson(lam=5, size=100) + np.random.poisson(lam=20, size=1),
        'action': np.random.choice(['login', 'logout', 'error'], 100)
    }
    df = pd.DataFrame(sample_data)
    
    # Statistical anomaly detection
    detector = StatisticalAnomalyDetector(df, method='zscore')
    result = detector.detect()
    anomalies = result[result['is_anomaly']]
    print(f"Found {len(anomalies)} anomalies:\n{anomalies}")
