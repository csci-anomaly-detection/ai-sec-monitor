from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple, TYPE_CHECKING
import numpy as np # type: ignore
import pandas as pd # type: ignore
from sklearn.ensemble import IsolationForest # type: ignore
from sklearn.preprocessing import StandardScaler # type: ignore
from collections import Counter, defaultdict
import hashlib
import math
import pickle
import json

# Add this for type checking without circular imports
if TYPE_CHECKING:
    from .data_sources import LokiDataSource

def extract_features(logs: List[Dict[str, Any]], 
                     features: List[str],
                     time_field: str = "@timestamp",
                     time_window: int = 5) -> pd.DataFrame:
    """
    Extract time-series features from logs for anomaly detection.
    Groups logs into time windows and calculates statistics.
    """
    if not logs:
        return pd.DataFrame()
    
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame(logs)
    
    # Parse timestamps
    df[time_field] = pd.to_datetime(df[time_field])
    
    # Create time window buckets (n-minute intervals)
    df['window'] = df[time_field].dt.floor(f'{time_window}min')
    
    result_data = []
    
    # Group by time window
    for window, group in df.groupby('window'):
        window_data = {'window': window}
        
        # For each requested feature, calculate metrics
        for feature in features:
            if feature in group.columns:
                if pd.api.types.is_numeric_dtype(group[feature]):
                    # For numeric features, calculate statistics
                    window_data[f'{feature}_mean'] = group[feature].mean()
                    window_data[f'{feature}_max'] = group[feature].max() 
                else:
                    # For categorical features, count occurrences
                    value_counts = group[feature].value_counts()
                    for val, count in value_counts.items():
                        window_data[f'{feature}_{val}'] = count
                        
        # Count total events per window
        window_data['event_count'] = len(group)
        result_data.append(window_data)
    
    return pd.DataFrame(result_data).fillna(0)

def extract_advanced_features(logs: List[Dict[str, Any]], window_minutes: int = 30) -> pd.DataFrame:
    """Extract sophisticated ML features for anomaly detection"""
    
    if not logs:
        return pd.DataFrame()
    
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame(logs)
    
    # Ensure timestamp parsing (CLEANED UP - no excessive prints)
    if '@timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['@timestamp'])
    elif 'suricata_timestamp' in df.columns:
        try:
            df['timestamp'] = pd.to_datetime(df['suricata_timestamp'], format='%m/%d/%Y-%H:%M:%S.%f', errors='coerce')
        except Exception:
            df['timestamp'] = pd.to_datetime('now', utc=True)
    else:
        df['timestamp'] = pd.to_datetime('now', utc=True)
    
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    # Group by time windows for feature extraction
    df['time_window'] = df['timestamp'].dt.floor(f'{window_minutes}min')
    
    features_list = []
    
    for window_time, window_df in df.groupby('time_window'):
        if len(window_df) == 0:
            continue
            
        features = extract_window_features(window_df, window_time)
        features_list.append(features)
    
    if not features_list:
        return pd.DataFrame()
    
    return pd.DataFrame(features_list)

def extract_window_features(window_df: pd.DataFrame, window_time) -> Dict[str, float]:
    """Extract features for a single time window"""
    
    features = {}
    
    # === VOLUME FEATURES ===
    features['total_requests'] = len(window_df)
    features['requests_per_minute'] = len(window_df) / 30.0  # Normalize to per minute
    features['requests_per_second'] = len(window_df) / 1800.0  # 30 min = 1800 sec
    
    # === ERROR RATE FEATURES ===
    if 'status' in window_df.columns:
        status_counts = Counter(window_df['status'].astype(str))
        total_requests = len(window_df)
        
        features['error_rate'] = sum(1 for s in status_counts.keys() if s.startswith('5')) / max(total_requests, 1)
        features['client_error_rate'] = sum(1 for s in status_counts.keys() if s.startswith('4')) / max(total_requests, 1)
        features['success_rate'] = sum(1 for s in status_counts.keys() if s.startswith('2')) / max(total_requests, 1)
        features['redirect_rate'] = sum(1 for s in status_counts.keys() if s.startswith('3')) / max(total_requests, 1)
    else:
        features['error_rate'] = 0.0
        features['client_error_rate'] = 0.0
        features['success_rate'] = 1.0
        features['redirect_rate'] = 0.0
    
    # === TRAFFIC PATTERN FEATURES ===
    if 'src_ip' in window_df.columns:
        unique_ips = window_df['src_ip'].nunique()
        features['unique_client_ips'] = unique_ips
        features['avg_requests_per_ip'] = len(window_df) / max(unique_ips, 1)
        
        # IP entropy (diversity measure)
        ip_counts = Counter(window_df['src_ip'])
        total = sum(ip_counts.values())
        features['client_ip_entropy'] = calculate_entropy([count/total for count in ip_counts.values()])
    else:
        features['unique_client_ips'] = 1
        features['avg_requests_per_ip'] = len(window_df)
        features['client_ip_entropy'] = 0.0
    
    # === ATTACK PATTERN FEATURES ===
    if 'dest_port' in window_df.columns:
        unique_ports = window_df['dest_port'].nunique()
        features['port_diversity'] = unique_ports
        
        # Suspicious port patterns
        suspicious_ports = {22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 6379}
        port_counts = Counter(window_df['dest_port'])
        features['suspicious_port_ratio'] = sum(count for port, count in port_counts.items() if port in suspicious_ports) / len(window_df)
    else:
        features['port_diversity'] = 1
        features['suspicious_port_ratio'] = 0.0
    
    # === TIME-BASED FEATURES ===
    features['hour_of_day'] = window_time.hour
    features['day_of_week'] = window_time.weekday()  # 0=Monday, 6=Sunday
    features['is_weekend'] = 1.0 if window_time.weekday() >= 5 else 0.0
    features['is_business_hours'] = 1.0 if 9 <= window_time.hour <= 17 else 0.0
    features['is_night_time'] = 1.0 if window_time.hour < 6 or window_time.hour > 22 else 0.0
    
    # === SURICATA-SPECIFIC FEATURES ===
    if 'gid' in window_df.columns:
        features['alert_diversity'] = window_df['gid'].nunique()
        
    if 'sid' in window_df.columns:
        features['signature_diversity'] = window_df['sid'].nunique()
        
    if 'priority' in window_df.columns:
        priorities = pd.to_numeric(window_df['priority'], errors='coerce')
        features['avg_priority'] = priorities.mean() if not priorities.isna().all() else 3.0
        features['high_priority_ratio'] = (priorities <= 2).sum() / len(window_df) if not priorities.isna().all() else 0.0
    
    # === SIZE AND TIMING FEATURES ===
    if 'duration_ms' in window_df.columns:
        durations = pd.to_numeric(window_df['duration_ms'], errors='coerce').dropna()
        if not durations.empty:
            features['avg_duration'] = durations.mean()
            features['max_duration'] = durations.max()
            features['duration_stddev'] = durations.std()
            features['slow_request_ratio'] = (durations > 5000).sum() / len(durations)
        else:
            features['avg_duration'] = 0.0
            features['max_duration'] = 0.0
            features['duration_stddev'] = 0.0
            features['slow_request_ratio'] = 0.0
    
    # === PROTOCOL FEATURES ===
    if 'protocol' in window_df.columns:
        protocol_counts = Counter(window_df['protocol'])
        features['protocol_diversity'] = len(protocol_counts)
        features['tcp_ratio'] = protocol_counts.get('TCP', 0) / len(window_df)
        features['udp_ratio'] = protocol_counts.get('UDP', 0) / len(window_df)
    
    # === STATISTICAL FEATURES ===
    # Request timing intervals
    if len(window_df) > 1:
        time_diffs = window_df['timestamp'].diff().dt.total_seconds().dropna()
        if not time_diffs.empty:
            features['avg_request_interval'] = time_diffs.mean()
            features['request_interval_stddev'] = time_diffs.std()
            features['min_request_interval'] = time_diffs.min()
        else:
            features['avg_request_interval'] = 30.0
            features['request_interval_stddev'] = 0.0
            features['min_request_interval'] = 30.0
    
    return features

def calculate_entropy(probabilities: List[float]) -> float:
    """Calculate Shannon entropy"""
    entropy = 0.0
    for p in probabilities:
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def train_model(training_logs: List[Dict[str, Any]], 
                features: List[str],
                contamination: float = 0.05) -> Tuple[IsolationForest, List[str]]:
    """
    Train an Isolation Forest model on historical log data.
    """
    # Extract features from logs
    feature_df = extract_features(training_logs, features)
    if feature_df.empty:
        raise ValueError("No valid features could be extracted from logs")
    
    # Drop non-feature columns
    feature_cols = [col for col in feature_df.columns if col != 'window']
    X = feature_df[feature_cols]
    
    # Train the model
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)
    
    return model, feature_cols

def detect_anomalies(logs: List[Dict[str, Any]], 
                     model: IsolationForest,
                     features: List[str],
                     feature_cols: List[str],
                     threshold: float = -0.2) -> List[Dict[str, Any]]:  # Changed from -0.5 to -0.2
    """
    Detect anomalies in logs using the trained model.
    """
    # Extract features from new logs
    feature_df = extract_features(logs, features)
    if feature_df.empty:
        return []
    
    # Ensure all required columns exist
    for col in feature_cols:
        if col not in feature_df.columns:
            feature_df[col] = 0
    
    # Get anomaly scores (-1 is anomalous, 1 is normal)
    X = feature_df[feature_cols]
    scores = model.decision_function(X)
    
    anomalies = []
    for i, (_, row) in enumerate(feature_df.iterrows()):
        score = scores[i]
        # Changed threshold to be less strict
        if score <= threshold:
            anomalies.append({
                'timestamp': row['window'].isoformat(),
                'score': float(score),
                'features': {col: float(row[col]) for col in feature_cols if col in row}
            })
    
    return anomalies

def detect_anomalies_advanced(logs: List[Dict[str, Any]], 
                            contamination: float = 0.1,
                            window_minutes: int = 5) -> List[Dict[str, Any]]:  # Changed from 30 to 5 minutes
    """Advanced anomaly detection using sophisticated feature engineering"""
    
    if len(logs) < 10:
        return []
    
    # Use SMALLER time windows to get more data points
    features_df = extract_advanced_features(logs, window_minutes)
    
    # LOWER the minimum threshold - Isolation Forest needs at least 2 samples
    if features_df.empty or len(features_df) < 2:  # Changed from 3 to 2
        return []
    
    # Handle missing values
    features_df = features_df.fillna(0)
    
    # Remove constant columns
    feature_vars = features_df.var()
    varying_features = feature_vars[feature_vars > 1e-10].index
    if len(varying_features) == 0:
        return []
        
    features_df = features_df[varying_features]
    
    # Scale features
    scaler = StandardScaler()
    try:
        features_scaled = scaler.fit_transform(features_df)
    except Exception:
        return []
    
    # Isolation Forest
    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_features=min(len(varying_features), 10)
    )
    
    try:
        predictions = iso_forest.fit_predict(features_scaled)
        anomaly_scores = iso_forest.score_samples(features_scaled)
    except Exception:
        return []
    
    # Find anomalies
    anomalies = []
    for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
        if pred == -1:  # Anomaly detected
            anomaly_info = {
                'window_index': i,
                'anomaly_score': float(score),
                'features': features_df.iloc[i].to_dict(),
                'severity': 'high' if score < -0.6 else 'medium',
                'suspicious_features': identify_suspicious_features(features_df.iloc[i], features_df)
            }
            anomalies.append(anomaly_info)
    
    return anomalies

def identify_suspicious_features(window_features: pd.Series, all_features_df: pd.DataFrame) -> List[str]:
    """Identify which features are most suspicious in this window"""
    
    suspicious = []
    
    # Calculate z-scores for each feature
    for feature in window_features.index:
        if feature in all_features_df.columns:
            mean_val = all_features_df[feature].mean()
            std_val = all_features_df[feature].std()
            
            if std_val > 0:
                z_score = abs((window_features[feature] - mean_val) / std_val)
                
                # Flag features with high z-scores
                if z_score > 2.0:
                    suspicious.append(f"{feature} (z={z_score:.2f})")
    
    return suspicious[:5]  # Top 5 most suspicious features

# Update the main anomaly detection function
def run_isolation_forest(logs: List[Dict[str, Any]], 
                        contamination: float = 0.1, 
                        features: List[str] = None) -> Optional[Dict[str, Any]]:
    """Enhanced isolation forest with advanced feature engineering"""
    
    anomalies = detect_anomalies_advanced(logs, contamination)
    
    if anomalies:
        most_severe = max(anomalies, key=lambda x: abs(x['anomaly_score']))
        
        return {
            'anomalies_detected': len(anomalies),
            'most_severe_score': most_severe['anomaly_score'],
            'severity': most_severe['severity'],
            'suspicious_features': most_severe['suspicious_features'],
            'all_anomalies': anomalies
        }
    
    return None

class TrainingDataManager:
    def __init__(self):
        self.trained_models = {}
        self.training_window_hours = 24
        
    def get_baseline_training_data(self, loki_source: 'LokiDataSource') -> List[Dict[str, Any]]:  # Use quotes
        """Get clean training data from historical logs"""
        
        # Get data from 2-7 days ago (avoid recent attacks)
        end_time = datetime.now(UTC) - timedelta(days=2)  
        start_time = end_time - timedelta(days=5)
        
        training_logs = loki_source.query_logs(
            '{job="suricata"}',  # All logs for baseline
            start_time, 
            end_time,
            limit=10000
        )
        
        # Filter for "normal" activity (low priority, no critical alerts)
        normal_logs = [
            log for log in training_logs 
            if int(log.get('priority', '3')) >= 3  # Only low priority
            and log.get('status') != 'critical'
        ]
        
        print(f"Training data: {len(normal_logs)} normal logs from {start_time} to {end_time}")
        return normal_logs
    
    def train_baseline_models(self, loki_source: 'LokiDataSource'):  # Use quotes
        """Train models on historical normal data"""
        
        training_data = self.get_baseline_training_data(loki_source)
        
        if len(training_data) < 100:
            print("Insufficient training data - using unsupervised mode")
            return None
            
        # Extract features from training data
        training_features = extract_advanced_features(training_data, window_minutes=30)
        
        if training_features.empty:
            return None
            
        # Train separate models for different feature sets
        models = {}
        
        # Traffic pattern model
        traffic_features = ['requests_per_minute', 'unique_client_ips', 'port_diversity']
        if all(f in training_features.columns for f in traffic_features):
            models['traffic_anomaly'] = self._train_model(
                training_features[traffic_features], 
                contamination=0.05
            )
        
        # Behavioral model  
        behavior_features = ['alert_diversity', 'avg_priority', 'protocol_diversity']
        if all(f in training_features.columns for f in behavior_features):
            models['behavioral_anomaly'] = self._train_model(
                training_features[behavior_features],
                contamination=0.10
            )
        
        self.trained_models = models
        print(f"Trained {len(models)} baseline models")
        return models
    
    def _train_model(self, feature_data: pd.DataFrame, contamination: float):
        """Train a single isolation forest model"""
        
        # Handle missing values and scaling
        feature_data = feature_data.fillna(0)
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(feature_data)
        
        # Train model
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=200
        )
        
        model.fit(scaled_features)
        
        return {
            'model': model,
            'scaler': scaler,
            'feature_names': list(feature_data.columns)
        }
    
    def predict_with_trained_models(self, live_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use pre-trained models to detect anomalies in live data"""
        
        if not self.trained_models:
            print("No trained models available - falling back to unsupervised")
            return detect_anomalies_advanced(live_logs)
        
        live_features = extract_advanced_features(live_logs, window_minutes=30)
        if live_features.empty:
            return []
        
        anomalies = []
        
        for model_name, model_data in self.trained_models.items():
            model = model_data['model']
            scaler = model_data['scaler'] 
            feature_names = model_data['feature_names']
            
            # Check if we have required features
            available_features = [f for f in feature_names if f in live_features.columns]
            if len(available_features) < len(feature_names) * 0.8:  # Need 80% of features
                continue
                
            # Predict anomalies
            live_data = live_features[available_features].fillna(0)
            scaled_live = scaler.transform(live_data)
            
            predictions = model.predict(scaled_live)
            scores = model.score_samples(scaled_live)
            
            # Collect anomalies
            for i, (pred, score) in enumerate(zip(predictions, scores)):
                if pred == -1:  # Anomaly detected
                    anomalies.append({
                        'model': model_name,
                        'window_index': i,
                        'anomaly_score': float(score),
                        'severity': 'high' if score < -0.6 else 'medium'
                    })
        
        return anomalies