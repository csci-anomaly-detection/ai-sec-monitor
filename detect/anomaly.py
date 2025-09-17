from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle
import json

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