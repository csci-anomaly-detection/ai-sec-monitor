from datetime import datetime, timedelta, UTC
from typing import Dict, List, Any, Optional
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .data_sources import LokiDataSource
from .anomaly import extract_advanced_features

class TrainingDataManager:
    def __init__(self):
        self.trained_models = {}
        self.model_save_path = "trained_models.pkl"
        
    def get_baseline_training_data(self, loki_source: LokiDataSource) -> List[Dict[str, Any]]:
        """Get clean training data from historical logs"""
        
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=48)  # Last 48 hours
        
        training_logs = loki_source.query_logs(
            '{job="suricata"}',  # All logs 
            start_time, 
            end_time,
            limit=5000
        )
        
        if not training_logs:
            return []
        
        # SIMPLIFIED FILTER - Don't be too restrictive
        normal_logs = []
        for log in training_logs:
            priority = int(log.get('priority', '3'))
            src_ip = log.get('src_ip', '')
            
            # LESS RESTRICTIVE: Just exclude the most obvious attack patterns
            if (priority >= 3 and 
                not (src_ip.startswith('10.77.') and log.get('dest_port', 0) == 2222)):  # Only exclude SSH attacks on honeypot
                normal_logs.append(log)
        
        return normal_logs
    
    def train_baseline_models(self, loki_source: LokiDataSource) -> Optional[Dict[str, Any]]:
        """Train models on historical normal data"""
        
        training_data = self.get_baseline_training_data(loki_source)
        
        if len(training_data) < 50:
            # SILENT - don't print this every time
            return None
            
        # SILENT TRAINING - only print errors
        training_features = self._extract_batch_features(training_data, batch_size=200)
        
        if training_features.empty or len(training_features) < 3:
            return None
            
        # Only print if successful
        models = {}
        
        # Train models (keep existing logic, remove debug prints)
        traffic_features = ['requests_per_batch', 'unique_client_ips', 'port_diversity']
        available_traffic = [f for f in traffic_features if f in training_features.columns]
        if len(available_traffic) >= 2:
            models['traffic_anomaly'] = self._train_model(
                training_features[available_traffic], 
                contamination=0.05
            )
    
        behavior_features = ['alert_diversity', 'avg_priority', 'protocol_diversity']
        available_behavior = [f for f in behavior_features if f in training_features.columns]
        if len(available_behavior) >= 2:
            models['behavioral_anomaly'] = self._train_model(
                training_features[available_behavior],
                contamination=0.10
            )
    
        volume_features = ['total_requests', 'requests_per_batch', 'suspicious_port_ratio']
        available_volume = [f for f in volume_features if f in training_features.columns]
        if len(available_volume) >= 2:
            models['volume_anomaly'] = self._train_model(
                training_features[available_volume],
                contamination=0.15
            )
    
        self.trained_models = models
    
        # ONLY print final success message
        if models:
            print(f"Trained {len(models)} ML models on {len(training_features)} feature batches")
    
        self._save_models()
        return models
    
    def _train_model(self, feature_data: pd.DataFrame, contamination: float) -> Dict[str, Any]:
        """Train a single isolation forest model"""
        
        # Handle missing values
        feature_data = feature_data.fillna(0)
        
        # Scale features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(feature_data)
        
        # Train model
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_features=min(len(feature_data.columns), 5)
        )
        
        model.fit(scaled_features)
        
        return {
            'model': model,
            'scaler': scaler,
            'feature_names': list(feature_data.columns),
            'training_stats': {
                'samples': len(feature_data),
                'features': len(feature_data.columns),
                'contamination': contamination
            }
        }
    
    def predict_with_trained_models(self, live_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use pre-trained models to detect anomalies in live data"""
        
        if not self.trained_models:
            # SILENT loading
            if not self._load_models():
                from .anomaly import detect_anomalies_advanced
                return detect_anomalies_advanced(live_logs)
        
        live_features = self._extract_batch_features(live_logs, batch_size=200)
        if live_features.empty:
            return []
        
        anomalies = []
        
        for model_name, model_data in self.trained_models.items():
            try:
                model = model_data['model']
                scaler = model_data['scaler'] 
                feature_names = model_data['feature_names']
                
                # Check if we have required features
                available_features = [f for f in feature_names if f in live_features.columns]
                if len(available_features) < len(feature_names) * 0.7:  # Need 70% of features
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
                            'batch_index': i,
                            'anomaly_score': float(score),
                            'severity': 'high' if score < -0.6 else 'medium',
                            'features_used': available_features
                        })
                        
            except Exception as e:
                print(f"Error in model {model_name}: {e}")
                continue
        
        return anomalies
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            import pickle
            with open(self.model_save_path, 'wb') as f:
                pickle.dump(self.trained_models, f)
            # REMOVE: print(f"Saved models to {self.model_save_path}")
        except Exception as e:
            print(f"Failed to save models: {e}")
    
    def _load_models(self) -> bool:
        """Load trained models from disk"""
        try:
            import pickle
            with open(self.model_save_path, 'rb') as f:
                self.trained_models = pickle.load(f)
            # REMOVE: print(f"Loaded {len(self.trained_models)} models from {self.model_save_path}")
            return True
        except Exception:
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about trained models"""
        if not self.trained_models:
            return {"status": "no_models", "models": []}
        
        model_info = []
        for name, data in self.trained_models.items():
            stats = data.get('training_stats', {})
            model_info.append({
                'name': name,
                'features': data.get('feature_names', []),
                'training_samples': stats.get('samples', 0),
                'contamination_rate': stats.get('contamination', 0)
            })
        
        return {
            "status": "trained",
            "model_count": len(self.trained_models),
            "models": model_info
        }
    
    def _extract_batch_features(self, logs: List[Dict[str, Any]], batch_size: int = 200) -> pd.DataFrame:
        """Extract features from batches of logs instead of time windows"""
        import pandas as pd
        
        # Split logs into batches
        batches = [logs[i:i + batch_size] for i in range(0, len(logs), batch_size)]
        
        if len(batches) < 3:
            return pd.DataFrame()
        
        # REMOVE: print(f"Created {len(batches)} batches of ~{batch_size} logs each")
        
        features_list = []
        
        for i, batch in enumerate(batches):
            if len(batch) < 10:  # Skip tiny batches
                continue
                
            # Extract features for this batch
            features = {
                'batch_id': i,
                'total_requests': len(batch),
                'requests_per_batch': len(batch) / batch_size * 200,  # Normalize to per-200-logs
                'unique_client_ips': len(set(log.get('src_ip', '') for log in batch)),
                'port_diversity': len(set(log.get('dest_port', 0) for log in batch)),
                'suspicious_port_ratio': sum(1 for log in batch if log.get('dest_port', 0) in [22, 2222, 80, 443]) / len(batch),
                'alert_diversity': len(set(log.get('alert_message', '') for log in batch)),
                'avg_priority': sum(int(log.get('priority', 3)) for log in batch) / len(batch),
                'high_priority_ratio': sum(1 for log in batch if int(log.get('priority', 3)) <= 2) / len(batch),
                'protocol_diversity': len(set(log.get('protocol', '') for log in batch)),
                'tcp_ratio': sum(1 for log in batch if log.get('protocol', '').lower() == 'tcp') / len(batch),
            }
            
            features_list.append(features)
        
        return pd.DataFrame(features_list)