"""
Cryptominer detection using resource usage patterns.
High CPU + High Memory + Network activity to mining pools.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class CryptominerDetector(BaseDetector):
    """Detects cryptocurrency mining based on resource patterns."""
    
    # Mining pool indicators
    MINING_POOLS = ['pool.minexmr.com', 'pool.supportxmr.com', 'xmrpool.eu', 'hashvault.pro']
    MINING_PORTS = [3333, 4444, 5555, 8333, 14444]
    MINING_PROCESSES = ['xmrig', 'minerd', 'cpuminer', 'ethminer', 'cgminer', 'bfgminer']
    
    def __init__(self):
        super().__init__("cryptominer_detector")
        if not self.trained:
            self.model = IsolationForest(
                contamination=0.05,  # Expect 5% anomalies
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                bootstrap=True
            )
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract resource usage features.
        
        Features:
        1. CPU usage (0-100)
        2. Memory usage (0-100)
        3. Network bytes (scaled)
        4. Process count
        5. Open files
        6. High CPU flag (>80%)
        7. Mining port flag
        """
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        
        # Check for mining pool indicators
        has_pool = any(pool in command for pool in self.MINING_POOLS)
        has_port = any(str(port) in command for port in self.MINING_PORTS)
        has_process = any(proc in command for proc in self.MINING_PROCESSES)
        
        features = [
            details.get('cpu_usage', 0),
            details.get('memory_usage', 0),
            details.get('network_bytes', 0) / 1000,  # Scale down
            details.get('process_count', 1),
            details.get('open_files', 0),
            1 if details.get('cpu_usage', 0) > 80 else 0,  # High CPU flag
            1 if (has_pool or has_port or has_process) else 0  # Mining indicators
        ]
        return np.array(features)
    
    def train(self, training_data: np.ndarray):
        """Train on normal (non-mining) workloads."""
        self.model.fit(training_data)
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is cryptomining."""
        if not self.trained:
            # Fallback to heuristics
            return self._heuristic_check(event)
        
        features = self.extract_features(event).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        score = -self.model.score_samples(features)[0]
        
        # Additional heuristic checks
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        process = str(details.get('process', '')).lower()
        
        heuristic_match = any([
            any(proc in command or proc in process for proc in self.MINING_PROCESSES),
            any(pool in command for pool in self.MINING_POOLS),
            'stratum' in command,
            details.get('cpu_usage', 0) > 90
        ])
        
        is_threat = (prediction == -1) or heuristic_match
        confidence = min(score + (0.3 if heuristic_match else 0), 1.0)
        confidence = 1 / (1 + np.exp(-confidence))
        confidence = max(0.0, min(1.0, confidence))
        return is_threat, confidence
    
    def _heuristic_check(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Heuristic-based detection when model not trained."""
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        process = str(details.get('process', '')).lower()
        
        indicators = [
            any(proc in command or proc in process for proc in self.MINING_PROCESSES),
            any(pool in command for pool in self.MINING_POOLS),
            any(str(port) in command for port in self.MINING_PORTS),
            'stratum' in command,
            details.get('cpu_usage', 0) > 85
        ]
        
        matches = sum(indicators)
        return matches >= 2, min(matches * 0.3, 1.0)