"""
Data exfiltration detection using network patterns.
Unusual outbound traffic, suspicious domains, data encoding.
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class ExfiltrationDetector(BaseDetector):
    """Detects data exfiltration patterns."""
    
    SUSPICIOUS_DOMAINS = [
        'pastebin', 'transfer.sh', 'file.io', 'temp', 'upload',
        'dropbox', 'mega.nz', 'wetransfer', 'anonfiles', 'sendspace'
    ]
    
    SUSPICIOUS_TOOLS = [
        'curl', 'wget', 'nc', 'ncat', 'netcat', 'base64', 'xxd',
        'scp', 'rsync', 'ftp', 'sftp', 'ssh'
    ]
    
    ENCODING_INDICATORS = ['base64', 'gzip', 'tar', 'zip', 'xxd', 'od']
    
    def __init__(self):
        super().__init__("exfiltration_detector")
        if not self.trained:
            self.model = RandomForestClassifier(
                n_estimators=50,
                random_state=42,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced'
            )
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract network and command features.
        
        Features:
        1. Network bytes (outbound)
        2. CPU usage
        3. Suspicious tools flag
        4. Suspicious domains flag
        5. POST/PUT methods flag
        6. File redirection flag
        7. Command complexity
        8. Process count
        """
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        event_str = str(event).lower()
        
        features = [
            details.get('network_bytes', 0) / 1000,  # Outbound traffic
            details.get('cpu_usage', 0),
            1 if any(tool in command for tool in self.SUSPICIOUS_TOOLS) else 0,
            1 if any(domain in event_str for domain in self.SUSPICIOUS_DOMAINS) else 0,
            1 if 'POST' in command or 'PUT' in command else 0,  # Upload methods
            1 if '@' in command or '>' in command else 0,  # File redirection
            len(command.split()) / 10,  # Command complexity
            details.get('process_count', 1)
        ]
        return np.array(features)
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """Train with labeled data (0=benign, 1=exfiltration)."""
        self.model.fit(X_train, y_train)
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is data exfiltration."""
        if not self.trained:
            # Fallback to heuristics
            return self._heuristic_check(event)
        
        features = self.extract_features(event).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        
        # Get probability if available
        if hasattr(self.model, 'predict_proba'):
            confidence = self.model.predict_proba(features)[0][1]
        else:
            confidence = 0.7 if prediction else 0.3
        
        return bool(prediction), confidence
    
    def _heuristic_check(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Heuristic-based detection when model not trained."""
        command = str(event.get('details', {}).get('command', '')).lower()
        event_str = str(event).lower()
        
        indicators = [
            any(tool in command for tool in self.SUSPICIOUS_TOOLS),
            any(domain in event_str for domain in self.SUSPICIOUS_DOMAINS),
            'POST' in command or 'PUT' in command,
            event.get('details', {}).get('network_bytes', 0) > 100000,
            any(enc in command for enc in self.ENCODING_INDICATORS)
        ]
        
        matches = sum(indicators)
        return matches >= 2, min(matches * 0.25, 1.0)