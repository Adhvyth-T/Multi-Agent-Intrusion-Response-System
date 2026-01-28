"""
Network anomaly detection (port scans, DDoS, etc.)
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class NetworkAnomalyDetector(BaseDetector):
    """Detects network-based anomalies."""
    
    SCAN_TOOLS = [
        'nmap', 'masscan', 'zmap', 'unicornscan',
        'nikto', 'sqlmap', 'dirb', 'gobuster', 'wfuzz',
        'metasploit', 'msfconsole', 'msfvenom'
    ]
    
    SCAN_FLAGS = [
        '-sS', '-sT', '-sU', '-sA', '-sF', '-sN', '-sX',  # Nmap scan types
        '-p-', '--top-ports', '-A', '-O',  # Nmap options
        '--rate', '--max-rate'  # Fast scanning
    ]
    
    def __init__(self):
        super().__init__("network_detector")
        if not self.trained:
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
                bootstrap=True
            )
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract network activity features.
        
        Features:
        1. Network bytes (scaled)
        2. CPU usage
        3. Process count
        4. Open files
        5. Scan tools flag
        6. Port specification flag
        7. Scan flags present
        """
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        
        features = [
            details.get('network_bytes', 0) / 1000,
            details.get('cpu_usage', 0),
            details.get('process_count', 1),
            details.get('open_files', 0),
            sum(1 for tool in self.SCAN_TOOLS if tool in command),
            1 if '-p' in command or '--port' in command else 0,  # Port specification
            sum(1 for flag in self.SCAN_FLAGS if flag in command)  # Scan types
        ]
        return np.array(features)
    
    def train(self, training_data: np.ndarray):
        """Train on normal network activity."""
        self.model.fit(training_data)
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is network anomaly."""
        command = str(event.get('details', {}).get('command', '')).lower()
        process = str(event.get('details', {}).get('process', '')).lower()
        
        # Check for scanning tools
        tool_matches = sum(1 for tool in self.SCAN_TOOLS if tool in command or tool in process)
        flag_matches = sum(1 for flag in self.SCAN_FLAGS if flag in command)
        
        # High confidence detections
        if tool_matches >= 1 and flag_matches >= 1:
            return True, 0.9
        
        if tool_matches >= 1:
            return True, 0.85
        
        if not self.trained:
            # High network activity heuristic
            network_bytes = event.get('details', {}).get('network_bytes', 0)
            open_files = event.get('details', {}).get('open_files', 0)
            
            is_high_activity = network_bytes > 500000 or open_files > 100
            return is_high_activity, min(network_bytes / 1000000, 1.0)
        
        features = self.extract_features(event).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        score = -self.model.score_samples(features)[0]
        
        is_threat = (prediction == -1) or (tool_matches >= 1)
        confidence = min(score + (0.3 if tool_matches > 0 else 0), 1.0)
        
        return is_threat, confidence