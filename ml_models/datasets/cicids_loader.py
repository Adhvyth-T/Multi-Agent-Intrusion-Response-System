# ml_models/datasets/cicids_loader.py
"""
Load and process CICIDS2017 dataset.
Best for: Realistic network traffic with modern attacks.
"""
import pandas as pd
import numpy as np
from pathlib import Path
import structlog

log = structlog.get_logger()

class CICIDS2017Loader:
    """Load CICIDS2017 dataset."""
    
    # Attack type mapping
    ATTACK_TYPES = {
        'BENIGN': 'benign',
        'DoS Hulk': 'dos',
        'DoS GoldenEye': 'dos',
        'DoS slowloris': 'dos',
        'DoS Slowhttptest': 'dos',
        'DDoS': 'dos',
        'PortScan': 'probe',
        'FTP-Patator': 'brute_force',
        'SSH-Patator': 'brute_force',
        'Bot': 'botnet',
        'Web Attack – Brute Force': 'web_attack',
        'Web Attack – XSS': 'web_attack',
        'Web Attack – Sql Injection': 'web_attack',
        'Infiltration': 'exfiltration',
        'Heartbleed': 'vulnerability'
    }
    
    OUR_THREAT_MAPPING = {
        'dos': 'anomalous_network',
        'probe': 'suspicious_process',
        'brute_force': 'privilege_escalation',
        'botnet': 'cryptominer',  # Similar resource patterns
        'web_attack': 'data_exfiltration',
        'exfiltration': 'data_exfiltration',
        'vulnerability': 'privilege_escalation'
    }
    
    def __init__(self):
        self.base_dir = Path("ml_models/datasets/raw/CICIDS2017")
    
    def load_dataset(self, day='Monday') -> pd.DataFrame:
        """Load CICIDS2017 dataset for a specific day."""
        
        # Find CSV file for the day
        pattern = f"*{day}*.csv"
        csv_files = list(self.base_dir.glob(pattern))
        
        if not csv_files:
            log.error(f"No CSV files found for {day} in {self.base_dir}")
            return None
        
        log.info(f"Loading CICIDS2017 {day} dataset: {csv_files[0].name}")
        
        try:
            # Read CSV with proper encoding
            df = pd.read_csv(csv_files[0], encoding='utf-8', low_memory=False)
            
            # Clean column names (remove spaces)
            df.columns = df.columns.str.strip()
            
            # Handle label column name variations
            label_col = None
            for col in [' Label', 'Label', 'label']:
                if col in df.columns:
                    label_col = col
                    break
            
            if label_col is None:
                log.error("Could not find label column")
                return None
            
            # Standardize label column
            df['attack_type'] = df[label_col].str.strip()
            
            # Map to categories
            df['category'] = df['attack_type'].map(self.ATTACK_TYPES)
            df['our_threat'] = df['category'].map(self.OUR_THREAT_MAPPING)
            
            # Fill missing values
            df = df.fillna(0)
            
            # Replace infinity values
            df = df.replace([np.inf, -np.inf], 0)
            
            log.info(f"Loaded {len(df)} samples")
            log.info(f"Attack distribution:\n{df['category'].value_counts()}")
            
            return df
            
        except Exception as e:
            log.error(f"Failed to load CICIDS2017", error=str(e))
            return None
    
    def get_features_for_threat(self, df: pd.DataFrame, threat_type: str) -> tuple:
        """Extract features for specific threat type."""
        
        # Key CICIDS features
        flow_bytes = 'Flow Bytes/s' if 'Flow Bytes/s' in df.columns else 'Flow Bytes/s'
        fwd_packets = 'Total Fwd Packets' if 'Total Fwd Packets' in df.columns else 'Fwd Packets'
        
        if threat_type == 'cryptominer':
            # Use botnet samples (similar resource patterns)
            benign = df[df['category'] == 'benign'].sample(n=min(10000, len(df[df['category'] == 'benign'])))
            attack = df[df['category'] == 'botnet']
            
            if len(attack) == 0:
                attack = df[df['category'] == 'dos'].sample(n=min(1000, len(df[df['category'] == 'dos'])))
            
            # Extract features
            X_benign = self._extract_resource_features(benign)
            X_attack = self._extract_resource_features(attack)
            X_attack[:, 5] = 1  # Set high CPU flag for attacks
            
            return X_benign, X_attack
        
        elif threat_type == 'data_exfiltration':
            benign = df[df['category'] == 'benign'].sample(n=min(5000, len(df[df['category'] == 'benign'])))
            attack = df[df['our_threat'] == 'data_exfiltration']
            
            if len(attack) == 0:
                log.warning("No exfiltration samples, using web attacks")
                attack = df[df['category'] == 'web_attack'].sample(n=min(1000, len(df[df['category'] == 'web_attack'])))
            
            X_benign = self._extract_exfiltration_features(benign)
            X_attack = self._extract_exfiltration_features(attack)
            X_attack[:, 2] = 1  # Set suspicious tools flag
            X_attack[:, 3] = 1  # Set suspicious domains flag
            
            y = np.concatenate([np.zeros(len(X_benign)), np.ones(len(X_attack))])
            X = np.vstack([X_benign, X_attack])
            
            indices = np.random.permutation(len(X))
            return X[indices], y[indices]
        
        elif threat_type == 'network_anomaly':
            benign = df[df['category'] == 'benign'].sample(n=min(10000, len(df[df['category'] == 'benign'])))
            attack = df[df['category'].isin(['probe', 'dos'])]
            
            X_benign = self._extract_network_features(benign)
            X_attack = self._extract_network_features(attack)
            X_attack[:, 4] = 1  # Scan tools flag
            
            return np.vstack([X_benign, X_attack])
        
        return None
    
    def _extract_resource_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract resource usage features for cryptominer detection."""
        # [cpu, memory, network, processes, files, high_cpu_flag, mining_port]
        
        features = []
        for col in ['Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 
                    'Bwd Packets/s', 'Active Mean', 'Idle Mean', 'Flow Duration']:
            if col in df.columns:
                features.append(df[col].values)
            else:
                features.append(np.zeros(len(df)))
        
        # Build feature matrix
        X = np.column_stack([
            np.clip(features[0] / 100000, 0, 100),  # CPU proxy (flow bytes)
            np.clip(features[1] / 1000, 0, 100),    # Memory proxy (packets)
            np.clip(features[2] / 1000, 0, 100),    # Network
            np.clip(features[3] / 100, 0, 100),     # Processes proxy
            np.clip(features[4] / 10000, 0, 100),   # Files proxy (active time)
            np.zeros(len(df)),                      # High CPU flag
            np.zeros(len(df))                       # Mining port flag
        ])
        
        return X
    
    def _extract_exfiltration_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract exfiltration features."""
        # [network_bytes, cpu, tools_flag, domains_flag, post_flag, redirect_flag, complexity, processes]
        
        X = np.column_stack([
            np.clip(df.get('Flow Bytes/s', np.zeros(len(df))) / 100000, 0, 100),
            np.clip(df.get('Fwd Packets/s', np.zeros(len(df))) / 1000, 0, 100),
            np.zeros(len(df)),  # Tools flag
            np.zeros(len(df)),  # Domains flag
            np.zeros(len(df)),  # POST flag
            np.zeros(len(df)),  # Redirect flag
            np.clip(df.get('Flow Duration', np.zeros(len(df))) / 1000000, 0, 100),
            np.clip(df.get('Total Fwd Packets', np.zeros(len(df))) / 100, 0, 100)
        ])
        
        return X
    
    def _extract_network_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract network anomaly features."""
        # [network_bytes, cpu, processes, files, scan_tools, port_specs, scan_flags]
        
        X = np.column_stack([
            np.clip(df.get('Flow Bytes/s', np.zeros(len(df))) / 100000, 0, 100),
            np.clip(df.get('Fwd Packets/s', np.zeros(len(df))) / 1000, 0, 100),
            np.clip(df.get('Total Fwd Packets', np.zeros(len(df))) / 100, 0, 100),
            np.clip(df.get('Active Mean', np.zeros(len(df))) / 10000, 0, 100),
            np.zeros(len(df)),  # Scan tools
            np.zeros(len(df)),  # Port specs
            np.zeros(len(df))   # Scan flags
        ])
        
        return X

# Singleton
cicids_loader = CICIDS2017Loader()