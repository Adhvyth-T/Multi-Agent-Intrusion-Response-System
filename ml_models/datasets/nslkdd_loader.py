# ml_models/datasets/nslkdd_loader.py
"""
Load and process NSL-KDD dataset.
"""
import pandas as pd
import numpy as np
from pathlib import Path
import structlog

log = structlog.get_logger()

class NSLKDDLoader:
    """Load NSL-KDD dataset with attack type mapping."""
    
    # NSL-KDD column names
    COLUMNS = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
        'attack_type', 'difficulty'
    ]
    
    # Attack type categories
    ATTACK_CATEGORIES = {
        'normal': 'benign',
        'back': 'dos',
        'land': 'dos',
        'neptune': 'dos',
        'pod': 'dos',
        'smurf': 'dos',
        'teardrop': 'dos',
        'apache2': 'dos',
        'udpstorm': 'dos',
        'processtable': 'dos',
        'mailbomb': 'dos',
        'ipsweep': 'probe',
        'nmap': 'probe',
        'portsweep': 'probe',
        'satan': 'probe',
        'mscan': 'probe',
        'saint': 'probe',
        'ftp_write': 'r2l',
        'guess_passwd': 'r2l',
        'imap': 'r2l',
        'multihop': 'r2l',
        'phf': 'r2l',
        'spy': 'r2l',
        'warezclient': 'r2l',
        'warezmaster': 'r2l',
        'sendmail': 'r2l',
        'named': 'r2l',
        'snmpgetattack': 'r2l',
        'snmpguess': 'r2l',
        'xlock': 'r2l',
        'xsnoop': 'r2l',
        'worm': 'r2l',
        'buffer_overflow': 'u2r',
        'loadmodule': 'u2r',
        'perl': 'u2r',
        'rootkit': 'u2r',
        'httptunnel': 'u2r',
        'ps': 'u2r',
        'sqlattack': 'u2r',
        'xterm': 'u2r'
    }
    
    # Map to our threat types
    OUR_THREAT_MAPPING = {
        'dos': 'anomalous_network',
        'probe': 'suspicious_process',
        'r2l': 'data_exfiltration',
        'u2r': 'privilege_escalation'
    }
    
    def __init__(self):
        self.base_dir = Path("ml_models/datasets/raw")
    
    def load_dataset(self, split='train') -> pd.DataFrame:
        """Load NSL-KDD dataset."""
        filepath = self.base_dir / f"KDD{split}.txt"
        
        if not filepath.exists():
            log.error(f"Dataset not found: {filepath}")
            return None
        
        log.info(f"Loading NSL-KDD {split} dataset...")
        
        df = pd.read_csv(filepath, names=self.COLUMNS, header=None)
        
        # Clean attack types (remove difficulty level)
        df['attack_type'] = df['attack_type'].str.replace(r'\d+', '', regex=True)
        
        # Add category
        df['category'] = df['attack_type'].map(self.ATTACK_CATEGORIES)
        
        # Map to our threat types
        df['our_threat'] = df['category'].map(self.OUR_THREAT_MAPPING)
        
        log.info(f"Loaded {len(df)} samples")
        log.info(f"Attack distribution:\n{df['category'].value_counts()}")
        
        return df
    
    def get_features_for_threat(self, df: pd.DataFrame, threat_type: str) -> tuple:
        """Extract features for specific threat type."""
        
        if threat_type == 'cryptominer':
            # High CPU simulation (use connection patterns as proxy)
            benign = df[df['category'] == 'benign'].copy()
            attack = df[df['category'] == 'dos'].copy()  # DoS simulates resource exhaustion
            
            # Map features to: [cpu, memory, network, processes, files, high_cpu_flag, mining_port]
            X_benign = np.column_stack([
                benign['src_bytes'].values / 1000,  # Network activity as CPU proxy
                benign['dst_bytes'].values / 1000,  # Memory proxy
                benign['count'].values * 100,  # Network
                benign['srv_count'].values,  # Processes
                benign['num_file_creations'].values,  # Files
                np.zeros(len(benign)),  # High CPU flag
                np.zeros(len(benign))   # Mining port flag
            ])
            
            X_attack = np.column_stack([
                attack['src_bytes'].values / 1000,
                attack['dst_bytes'].values / 1000,
                attack['count'].values * 100,
                attack['srv_count'].values,
                attack['num_file_creations'].values,
                np.ones(len(attack)),  # High CPU flag for attacks
                np.zeros(len(attack))
            ])
            
            # Normalize to 0-100 range
            X_benign = np.clip(X_benign, 0, 100)
            X_attack = np.clip(X_attack, 0, 100)
            
            return X_benign, X_attack
        
        elif threat_type == 'data_exfiltration':
            benign = df[df['category'] == 'benign']
            attack = df[df['category'] == 'r2l']  # Remote to Local attacks
            
            # [network_bytes, cpu, tools_flag, domains_flag, post_flag, redirect_flag, complexity, processes]
            X_benign = np.column_stack([
                benign['dst_bytes'].values / 1000,
                benign['src_bytes'].values / 10000,
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                benign['num_file_creations'].values / 10,
                benign['count'].values / 10,
                benign['srv_count'].values
            ])
            
            X_attack = np.column_stack([
                attack['dst_bytes'].values / 1000,
                attack['src_bytes'].values / 10000,
                np.ones(len(attack)),  # Flag suspicious activity
                np.ones(len(attack)),
                np.ones(len(attack)),
                attack['num_file_creations'].values / 10,
                attack['count'].values / 10,
                attack['srv_count'].values
            ])
            
            y = np.concatenate([np.zeros(len(benign)), np.ones(len(attack))])
            X = np.vstack([X_benign, X_attack])
            
            # Clip and shuffle
            X = np.clip(X, 0, 100)
            indices = np.random.permutation(len(X))
            
            return X[indices], y[indices]
        
        elif threat_type == 'privilege_escalation':
            benign = df[df['category'] == 'benign']
            attack = df[df['category'] == 'u2r']  # User to Root attacks
            
            # [escalation_patterns, sensitive_paths, root_access, perms, chmod, cpu, processes, complexity]
            X_benign = np.column_stack([
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                benign['root_shell'].values,  # Legitimate root shells
                benign['num_compromised'].values,
                np.zeros(len(benign)),
                benign['src_bytes'].values / 10000,
                benign['srv_count'].values,
                benign['count'].values / 20
            ])
            
            X_attack = np.column_stack([
                np.ones(len(attack)) * 2,  # High escalation patterns
                np.ones(len(attack)),
                attack['root_shell'].values + 1,
                attack['num_compromised'].values,
                np.ones(len(attack)),
                attack['src_bytes'].values / 10000,
                attack['srv_count'].values,
                attack['count'].values / 20
            ])
            
            X = np.vstack([X_benign, X_attack])
            X = np.clip(X, 0, 100)
            
            return X
        
        elif threat_type == 'network_anomaly':
            benign = df[df['category'] == 'benign']
            attack = df[df['category'] == 'probe']  # Port scans, network probes
            
            # [network_bytes, cpu, processes, files, scan_tools, port_specs, scan_flags]
            X_benign = np.column_stack([
                benign['src_bytes'].values / 1000,
                benign['dst_bytes'].values / 10000,
                benign['srv_count'].values,
                benign['num_file_creations'].values,
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                np.zeros(len(benign))
            ])
            
            X_attack = np.column_stack([
                attack['src_bytes'].values / 1000,
                attack['dst_bytes'].values / 10000,
                attack['srv_count'].values,
                attack['num_file_creations'].values,
                np.ones(len(attack)),  # Scan tools detected
                np.ones(len(attack)),
                np.ones(len(attack))
            ])
            
            X = np.vstack([X_benign, X_attack])
            X = np.clip(X, 0, 100)
            
            return X
        
        elif threat_type == 'reverse_shell':
            benign = df[df['category'] == 'benign']
            attack = df[df['category'] == 'r2l']
            
            # [network_bytes, processes, shell_patterns, redirection, background, piping, cpu, cmd_length]
            X_benign = np.column_stack([
                benign['dst_bytes'].values / 1000,
                benign['srv_count'].values,
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                np.zeros(len(benign)),
                benign['src_bytes'].values / 10000,
                benign['count'].values / 10
            ])
            
            X_attack = np.column_stack([
                attack['dst_bytes'].values / 1000,
                attack['srv_count'].values,
                np.ones(len(attack)) * 2,  # Multiple shell patterns
                np.ones(len(attack)),
                np.ones(len(attack)),
                np.ones(len(attack)),
                attack['src_bytes'].values / 10000,
                attack['count'].values / 10
            ])
            
            X = np.vstack([X_benign, X_attack])
            X = np.clip(X, 0, 100)
            
            return X
        
        return None

# Singleton
nslkdd_loader = NSLKDDLoader()