# ml_models/train_with_datasets.py
"""
Train ML models using public datasets (NSL-KDD, CICIDS2017).
Usage: python -m ml_models.train_with_datasets
"""
import numpy as np
import structlog
from pathlib import Path

from .cryptominer_detector import CryptominerDetector
from .exfiltration_detector import ExfiltrationDetector
from .privilege_detector import PrivilegeDetector
from .shell_detector import ReverseShellDetector
from .escape_detector import ContainerEscapeDetector
from .network_detector import NetworkAnomalyDetector

from .datasets.downloader import DatasetDownloader
from .datasets.nslkdd_loader import nslkdd_loader
from .datasets.cicids_loader import cicids_loader

log = structlog.get_logger()

class PublicDatasetTrainer:
    """Train models using public datasets."""
    
    def __init__(self):
        self.downloader = DatasetDownloader()
    
    def prepare_datasets(self):
        """Download and prepare datasets."""
        log.info("="*60)
        log.info("Preparing Public Datasets")
        log.info("="*60)
        
        # Download NSL-KDD (automatic)
        self.downloader.download_nslkdd()
        
        # Check for CICIDS2017
        has_cicids = self.downloader.check_cicids2017()
        
        return has_cicids
    
    def train_with_nslkdd(self):
        """Train all models using NSL-KDD dataset."""
        log.info("\n" + "="*60)
        log.info("Training with NSL-KDD Dataset")
        log.info("="*60)
        
        # Load dataset
        df = nslkdd_loader.load_dataset('train')
        if df is None:
            log.error("Failed to load NSL-KDD dataset")
            return False
        
        # Train Cryptominer Detector
        log.info("\n[1/6] Training Cryptominer Detector...")
        cryptominer = CryptominerDetector()
        if not cryptominer.trained:
            X_benign, X_attack = nslkdd_loader.get_features_for_threat(df, 'cryptominer')
            log.info(f"Training on {len(X_benign)} benign + {len(X_attack)} attack samples")
            cryptominer.train(X_benign)
            log.info("✅ Cryptominer detector trained")
        
        # Train Exfiltration Detector
        log.info("\n[2/6] Training Exfiltration Detector...")
        exfiltration = ExfiltrationDetector()
        if not exfiltration.trained:
            X, y = nslkdd_loader.get_features_for_threat(df, 'data_exfiltration')
            log.info(f"Training on {len(X)} labeled samples")
            exfiltration.train(X, y)
            log.info("✅ Exfiltration detector trained")
        
        # Train Privilege Detector
        log.info("\n[3/6] Training Privilege Escalation Detector...")
        privilege = PrivilegeDetector()
        if not privilege.trained:
            X = nslkdd_loader.get_features_for_threat(df, 'privilege_escalation')
            log.info(f"Training on {len(X)} samples")
            privilege.train(X)
            log.info("✅ Privilege detector trained")
        
        # Train Shell Detector
        log.info("\n[4/6] Training Reverse Shell Detector...")
        shell = ReverseShellDetector()
        if not shell.trained:
            X = nslkdd_loader.get_features_for_threat(df, 'reverse_shell')
            log.info(f"Training on {len(X)} samples")
            shell.train(X)
            log.info("✅ Shell detector trained")
        
        # Train Network Detector
        log.info("\n[5/6] Training Network Anomaly Detector...")
        network = NetworkAnomalyDetector()
        if not network.trained:
            X = nslkdd_loader.get_features_for_threat(df, 'network_anomaly')
            log.info(f"Training on {len(X)} samples")
            network.train(X)
            log.info("✅ Network detector trained")
        
        # Container Escape (rule-based)
        log.info("\n[6/6] Initializing Container Escape Detector...")
        escape = ContainerEscapeDetector()
        log.info("✅ Escape detector ready (rule-based)")
        
        return True
    
    def train_with_cicids(self):
        """Train models using CICIDS2017 dataset."""
        log.info("\n" + "="*60)
        log.info("Training with CICIDS2017 Dataset")
        log.info("="*60)
        
        # Load Monday dataset (contains benign traffic)
        df = cicids_loader.load_dataset('Monday')
        if df is None:
            log.warning("Failed to load CICIDS2017 - skipping")
            return False
        
        # Load Friday dataset (contains attacks)
        df_attacks = cicids_loader.load_dataset('Friday')
        if df_attacks is not None:
            df = pd.concat([df, df_attacks], ignore_index=True)
        
        # Train Cryptominer Detector
        log.info("\n[1/3] Training Cryptominer Detector with CICIDS...")
        cryptominer = CryptominerDetector()
        X_benign, X_attack = cicids_loader.get_features_for_threat(df, 'cryptominer')
        if X_benign is not None:
            log.info(f"Training on {len(X_benign)} benign samples")
            cryptominer.train(X_benign)
            log.info("✅ Cryptominer detector retrained with CICIDS")
        
        # Train Exfiltration Detector
        log.info("\n[2/3] Training Exfiltration Detector with CICIDS...")
        exfiltration = ExfiltrationDetector()
        result = cicids_loader.get_features_for_threat(df, 'data_exfiltration')
        if result is not None:
            X, y = result
            log.info(f"Training on {len(X)} samples")
            exfiltration.train(X, y)
            log.info("✅ Exfiltration detector retrained with CICIDS")
        
        # Train Network Detector
        log.info("\n[3/3] Training Network Detector with CICIDS...")
        network = NetworkAnomalyDetector()
        X = cicids_loader.get_features_for_threat(df, 'network_anomaly')
        if X is not None:
            log.info(f"Training on {len(X)} samples")
            network.train(X)
            log.info("✅ Network detector retrained with CICIDS")
        
        return True
    
    def train_all(self):
        """Train all models with available datasets."""
        log.info("="*60)
        log.info("Training ML Models with Public Datasets")
        log.info("="*60)
        
        # Prepare datasets
        has_cicids = self.prepare_datasets()
        
        # Train with NSL-KDD (always available - auto-download)
        success_nslkdd = self.train_with_nslkdd()
        
        # Train with CICIDS if available
        if has_cicids:
            success_cicids = self.train_with_cicids()
        else:
            log.info("\nCICIDS2017 not available - skipping enhanced training")
            log.info("Models trained with NSL-KDD will work fine!")
        
        log.info("\n" + "="*60)
        log.info("✅ TRAINING COMPLETE")
        log.info("="*60)
        log.info("Models saved to: ml_models/trained_models/")
        log.info("\nTo use trained models:")
        log.info("  python main.py")

def main():
    """Main training entry point."""
    trainer = PublicDatasetTrainer()
    trainer.train_all()

if __name__ == "__main__":
    import pandas as pd  # Import here for CICIDS
    main()