# ml_models/datasets/downloader.py
"""
Download and prepare public security datasets.
"""
import os
import requests
import zipfile
import gzip
import shutil
from pathlib import Path
import structlog

log = structlog.get_logger()

class DatasetDownloader:
    """Download public cybersecurity datasets."""
    
    BASE_DIR = Path("ml_models/datasets/raw")
    
    DATASETS = {
        "nslkdd": {
            "train": "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTrain%2B.txt",
            "test": "https://github.com/jmnwong/NSL-KDD-Dataset/raw/master/KDDTest%2B.txt",
            "description": "NSL-KDD: Network intrusion detection dataset"
        },
        "cicids2017": {
            "info": "Download from: https://www.unb.ca/cic/datasets/ids-2017.html",
            "description": "CICIDS2017: Realistic network traffic with labeled attacks",
            "note": "Manual download required (large files ~2.5GB)"
        },
        "unsw_nb15": {
            "info": "Download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "description": "UNSW-NB15: Modern network intrusion dataset",
            "note": "Manual download required"
        }
    }
    
    def __init__(self):
        self.BASE_DIR.mkdir(parents=True, exist_ok=True)
    
    def download_nslkdd(self) -> bool:
        """Download NSL-KDD dataset (automatic)."""
        log.info("Downloading NSL-KDD dataset...")
        
        try:
            for split, url in [("train", self.DATASETS["nslkdd"]["train"]),
                              ("test", self.DATASETS["nslkdd"]["test"])]:
                output_path = self.BASE_DIR / f"KDD{split}.txt"
                
                if output_path.exists():
                    log.info(f"File already exists: {output_path}")
                    continue
                
                response = requests.get(url, stream=True)
                response.raise_for_status()
                
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                log.info(f"Downloaded: {output_path}")
            
            log.info("✅ NSL-KDD dataset downloaded successfully")
            return True
            
        except Exception as e:
            log.error(f"Failed to download NSL-KDD", error=str(e))
            return False
    
    def check_cicids2017(self) -> bool:
        """Check if CICIDS2017 dataset exists."""
        cicids_dir = self.BASE_DIR / "CICIDS2017"
        
        if not cicids_dir.exists():
            log.warning("CICIDS2017 not found. Please download manually from:")
            log.warning("https://www.unb.ca/cic/datasets/ids-2017.html")
            log.warning(f"Extract to: {cicids_dir}")
            return False
        
        csv_files = list(cicids_dir.glob("*.csv"))
        if not csv_files:
            log.warning(f"No CSV files found in {cicids_dir}")
            return False
        
        log.info(f"✅ Found {len(csv_files)} CICIDS2017 CSV files")
        return True
    
    def check_unsw_nb15(self) -> bool:
        """Check if UNSW-NB15 dataset exists."""
        unsw_dir = self.BASE_DIR / "UNSW-NB15"
        
        if not unsw_dir.exists():
            log.warning("UNSW-NB15 not found. Please download manually from:")
            log.warning("https://research.unsw.edu.au/projects/unsw-nb15-dataset")
            log.warning(f"Extract to: {unsw_dir}")
            return False
        
        csv_files = list(unsw_dir.glob("*.csv"))
        if not csv_files:
            log.warning(f"No CSV files found in {unsw_dir}")
            return False
        
        log.info(f"✅ Found {len(csv_files)} UNSW-NB15 CSV files")
        return True
    
    def download_all(self):
        """Download all available datasets."""
        log.info("="*60)
        log.info("Dataset Downloader")
        log.info("="*60)
        
        # NSL-KDD (automatic)
        self.download_nslkdd()
        
        # CICIDS2017 (manual check)
        self.check_cicids2017()
        
        # UNSW-NB15 (manual check)
        self.check_unsw_nb15()
        
        log.info("="*60)
        log.info("Dataset download complete!")
        log.info("="*60)

if __name__ == "__main__":
    downloader = DatasetDownloader()
    downloader.download_all()