"""
Dataset loaders for training ML models.
"""

from .downloader import DatasetDownloader
from .nslkdd_loader import nslkdd_loader
from .cicids_loader import cicids_loader

__all__ = [
    'DatasetDownloader',
    'nslkdd_loader',
    'cicids_loader'
]
