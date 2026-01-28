# ml_models/datasets/README.md

# Public Security Datasets

## Automatic Download (NSL-KDD)

NSL-KDD will be downloaded automatically when you run the training script.
```bash
python -m ml_models.train_with_datasets
```

## Manual Download (Recommended for Best Results)

### CICIDS2017 (Recommended)
- **Source**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Size**: ~2.5GB
- **Contains**: 5 days of realistic network traffic with labeled attacks
- **Download Steps**:
  1. Visit the website
  2. Download CSV files
  3. Extract to: `ml_models/datasets/raw/CICIDS2017/`

**Files needed:**
- Monday-WorkingHours.csv (benign traffic)
- Friday-WorkingHours-Afternoon-DDos.csv (attacks)

### UNSW-NB15 (Optional)
- **Source**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Size**: ~500MB
- **Contains**: Modern attack categories
- **Extract to**: `ml_models/datasets/raw/UNSW-NB15/`

## Dataset Information

### NSL-KDD
- **Attacks**: DoS, Probe, R2L (remote to local), U2R (user to root)
- **Samples**: ~125,000 training + 22,000 testing
- **Used for**: All 6 detectors
- **Quality**: Classic benchmark, well-tested

### CICIDS2017
- **Attacks**: DDoS, PortScan, Botnet, Web Attacks, Infiltration
- **Samples**: ~2.8 million
- **Used for**: Cryptominer, Exfiltration, Network detectors
- **Quality**: Modern, realistic traffic patterns

## Feature Mapping

Our system uses 5-7 core features per detector. Public datasets have 40+ features which we map:

| Our Feature | NSL-KDD Mapping | CICIDS Mapping |
|-------------|----------------|----------------|
| cpu_usage | src_bytes | Flow Bytes/s |
| memory_usage | dst_bytes | Fwd Packets/s |
| network_bytes | count | Flow Bytes/s |
| process_count | srv_count | Total Fwd Packets |
| open_files | num_file_creations | Active Mean |