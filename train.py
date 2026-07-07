import os
import argparse
import pandas as pd
import numpy as np
from models.detector import AnomalyDetector

def main():
    parser = argparse.ArgumentParser(description="Train network anomaly detection model.")
    parser.add_argument(
        "--dataset-dir", 
        type=str, 
        default=r"C:\Users\sujay\.cache\kagglehub\datasets\chethuhn\network-intrusion-dataset\versions\1",
        help="Path to the directory containing CIC-IDS2017 CSV files"
    )
    parser.add_argument(
        "--sample-size", 
        type=int, 
        default=1000000, 
        help="Number of rows to sample from Monday's benign file for training"
    )
    parser.add_argument(
        "--contamination", 
        type=float, 
        default=0.02, 
        help="Proportion of outliers in the training data"
    )
    args = parser.parse_args()

    monday_file = os.path.join(args.dataset_dir, "Monday-WorkingHours.pcap_ISCX.csv")
    if not os.path.exists(monday_file):
        raise FileNotFoundError(f"Monday baseline file not found at: {monday_file}")

    print(f"Loading baseline training data from: {monday_file}")
    # Read a sample to train faster, using a random sample or chunk
    # We read first 10k to check columns then read chunks or random sample
    print(f"Reading up to {args.sample_size} rows...")
    
    # Read in chunks to handle large file memory footprint cleanly
    chunks = []
    chunksize = 50000
    total_loaded = 0
    for chunk in pd.read_csv(monday_file, chunksize=chunksize):
        chunks.append(chunk)
        total_loaded += len(chunk)
        if total_loaded >= args.sample_size:
            break
            
    if not chunks:
        raise ValueError(f"No data found in {monday_file}. Is the file empty?")
        
    df = pd.concat(chunks, ignore_index=True)
    if len(df) > args.sample_size:
        df = df.sample(n=args.sample_size, random_state=42).reset_index(drop=True)
        
    print(f"Loaded {len(df)} rows of baseline normal traffic.")

    # Initialize and train detector
    detector = AnomalyDetector(contamination=args.contamination)
    detector.train(df)

    # Validate on training data
    preds, scores = detector.predict(df)
    anomalies = np.sum(preds == -1)
    normal = np.sum(preds == 1)
    print("\n=== Training Evaluation ===")
    print(f"Total evaluated: {len(preds)}")
    print(f"Normal predictions (1): {normal} ({normal/len(preds)*100:.2f}%)")
    print(f"Anomaly predictions (-1): {anomalies} ({anomalies/len(preds)*100:.2f}%)")
    print(f"Mean Anomaly Score: {np.mean(scores):.4f} (Min: {np.min(scores):.4f}, Max: {np.max(scores):.4f})")

    # Save model
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "saved_model")
    detector.save(model_dir)

if __name__ == "__main__":
    main()
