import os
import argparse
import sys
from capture.simulator import TrafficSimulator

def main():
    parser = argparse.ArgumentParser(description="Run live network anomaly detection pipeline (playback simulator mode).")
    parser.add_argument(
        "--dataset-dir", 
        type=str, 
        default=r"C:\Users\sujay\.cache\kagglehub\datasets\chethuhn\network-intrusion-dataset\versions\1",
        help="Path to the directory containing CIC-IDS2017 CSV files"
    )
    parser.add_argument(
        "--model-dir", 
        type=str, 
        default=None, 
        help="Path to model directory containing trained isolation_forest.joblib and scaler.joblib"
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["playback", "live"],
        default="playback",
        help="Pipeline execution mode: playback (dataset simulator) or live (actual packet sniffing)"
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to sniff on in live mode (e.g., 'Ethernet', 'VMware Network Adapter VMnet8'). Defaults to system default."
    )
    args = parser.parse_args()

    # Determine default model path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = args.model_dir or os.path.join(script_dir, "models", "saved_model")
    
    if not os.path.exists(model_dir):
        print(f"Warning: Model directory {model_dir} does not exist. Run train.py first to train a model.")
        # We can still proceed; simulator will use threshold rules
        
    print(f"Initializing background detection pipeline ({args.mode.upper()} Mode)...")
    if args.iface:
        print(f"Sniffing on interface: {args.iface}")
    simulator = TrafficSimulator(dataset_dir=args.dataset_dir, model_dir=model_dir, mode=args.mode, iface=args.iface)
    
    try:
        simulator.run_loop()
    except KeyboardInterrupt:
        print("\nStopping background pipeline...")
        simulator.is_running = False
        simulator.reset_files()
        print("Pipeline stopped.")

if __name__ == "__main__":
    main()

