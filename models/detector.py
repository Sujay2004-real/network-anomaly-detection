import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Define the set of features we will use for training and inference
FEATURE_COLS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Average Packet Size',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count'
]

class AnomalyDetector:
    def __init__(self, contamination=0.02, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_trained = False

    def clean_data(self, df):
        """Cleans and extracts selected features, handling NaNs and Infinities."""
        # Standardize column names (strip whitespace)
        df_clean = df.copy()
        df_clean.columns = [col.strip() for col in df_clean.columns]
        
        # Verify that all required features exist in the dataframe
        missing_cols = [col for col in FEATURE_COLS if col not in df_clean.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns in input dataframe: {missing_cols}")
            
        # Select features
        df_features = df_clean[FEATURE_COLS].copy()
        
        # Replace inf and -inf with NaN, then fill NaNs with 0
        df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_features.fillna(0, inplace=True)
        
        # Clip negative values to 0 and log-transform to handle exponential scale skewness
        df_features = np.clip(df_features, 0, None)
        df_features = np.log1p(df_features)
        
        return df_features

    def train(self, df):
        """Cleans, scales, and trains the Isolation Forest model on baseline data."""
        print("Cleaning training data...")
        X = self.clean_data(df)
        
        print("Scaling features...")
        X_scaled = self.scaler.fit_transform(X)
        
        print("Fitting Isolation Forest model...")
        self.model.fit(X_scaled)
        self.is_trained = True
        print("Training complete.")

    def predict(self, df):
        """Scores and predicts anomaly status for input dataframe.
        
        Returns:
            predictions: numpy array of 1 (normal) or -1 (anomaly)
            scores: numpy array of anomaly scores (lower/more negative means more anomalous)
        """
        if not self.is_trained:
            raise ValueError("Model is not trained. Load a model or train first.")
            
        X = self.clean_data(df)
        X_scaled = self.scaler.transform(X)
        
        predictions = self.model.predict(X_scaled)
        # Isolation Forest decision_function returns anomaly scores (negative are anomalies, positive are normal)
        scores = self.model.decision_function(X_scaled)
        
        return predictions, scores

    def save(self, directory):
        """Saves model and scaler to the specified directory."""
        os.makedirs(directory, exist_ok=True)
        joblib.dump(self.scaler, os.path.join(directory, 'scaler.joblib'))
        joblib.dump(self.model, os.path.join(directory, 'isolation_forest.joblib'))
        joblib.dump(self.is_trained, os.path.join(directory, 'metadata.joblib'))
        print(f"Model saved successfully to {directory}")

    def load(self, directory):
        """Loads model and scaler from the specified directory."""
        scaler_path = os.path.join(directory, 'scaler.joblib')
        model_path = os.path.join(directory, 'isolation_forest.joblib')
        meta_path = os.path.join(directory, 'metadata.joblib')
        
        if not (os.path.exists(scaler_path) and os.path.exists(model_path)):
            raise FileNotFoundError(f"Model files not found in {directory}")
            
        self.scaler = joblib.load(scaler_path)
        self.model = joblib.load(model_path)
        self.is_trained = joblib.load(meta_path) if os.path.exists(meta_path) else True
        print(f"Model loaded successfully from {directory}")
