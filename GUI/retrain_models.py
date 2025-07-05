import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import pickle
import FeatureExtraction
from sklearn.preprocessing import LabelEncoder
import os

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))

# Helper to build paths relative to project root
def project_path(*parts):
    return os.path.join(PROJECT_ROOT, *parts)

def preprocess_data(data):
    # Drop non-numeric columns
    numeric_data = data.select_dtypes(include=['int64', 'float64'])
    
    # Handle any missing values
    numeric_data = numeric_data.fillna(0)
    
    return numeric_data

def load_data():
    # Paths
    new_csv = project_path('extracted_csv_files', 'xgboost_retrain.csv')
    legit_csv = project_path('extracted_csv_files', 'legitimate_websites_1.11.csv')
    phish_csv = project_path('extracted_csv_files', 'phishing_websites_1.11.csv')
    # Load base data
    legitimate_urls = pd.read_csv(legit_csv)
    phishing_urls = pd.read_csv(phish_csv)
    data = pd.concat([legitimate_urls, phishing_urls], ignore_index=True)
    # If new CSV exists, concatenate it as well
    if os.path.exists(new_csv):
        print(f"Loading and concatenating data from {new_csv}...")
        new_data = pd.read_csv(new_csv)
        # Remove duplicates based on Address if present
        if 'Address' in new_data.columns and 'Address' in data.columns:
            combined = pd.concat([data, new_data], ignore_index=True)
            combined = combined.drop_duplicates(subset=['Address'], keep='last')
            data = combined
        else:
            data = pd.concat([data, new_data], ignore_index=True)
    # Define feature columns (exclude non-features)
    feature_cols = [
        'long_url', 'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation',
        'sub_domains', 'having_ip_address', 'shortening_service', 'https_token',
        'web_traffic', 'domain_registration_length', 'dns_record', 'age_of_domain',
        'statistical_report'
    ]
    X = data[feature_cols]
    y = data['label']
    X = preprocess_data(X)
    return X, y

def train_and_save_models():
    print("Loading data...")
    X, y = load_data()
    
    print("Training XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    xgb_model.fit(X, y)
    
    # print("Training Random Forest model...")
    # rf_model = RandomForestClassifier(
    #     n_estimators=100,
    #     max_depth=10,
    #     random_state=42
    # )
    # rf_model.fit(X, y)
    
    print("Saving models...")
    # Save XGBoost model
    model_path = os.path.join(SCRIPT_DIR, 'XGBoostModel_12000.sav')
    xgb_model.save_model(model_path)
    
    # Save Random Forest model
    # with open('RFmodel_12000.sav', 'wb') as f:
    #     pickle.dump(rf_model, f)
    
    print(f"Models saved successfully! Model saved to {model_path}")

if __name__ == "__main__":
    train_and_save_models() 