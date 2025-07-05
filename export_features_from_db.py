import pandas as pd
import sqlite3
from GUI.FeatureExtraction import FeatureExtraction
from urllib.parse import urlparse
import tldextract
import os

# Path to the SQLite database
DB_PATH = 'GUI/instance/phishing.db'
# Output CSV file
OUTPUT_CSV = 'extracted_csv_files/xgboost_retrain.csv'

# Desired column order
DESIRED_COLS = [
    'Protocol', 'Domain_name', 'Address',
    'long_url', 'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation',
    'sub_domains', 'having_ip_address', 'shortening_service', 'https_token',
    'web_traffic', 'domain_registration_length', 'dns_record', 'age_of_domain',
    'statistical_report', 'label'
]

# Load existing CSV if it exists
if os.path.exists(OUTPUT_CSV):
    existing_df = pd.read_csv(OUTPUT_CSV)
    processed_urls = set(existing_df['Address'].astype(str))
else:
    existing_df = None
    processed_urls = set()

# Connect to the database
conn = sqlite3.connect(DB_PATH)

# Fetch url and label from url_check table
query = 'SELECT url, label FROM url_check'
df = pd.read_sql_query(query, conn)

# Only process URLs not already in the CSV
df = df[~df['url'].astype(str).isin(processed_urls)]

# Initialize feature extractor
fe = FeatureExtraction()

# List to hold feature dicts
feature_rows = []

for idx, row in df.iterrows():
    url = row['url']
    label = row['label']
    features_df, _ = fe.getAttributess(url)
    if features_df is not None:
        features = features_df.iloc[0].to_dict()
        # Check if all features are 1 (suspicious subdomain override)
        feature_keys = [k for k in features if k not in ['url', 'protocol', 'domain', 'label']]
        if all(features[k] == 1 for k in feature_keys):
            # Patch the method to ignore suspicious subdomain for this call
            original_method = fe._is_suspicious_subdomain
            fe._is_suspicious_subdomain = lambda sub: False
            features_df2, _ = fe.getAttributess(url)
            fe._is_suspicious_subdomain = original_method
            if features_df2 is not None:
                features = features_df2.iloc[0].to_dict()
                features['suspicious_subdomain'] = 1  # Set only this to 1
        # Add extra info
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        features['Address'] = url  # Rename url to Address
        features['Protocol'] = parsed.scheme  # Protocol first
        features['Domain_name'] = ext.registered_domain  # Domain_name second
        features['label'] = label
        # Remove suspicious_subdomain if present
        if 'suspicious_subdomain' in features:
            del features['suspicious_subdomain']
        feature_rows.append(features)
    else:
        print(f"Skipping URL due to extraction error: {url}")

# Create DataFrame and save to CSV
if feature_rows:
    features_df = pd.DataFrame(feature_rows)
    # Replace 2s in feature columns with the label value for that row
    feature_cols = [col for col in features_df.columns if col not in ['Protocol', 'Domain_name', 'Address', 'label']]
    for idx, row in features_df.iterrows():
        label = row['label']
        for col in feature_cols:
            if row[col] == 2:
                features_df.at[idx, col] = label
    # Force the desired column order, append any extra columns at the end
    extra_cols = [col for col in features_df.columns if col not in DESIRED_COLS]
    ordered_cols = DESIRED_COLS + extra_cols
    features_df = features_df[[col for col in ordered_cols if col in features_df.columns]]
    # Append to existing CSV if it exists
    if existing_df is not None:
        features_df = pd.concat([existing_df, features_df], ignore_index=True)
    features_df.to_csv(OUTPUT_CSV, index=False)
    print(f"Feature CSV saved to {OUTPUT_CSV}")
else:
    print("No new URLs to process. CSV is up to date.") 