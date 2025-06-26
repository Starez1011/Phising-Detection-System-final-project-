import os
import xgboost as xgb
import pandas as pd

def get_model_path(model_name):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, model_name)

def load_xgb_model():
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42,
        tree_method='hist',
        n_jobs=1
    )
    xgb_model_path = get_model_path('XGBoostModel_12000.sav')
    xgb_model.load_model(xgb_model_path)
    return xgb_model

def preprocess_data(data):
    required_features = [
        'long_url',
        'having_@_symbol',
        'redirection_//_symbol',
        'prefix_suffix_seperation',
        'sub_domains',
        'having_ip_address',
        'shortening_service',
        'https_token',
        'web_traffic',
        'domain_registration_length',
        'dns_record',
        'age_of_domain',
        'statistical_report'
    ]
    numeric_data = data.select_dtypes(include=['int64', 'float64'])
    numeric_data = numeric_data.fillna(0)
    for feature in required_features:
        if feature not in numeric_data.columns:
            numeric_data[feature] = 0
    return numeric_data[required_features]
