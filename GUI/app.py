from flask import Flask, render_template, request
import FeatureExtraction
import pickle
import warnings
import xgboost as xgb
import pandas as pd

app = Flask(__name__, static_url_path='/static')

# Suppress warnings
warnings.filterwarnings('ignore')

# Create a FeatureExtraction instance
feature_extractor = FeatureExtraction.FeatureExtraction()

def preprocess_data(data):
    """Preprocess the data to match model's expected format"""
    # Ensure all required features are present
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
    
    # Drop non-numeric columns
    numeric_data = data.select_dtypes(include=['int64', 'float64'])
    
    # Handle any missing values
    numeric_data = numeric_data.fillna(0)
    
    # Ensure all required features are present
    for feature in required_features:
        if feature not in numeric_data.columns:
            numeric_data[feature] = 0
    
    # Reorder columns to match model's expected order
    return numeric_data[required_features]

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

try:
    # Load XGBoost model
    model = xgb.XGBClassifier()
    model.load_model('XGBoostModel_12000.sav')
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading XGBoost model: {e}")
    model = None

def get_reasons(features):
    reasons = []
    feature_descriptions = {
        'long_url': 'URL length is suspiciously long',
        'having_@_symbol': 'URL contains @ symbol (high risk)',
        'redirection_//_symbol': 'URL contains suspicious redirection (high risk)',
        'prefix_suffix_seperation': 'Domain contains hyphens',
        'sub_domains': 'URL has multiple subdomains',
        'having_ip_address': 'URL contains IP address (high risk)',
        'shortening_service': 'URL uses URL shortening service (high risk)',
        'https_token': 'URL has suspicious HTTPS tokens',
        'web_traffic': 'Suspicious web traffic patterns',
        'domain_registration_length': 'Domain registration period is short',
        'dns_record': 'No DNS record found',
        'age_of_domain': 'Domain is very new',
        'statistical_report': 'Statistical analysis indicates suspicious patterns'
    }
    
    # Check typo-squatting first
    typo_check = feature_extractor.check_typo_squatting(request.form['url'])
    if typo_check['is_typo_squatting']:
        reasons.append(f"⚠️ HIGH RISK: This appears to be a typo-squatting attempt")
        reasons.append(f"This domain is trying to impersonate {typo_check['company_name']}'s official website ({typo_check['original_domain']})")
        reasons.append("Common typo-squatting techniques detected:")
        reasons.append("- Using numbers instead of letters (e.g., '0' instead of 'o')")
        reasons.append("- Using similar-looking characters")
        reasons.append("- Slight misspellings of the original domain")
        reasons.append(f"Please visit the official website: {typo_check['original_domain']}")
        return reasons
    
    # Check blacklist
    blacklist_check = feature_extractor.check_blacklist(request.form['url'])
    if blacklist_check['is_blacklisted']:
        reasons.append(f"⚠️ HIGH RISK: {blacklist_check['reason']}")
        if 'similar_to' in blacklist_check:
            reasons.append(f"This domain is similar to a known malicious domain: {blacklist_check['similar_to']}")
        return reasons
    
    # High risk features that strongly indicate phishing
    high_risk_features = ['having_@_symbol', 'redirection_//_symbol', 'having_ip_address', 'shortening_service']
    
    # Features that might be normal for certain types of legitimate sites
    context_dependent_features = ['age_of_domain', 'domain_registration_length', 'sub_domains', 'prefix_suffix_seperation']
    
    # Check if the URL is trusted
    is_trusted = feature_extractor.is_trusted_domain(request.form['url'])
    
    # Add warning for suspicious TLD or domain
    if feature_extractor.check_suspicious_tld(request.form['url']):
        reasons.append("WARNING: This website uses a suspicious top-level domain commonly associated with malicious sites")
    if feature_extractor.check_suspicious_domain(request.form['url']):
        reasons.append("WARNING: This domain contains suspicious patterns that may indicate phishing")
    
    # Only show feature warnings if the site is not trusted
    if not is_trusted:
        for feature, value in features.items():
            if value == 1 and feature in feature_descriptions:
                # Add context for certain features
                if feature in context_dependent_features:
                    if '.gov' in request.form['url']:
                        reasons.append(f"{feature_descriptions[feature]} (Note: This is normal for government websites)")
                    elif feature_extractor.is_known_bank(request.form['url']):
                        reasons.append(f"{feature_descriptions[feature]} (Note: This is normal for financial websites)")
                    else:
                        reasons.append(feature_descriptions[feature])
                else:
                    reasons.append(feature_descriptions[feature])
    
    # Add additional context
    if '.gov' in request.form['url']:
        reasons.append("This appears to be a government website (.gov domain)")
    elif feature_extractor.is_known_bank(request.form['url']):
        reasons.append("This is a legitimate financial website")
    elif is_trusted:
        reasons.append("This is a trusted website")
    elif not reasons:
        reasons.append("No suspicious features detected")
    
    return reasons

@app.route('/getURL', methods=['GET', 'POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        
        # Validate URL first
        is_valid, result = feature_extractor.validate_url(url)
        if not is_valid:
            return render_template("home.html", error="Invalid URL", reasons=[result])
        
        # Use the validated URL (which might have http:// added)
        url = result
        
        if model is None:
            return render_template("home.html", error="Error: Model not loaded properly")
        
        try:
            # Check typo-squatting first
            typo_check = feature_extractor.check_typo_squatting(url)
            if typo_check['is_typo_squatting']:
                return render_template("home.html", 
                                    error="⚠️ HIGH RISK: This URL is Phishing",
                                    reasons=[
                                        f"⚠️ HIGH RISK: This appears to be a typo-squatting attempt",
                                        f"This domain is trying to impersonate {typo_check['company_name']}'s official website ({typo_check['original_domain']})",
                                        "Common typo-squatting techniques detected:",
                                        "- Using numbers instead of letters (e.g., '0' instead of 'o')",
                                        "- Using similar-looking characters",
                                        "- Slight misspellings of the original domain",
                                        f"Please visit the official website: {typo_check['original_domain']}"
                                    ])
            
            # Check blacklist
            blacklist_check = feature_extractor.check_blacklist(url)
            if blacklist_check['is_blacklisted']:
                return render_template("home.html", 
                                    error="⚠️ HIGH RISK: This URL is Phishing",
                                    reasons=[
                                        f"⚠️ HIGH RISK: {blacklist_check['reason']}",
                                        "This domain is known to be malicious and has been blacklisted"
                                    ])
            
            # Get features from URL
            data, phishing_reasons = feature_extractor.getAttributess(url)
            
            # Preprocess the data
            data = preprocess_data(data)
            
            # Make prediction
            predicted_value = model.predict(data)
            features = data.iloc[0].to_dict()
            reasons = get_reasons(features)
            
            # Add any phishing reasons from feature extraction
            if phishing_reasons:
                reasons.extend(phishing_reasons)
            
            # Override prediction for trusted domains
            if feature_extractor.is_trusted_domain(url):
                predicted_value[0] = 0  # Force legitimate classification
            
            # Check for suspicious patterns
            if feature_extractor.check_suspicious_domain(url):
                predicted_value[0] = 1  # Force phishing classification
                reasons.append("⚠️ HIGH RISK: This domain contains suspicious patterns that may indicate phishing")
            
            # Check for suspicious TLD
            if feature_extractor.check_suspicious_tld(url):
                predicted_value[0] = 1  # Force phishing classification
                reasons.append("⚠️ HIGH RISK: This website uses a suspicious top-level domain commonly associated with malicious sites")
            
            if predicted_value[0] == 0:    
                value = "This URL is Legitimate"
                if not reasons:
                    reasons.append("No suspicious features detected")
            else:
                value = "⚠️ HIGH RISK: This URL is Phishing"
            
            return render_template("home.html", error=value, reasons=reasons)
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            return render_template("home.html", error=f"Error during prediction: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)