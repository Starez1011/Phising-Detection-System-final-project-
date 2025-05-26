from flask import Flask, render_template, request
import FeatureExtraction
import pickle
import warnings
import xgboost as xgb
import pandas as pd
from security_utils import SecurityUtils
from urllib.parse import urlparse

app = Flask(__name__, static_url_path='/static')

# Suppress warnings
warnings.filterwarnings('ignore')

# Create instances
feature_extractor = FeatureExtraction.FeatureExtraction()
security_utils = SecurityUtils()

# Load XGBoost model
try:
    model = xgb.XGBClassifier()
    model.load_model('XGBoostModel_12000.sav')
    print("Model loaded successfully")
except Exception as e:
    print(f"Error loading XGBoost model: {e}")
    model = None

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
    
    url = request.form['url']
    
    # Check for number-for-letter substitutions
    number_letter_map = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b'
    }
    
    suspicious_chars = []
    for char in url:
        if char in number_letter_map:
            suspicious_chars.append(f"'{char}' (mimicking '{number_letter_map[char]}')")
    
    if suspicious_chars:
        reasons.append("⚠️ HIGH RISK: This URL uses numbers to mimic letters")
        reasons.append("Suspicious character substitutions detected:")
        for char in suspicious_chars:
            reasons.append(f"- {char}")
        reasons.append("This is a common phishing technique to make malicious URLs look legitimate")
    
    # Check typo-squatting
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
    
    # Add warning for suspicious TLD or domain
    if feature_extractor.check_suspicious_tld(request.form['url']):
        reasons.append("WARNING: This website uses a suspicious top-level domain commonly associated with malicious sites")
    if feature_extractor.check_suspicious_domain(request.form['url']):
        reasons.append("WARNING: This domain contains suspicious patterns that may indicate phishing")
    
    # Show feature warnings based on ML model features
    for feature, value in features.items():
        if value == 1 and feature in feature_descriptions:
            reasons.append(feature_descriptions[feature])
    
    # Add additional context
    if '.gov' in request.form['url']:
        reasons.append("This appears to be a government website (.gov domain)")
    elif not reasons:
        reasons.append("No suspicious features detected")
    
    return reasons

def is_trusted_domain(url):
    """Check if the domain is from a trusted TLD"""
    trusted_tlds = ['.gov.np', '.edu.np']
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    return any(domain.endswith(tld) for tld in trusted_tlds)

@app.route('/getURL', methods=['GET', 'POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        print(f"\nProcessing URL: {url}")
        
        # Validate URL first
        is_valid, result = feature_extractor.validate_url(url)
        if not is_valid:
            return render_template("home.html", error="Invalid URL", reasons=[result])
        
        # Use the validated URL
        url = result
        print(f"Validated URL: {url}")
        
        if model is None:
            return render_template("home.html", error="Error: Model not loaded properly")
        
        try:
            # Get features and make ML prediction
            data, phishing_reasons = feature_extractor.getAttributess(url)
            data = preprocess_data(data)
            predicted_value = model.predict(data)
            features = data.iloc[0].to_dict()
            
            # Perform security checks
            security_results = perform_security_checks(url)
            
            # Determine final result based on ML prediction and security checks
            is_phishing = False
            confidence = "HIGH"
            trust_level = "HIGH" if is_trusted_domain(url) else "NORMAL"
            
            # If ML model predicts phishing, it's likely phishing
            if predicted_value[0] == 1:
                is_phishing = True
                confidence = "HIGH"
            # If security checks show suspicious patterns
            elif security_results['is_suspicious']:
                is_phishing = True
                confidence = "MODERATE"
            
            # Prepare the response
            if is_phishing:
                value = f"⚠️ {confidence} RISK: This URL is Phishing"
                # Combine all reasons for suspicious URLs, using set to prevent duplicates
                reasons = set()
                
                # Add domain trust information if applicable
                if trust_level == "HIGH":
                    reasons.add("⚠️ WARNING: This URL is on a trusted domain (.gov.np/.edu.np) but shows suspicious behavior. Even trusted domains can be compromised.")
                
                if phishing_reasons:
                    reasons.update(phishing_reasons)
                if security_results['warnings']:
                    reasons.update(security_results['warnings'])
                if security_results['reasons']:
                    reasons.update(security_results['reasons'])
                if not reasons:
                    reasons.add("Multiple indicators suggest this is a phishing website")
                reasons = list(reasons)  # Convert set back to list for template
            else:
                if trust_level == "HIGH":
                    value = "This URL is Legitimate"
                    reasons = [f"This is an official website on a trusted domain ({urlparse(url).netloc})"]
                else:
                    value = "This URL is Legitimate"
                    reasons = []  # No reasons for legitimate URLs
            
            return render_template("home.html", error=value, reasons=reasons)
            
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            return render_template("home.html", error=f"Error during prediction: {str(e)}")

def perform_security_checks(url):
    """Perform all security checks on the URL"""
    results = {
        'is_suspicious': False,
        'reasons': [],
        'warnings': set()  # Using set to prevent duplicates
    }
    
    # Check SSL certificate
    ssl_result = security_utils.check_ssl_certificate(url)
    if not ssl_result['valid']:
        results['is_suspicious'] = True
        results['reasons'].append(ssl_result['error'])
    elif ssl_result.get('error'):
        results['warnings'].add(ssl_result['error'])
    
    # Check redirect chain
    redirect_result = security_utils.check_redirect_chain(url)
    if redirect_result['suspicious']:
        results['is_suspicious'] = True
        results['reasons'].extend(redirect_result['reasons'])
    elif redirect_result.get('reasons'):
        results['warnings'].update(redirect_result['reasons'])
    
    # Check IP reputation
    ip_result = security_utils.check_ip_reputation(url)
    if ip_result.get('is_suspicious'):
        results['is_suspicious'] = True
        if ip_result.get('warnings'):
            results['reasons'].extend(ip_result['warnings'])
        else:
            results['reasons'].append(f"⚠️ Suspicious IP Address: {ip_result.get('ip_address')}")
    
    # Add any warnings from IP check
    if ip_result.get('warnings'):
        results['warnings'].update(ip_result['warnings'])
    
    # Convert set back to list for template rendering
    results['warnings'] = list(results['warnings'])
    return results

if __name__ == "__main__":
    app.run(debug=True)