from flask import Blueprint, request, jsonify, session
from flask_login import login_required, current_user
from models import db, URLCheck, TextCheck, Message
from FeatureExtraction import FeatureExtraction
from ml_models import load_xgb_model, preprocess_data
from nlp_models import TinyBERTPhishingDetector

routes_bp = Blueprint('routes', __name__)
feature_extractor = FeatureExtraction()
try:
    xgb_model = load_xgb_model()
    print("[INFO] ML model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load ML model: {e}")
    xgb_model = None
try:
    nlp_model = TinyBERTPhishingDetector()
    print("[INFO] NLP model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load NLP model: {e}")
    nlp_model = None

@routes_bp.route('/check_message', methods=['POST'])
@login_required
def check_message():
    message = request.json.get('message')
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    
    # 1. Save full message
    msg = Message(user_id=current_user.id, content=message)
    db.session.add(msg)
    db.session.commit()
    
    # 2. Split message into text and url
    url = None
    text = message
    
    # Look specifically for 'https://' URLs
    if 'https://' in message:
        parts = message.split('https://')
        if len(parts) > 1:
            # Take the first URL found
            url_part = 'https://' + parts[1].split()[0]  # Split at first whitespace
            url = url_part
            # Remove the URL from text
            text = message.replace(url_part, '').strip()
    
    # 3. Process URL (if present)
    url_result = None
    url_user_message = None
    if url and xgb_model:
        data, _ = feature_extractor.getAttributess(url)
        data = preprocess_data(data)
        xgb_proba = xgb_model.predict_proba(data)[0]
        url_label = int(xgb_proba[0] <= 0.57)
        print(f"[ML Prediction] URL: {url}, Label: {url_label}, Probabilities: {xgb_proba.tolist()}")
        # Only add if not already present for this user
        existing_url = URLCheck.query.filter_by(user_id=current_user.id, url=url).first()
        if not existing_url:
            url_obj = URLCheck(user_id=current_user.id, url=url, label=url_label)
            db.session.add(url_obj)
            db.session.commit()
        if url_label == 0:
            url_user_message = "This URL is safe. You can use this website without any problem."
        else:
            url_user_message = "Warning: This URL is likely a phishing site. Do NOT access this website or provide any sensitive data."
        url_result = {'url': url, 'label': url_label, 'probabilities': xgb_proba.tolist(), 'user_message': url_user_message}
    
    # 4. Process text with TinyBERT
    text_result = None
    text_user_message = None
    if text and nlp_model:
        nlp_result = nlp_model.predict(text)
        text_label = nlp_result['label']
        print(f"[NLP Prediction] Text: {text}, Label: {text_label}, Probabilities: {nlp_result['probabilities']}")
        text_obj = TextCheck(user_id=current_user.id, text=text, label=text_label)
        db.session.add(text_obj)
        db.session.commit()
        if text_label == 0:
            text_user_message = "The text content appears safe and does not indicate phishing."
        else:
            text_user_message = "Warning: The text content may be related to phishing. Please be cautious and do not provide sensitive information."
        text_result = {
            'text': text,
            'label': text_label,
            'probabilities': nlp_result['probabilities'],
            'user_message': text_user_message
        }
    
    # Combine user messages
    combined_user_message = []
    if url_user_message:
        combined_user_message.append(f"URL Analysis: {url_user_message}")
    if text_user_message:
        combined_user_message.append(f"Text Analysis: {text_user_message}")
    return jsonify({
        'message_id': msg.id,
        'url_result': url_result,
        'text_result': text_result,
        'user_message': "\n".join(combined_user_message) if combined_user_message else None
    })

@routes_bp.route('/check_url', methods=['POST'])
@login_required
def check_url():
    url = request.json.get('url')
    if not xgb_model:
        return jsonify({'error': 'ML model not loaded'}), 500
    data, _ = feature_extractor.getAttributess(url)
    data = preprocess_data(data)
    xgb_proba = xgb_model.predict_proba(data)[0]
    label = int(xgb_proba[0] <= 0.57)
    print(f"[ML Prediction] URL: {url}, Label: {label}, Probabilities: {xgb_proba.tolist()}")
    # Only add if not already present for this user
    existing_url = URLCheck.query.filter_by(user_id=current_user.id, url=url).first()
    if not existing_url:
        url_check = URLCheck(user_id=current_user.id, url=url, label=label)
        db.session.add(url_check)
        db.session.commit()
    if label == 0:
        user_message = "This URL is safe. You can use this website without any problem."
    else:
        user_message = "Warning: This URL is likely a phishing site. Do NOT access this website or provide any sensitive data."
    return jsonify({'url': url, 'label': label, 'probabilities': xgb_proba.tolist(), 'user_message': user_message})


@routes_bp.route('/user/history', methods=['GET'])
@login_required
def history_combined():
    messages = Message.query.filter_by(user_id=current_user.id).all()
    urls = URLCheck.query.filter_by(user_id=current_user.id).all()
    combined = []
    
    # Collect all URLs that appear in any message content
    message_urls = set()
    for m in messages:
        if 'https://' in m.content:
            parts = m.content.split('https://')
            if len(parts) > 1:
                url = 'https://' + parts[1].split()[0]
                message_urls.add(url)
    
    # Add messages
    for m in messages:
        combined.append({'type': 'message', 'content': m.content, 'timestamp': m.timestamp})
    
    # Add only those URLCheck entries whose url is NOT in any message content
    for u in urls:
        if u.url not in message_urls:
            combined.append({'type': 'url', 'url': u.url, 'label': u.label, 'timestamp': u.timestamp})
    
    # Sort by timestamp, latest first
    combined.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(combined)
