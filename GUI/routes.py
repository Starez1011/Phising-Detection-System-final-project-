from flask import Blueprint, request, jsonify, session
from flask_login import login_required, current_user
from models import db, URLCheck, TextCheck, Message
from FeatureExtraction import FeatureExtraction
from ml_models import load_xgb_model, preprocess_data
from nlp_models import TinyBERTPhishingDetector
import re

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
    
    # 1. Save full message only if not already present for this user
    existing_message = Message.query.filter_by(user_id=current_user.id, content=message).first()
    if not existing_message:
        msg = Message(user_id=current_user.id, content=message)
        db.session.add(msg)
        db.session.commit()
    else:
        msg = existing_message
    
    # 2. Split message into text and url using regex for http/https
    url = None
    text = message
    url_match = re.search(r'(https?://\S+)', message)
    if url_match:
        url = url_match.group(1)
        text = message.replace(url, '').strip()
    
    # 3. Process URL (if present)
    url_result = None
    url_user_message = None
    if url and xgb_model:
        data, _ = feature_extractor.getAttributess(url)
        data = preprocess_data(data)
        xgb_proba = xgb_model.predict_proba(data)[0]
        url_label = int(xgb_proba[0] <= 0.57)
        legit_percent = round(xgb_proba[0] * 100, 2)
        phish_percent = round(xgb_proba[1] * 100, 2)
        print(f"[ML Prediction] URL: {url}, \nLegitimate: {legit_percent}%, \nPhishing: {phish_percent}%")
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
        nlp_proba = nlp_result['probabilities']
        legit_percent = round(nlp_proba[0] * 100, 2)
        phish_percent = round(nlp_proba[1] * 100, 2)
        print(f"[NLP Prediction] Text: {text}, \nLegitimate: {legit_percent}%, \nPhishing: {phish_percent}%")
        # Only add if not already present for this user
        existing_text = TextCheck.query.filter_by(user_id=current_user.id, text=text).first()
        if not existing_text:
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
    legit_percent = round(xgb_proba[0] * 100, 2)
    phish_percent = round(xgb_proba[1] * 100, 2)
    print(f"[ML Prediction] URL: {url}, \nLegitimate: {legit_percent}%, \nPhishing: {phish_percent}%")
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
        # Split message into text and url using regex for http/https
        url = None
        text = m.content
        url_match = re.search(r'(https?://\S+)', m.content)
        if url_match:
            url = url_match.group(1)
            text = m.content.replace(url, '').strip()
        # Get text label
        text_label = None
        if text:
            text_check = TextCheck.query.filter_by(user_id=m.user_id, text=text).first()
            if text_check:
                text_label = text_check.label
        # Get url label
        url_label = None
        if url:
            url_check = URLCheck.query.filter_by(user_id=m.user_id, url=url).first()
            if url_check:
                url_label = url_check.label
        combined.append({
            'type': 'message',
            'content': m.content,
            'timestamp': m.timestamp,
            'text_label': text_label,
            'url_label': url_label
        })
    
    # Add only those URLCheck entries whose url is NOT in any message content
    for u in urls:
        if u.url not in message_urls:
            combined.append({'type': 'url', 'url': u.url, 'label': u.label, 'timestamp': u.timestamp})
    
    # Sort by timestamp, latest first
    combined.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify(combined)

@routes_bp.route('/stats', methods=['GET'])
def stats():
    # TinyBERT stats (from your last run)
    tinybert_stats = {
        "validation_accuracy": 0.9866,
        "precision": 0.9904,
        "recall": 0.9367,
        "f1_score": 0.9628,
        "confusion_matrix": [[972, 2], [14, 207]],
        "classification_report": {
            "0": {"precision": 0.99, "recall": 1.00, "f1-score": 0.99, "support": 974},
            "1": {"precision": 0.99, "recall": 0.94, "f1-score": 0.96, "support": 221},
            "accuracy": 0.99,
            "macro avg": {"precision": 0.99, "recall": 0.97, "f1-score": 0.98, "support": 1195},
            "weighted avg": {"precision": 0.99, "recall": 0.99, "f1-score": 0.99, "support": 1195}
        }
    }

    # XGBoost stats (from your Jupyter notebook, user provided)
    xgboost_stats = {
        "train_accuracy": 0.7842,
        "test_accuracy": 0.7703,
        "precision": 0.77,
        "recall": 0.77,
        "f1_score": 0.77,
        "confusion_matrix": [[914, 263], [261, 843]],
        "classification_report": {
            "0": {"precision": 0.78, "recall": 0.78, "f1-score": 0.78, "support": 1177},
            "1": {"precision": 0.76, "recall": 0.76, "f1-score": 0.76, "support": 1104},
            "accuracy": 0.77,
            "macro avg": {"precision": 0.77, "recall": 0.77, "f1-score": 0.77, "support": 2281},
            "weighted avg": {"precision": 0.77, "recall": 0.77, "f1-score": 0.77, "support": 2281}
        }
    }

    return jsonify({
        "tinybert": tinybert_stats,
        "xgboost": xgboost_stats
    })
