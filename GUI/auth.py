from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail
from email_utils import generate_otp, send_otp_email
from datetime import datetime, timedelta, timezone

auth_bp = Blueprint('auth', __name__)
login_manager = LoginManager()
login_manager.login_view = 'auth.login'

mail = Mail()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@auth_bp.record_once
def on_load(state):
    mail.init_app(state.app)

def is_otp_valid(user):
    if not user.otp or not user.otp_created_at:
        return False
    otp_created_at = user.otp_created_at
    if otp_created_at.tzinfo is None:
        otp_created_at = otp_created_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) <= otp_created_at + timedelta(minutes=5)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.json
    user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
    if user:
        if not user.is_active:
            # Check if OTP is still valid
            if is_otp_valid(user):
                return jsonify({'error': 'Account exists but not verified. Please check your email for the OTP sent. OTP is valid for 5 minutes.'}), 400
            else:
                # OTP expired, generate and send new OTP
                otp = generate_otp()
                user.otp = otp
                user.otp_created_at = datetime.now(timezone.utc)
                db.session.commit()
                send_otp_email(mail, user.email, otp)
                return jsonify({'error': 'Account exists but not verified. Previous OTP expired, a new OTP has been sent to your email.'}), 400
        return jsonify({'error': 'Username or email already exists. Please login.'}), 400
    hashed_pw = generate_password_hash(data['password'])
    otp = generate_otp()
    now = datetime.now(timezone.utc)
    user = User(username=data['username'], email=data['email'], password_hash=hashed_pw, otp=otp, otp_created_at=now, is_active=False)
    db.session.add(user)
    db.session.commit()
    send_otp_email(mail, user.email, otp)
    return jsonify({'message': 'User created successfully. Please verify your email with the OTP sent.'})

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if not user.otp or not user.otp_created_at:
        return jsonify({'error': 'No OTP found. Please login to receive a new OTP.'}), 400
    otp_created_at = user.otp_created_at
    if otp_created_at.tzinfo is None:
        otp_created_at = otp_created_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > otp_created_at + timedelta(minutes=5):
        # OTP expired, generate and send new OTP
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = datetime.now(timezone.utc)
        db.session.commit()
        send_otp_email(mail, user.email, otp)
        return jsonify({'error': 'OTP expired. A new OTP has been sent to your email.'}), 400
    if user.otp == data['otp']:
        user.is_active = True
        user.otp = None
        user.otp_created_at = None
        db.session.commit()
        return jsonify({'message': 'Email verified successfully!'})
    else:
        return jsonify({'error': 'Invalid OTP'}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        if not user.is_active:
            # Only send new OTP if previous is expired or missing
            if is_otp_valid(user):
                return jsonify({'error': 'Account not verified. Please check your email for the OTP sent. OTP is valid for 5 minutes.'}), 403
            else:
                otp = generate_otp()
                user.otp = otp
                user.otp_created_at = datetime.now(timezone.utc)
                db.session.commit()
                send_otp_email(mail, user.email, otp)
                return jsonify({'error': 'Account not verified. Previous OTP expired, a new OTP has been sent to your email.'}), 403
        login_user(user)
        session['user_id'] = user.id
        # Get the session token (session cookie value)
        session_cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
        session_token = request.cookies.get(session_cookie_name)
        return jsonify({
            'message': 'Login successful',
            'session_token': session_token,
            'username': user.username,
            'email': user.email
        })
    return jsonify({'error': 'Invalid credentials'}), 401

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'})
