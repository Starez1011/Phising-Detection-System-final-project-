from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    otp = db.Column(db.String(6), nullable=True)  # For email OTP verification
    otp_created_at = db.Column(db.DateTime(timezone=True), nullable=True)  # OTP creation time
    is_active = db.Column(db.Boolean, default=False)  # Email verified status
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

class Message(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # The full message (text + url)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

class URLCheck(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    label = db.Column(db.Integer, nullable=False)  # 0: legit, 1: phishing
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())

class TextCheck(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    label = db.Column(db.Integer, nullable=False)  # 0: legit, 1: phishing
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
