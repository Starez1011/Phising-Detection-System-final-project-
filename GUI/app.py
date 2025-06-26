from dotenv import load_dotenv
import os

load_dotenv()

from flask import Flask
from flask_cors import CORS
from config import Config
from models import db
from auth import auth_bp, login_manager
from routes import routes_bp
from flask_mail import Mail

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    CORS(app) #  CORS(app, origins=["http://localhost:3000"])
    login_manager.init_app(app)
    mail.init_app(app)
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(routes_bp, url_prefix='/api')
    with app.app_context():
        db.create_all()
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)