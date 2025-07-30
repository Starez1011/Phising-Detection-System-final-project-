# 🛡️ PhishGuard Pro - AI-Powered Phishing Detection System

A comprehensive, multi-modal phishing detection system that combines machine learning and natural language processing to protect users from phishing attacks. The system analyzes both URLs and text content to provide real-time protection against phishing threats.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [System Architecture](#system-architecture)
- [Features](#features)
- [Components](#components)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Model Performance](#model-performance)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## 🎯 Project Overview

This project implements a sophisticated phishing detection system with three main components:

1. **Web Application (Flask Backend)** - Core API server with ML/NLP models
2. **Chrome Extension** - Real-time browser protection
3. **Machine Learning Models** - URL and text analysis engines

### Key Capabilities

- **URL Analysis**: Extracts 13+ features from URLs to detect phishing websites
- **Text Analysis**: Uses fine-tuned TinyBERT model for phishing intent detection
- **Real-time Protection**: Chrome extension provides instant security alerts
- **User Management**: Secure authentication with email verification
- **History Tracking**: Maintains user check history and statistics

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Chrome        │    │   Flask         │    │   Machine       │
│   Extension     │◄──►│   Backend       │◄──►│   Learning      │
│                 │    │   (Port 5050)   │    │   Models        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User          │    │   SQLite        │    │   Feature       │
│   Interface     │    │   Database      │    │   Extraction    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Data Flow

1. **User Input**: URL or text submitted via web app or extension
2. **Feature Extraction**: URL features extracted using `FeatureExtraction.py`
3. **Model Prediction**: XGBoost for URLs, TinyBERT for text
4. **Result Processing**: Confidence scores and user-friendly messages
5. **Storage**: Results saved to database with user association

## ✨ Features

### 🔍 **URL Analysis Features**

- **Long URL Detection**: Identifies URLs longer than 54 characters
- **Suspicious Symbols**: Detects @ symbols and redirection patterns
- **Domain Analysis**: Subdomain count, IP address detection
- **Security Indicators**: HTTPS token, shortening service detection
- **Web Traffic Analysis**: Domain popularity and ranking
- **Domain Age**: Registration length and DNS record validation
- **Statistical Reports**: Comprehensive domain reputation analysis

### 📝 **Text Analysis Features**

- **NLP Processing**: Fine-tuned TinyBERT model for text classification
- **Phishing Intent Detection**: Identifies suspicious language patterns
- **Context Analysis**: Understands message context and urgency
- **Confidence Scoring**: Provides probability scores for predictions

### 🛡️ **Security Features**

- **User Authentication**: Secure login with email verification
- **Session Management**: Flask-Login integration
- **Input Validation**: Comprehensive URL and text sanitization
- **Rate Limiting**: Prevents abuse and ensures system stability

### 📊 **User Experience**

- **Real-time Results**: Instant analysis and feedback
- **History Management**: Track all previous checks
- **Visual Indicators**: Clear safe/phishing status badges
- **Detailed Reports**: Comprehensive analysis breakdown

## 🧩 Components

### 1. **Web Application (`GUI/`)**

#### Core Files:

- **`app.py`**: Flask application entry point
- **`routes.py`**: API endpoints for URL/text checking
- **`auth.py`**: User authentication and session management
- **`models.py`**: Database models (User, Message, URLCheck, TextCheck)
- **`config.py`**: Application configuration and environment variables

#### ML/NLP Components:

- **`FeatureExtraction.py`**: URL feature extraction engine (870 lines)
- **`ml_models.py`**: XGBoost model loading and preprocessing
- **`nlp_models.py`**: TinyBERT model implementation
- **`train_nlp_model.py`**: NLP model training script

#### Models:

- **`XGBoostModel_12000.sav`**: Trained XGBoost model for URL classification
- **`RFmodel_12000.sav`**: Random Forest model (backup)

### 2. **Chrome Extension (`chrome-extension/`)**

#### Files:

- **`manifest.json`**: Extension configuration (Manifest V3)
- **`popup.html`**: Extension popup interface
- **`popup.js`**: Frontend logic and API communication
- **`popup.css`**: Styling and animations
- **`background.js`**: Background service worker
- **`icon*.png`**: Extension icons (16x16 to 128x128)

### 3. **Data and Models**

#### Datasets:

- **`extracted_csv_files/`**: Processed feature datasets
- **`raw_datasets2/`**: Original phishing/legitimate website data
- **`text_csv_file/`**: Text dataset for NLP training
- **`web_traffic_dataset/`**: Tranco top 1M domains for traffic analysis

#### Training Scripts:

- **`Phishing Website Detection Models.ipynb`**: Main ML model training
- **`Phishing_NLP_Training_and_Evaluation.ipynb`**: NLP model training
- **`export_features_from_db.py`**: Database to CSV export utility

## 🚀 Installation & Setup

### Prerequisites

- Python 3.8+
- Node.js (for development)
- Chrome browser (for extension)
- Email service (for OTP verification)

### 1. **Clone and Setup**

```bash
git clone <repository-url>
cd Phishing
```

### 2. **Python Environment**

```bash
# Create virtual environment
python -m venv venv

# Activate environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. **Environment Configuration**

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///GUI/instance/phishing.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

### 4. **Database Setup**

```bash
cd GUI
python app.py
# Database will be automatically created on first run
```

### 5. **Model Training (Optional)**

```bash
# Train NLP model
python GUI/train_nlp_model.py

# Export features from database
python export_features_from_db.py
```

### 6. **Chrome Extension Setup**

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `chrome-extension/` folder
4. The extension will appear in your browser toolbar

## 📖 Usage

### **Web Application**

1. **Start the server**:

   ```bash
   cd GUI
   python app.py
   ```

   Server runs on `http://localhost:5050`

2. **Access the application**:
   - Open browser to `http://localhost:5050`
   - Register/login with email verification
   - Submit URLs or text for analysis

### **Chrome Extension**

1. **Automatic Protection**:

   - Extension automatically scans visited websites
   - Shows security status in popup
   - Displays notifications for threats

2. **Manual Analysis**:
   - Click extension icon to open popup
   - Use "Check Current Page" for website analysis
   - Select text and use "Check Selected Text" for content analysis

### **API Endpoints**

#### Authentication:

- `POST /api/auth/signup` - User registration
- `POST /api/auth/verify-otp` - Email verification
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

#### Analysis:

- `POST /api/check_message` - Analyze message (URL + text)
- `POST /api/check_url` - Analyze URL only
- `GET /api/user/history` - Get user check history
- `GET /api/stats` - Get system statistics

## 🔧 Technical Details

### **Machine Learning Models**

#### XGBoost (URL Classification)

- **Features**: 13 extracted URL characteristics
- **Performance**: 77% accuracy, 78% precision
- **Training Data**: 12,000+ URLs (phishing + legitimate)
- **Threshold**: 0.57 (probability threshold for classification)

#### TinyBERT (Text Classification)

- **Model**: `huawei-noah/TinyBERT_General_4L_312D`
- **Fine-tuning**: Custom dataset with phishing/legitimate text
- **Performance**: ~93% validation accuracy
- **Input**: Text messages up to 128 tokens

### **Feature Extraction Process**

1. **URL Parsing**: Extract protocol, domain, path components
2. **Domain Analysis**: Check TLD, subdomains, IP addresses
3. **Security Checks**: HTTPS, shortening services, suspicious patterns
4. **Traffic Analysis**: Web traffic ranking and domain popularity
5. **DNS Validation**: Domain age, registration length, DNS records

### **Database Schema**

```sql
-- Users table
CREATE TABLE user (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    otp VARCHAR(6),
    otp_created_at DATETIME,
    is_active BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- URL checks table
CREATE TABLE url_check (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES user(id),
    url VARCHAR(512) NOT NULL,
    label INTEGER NOT NULL,  -- 0: legitimate, 1: phishing
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Text checks table
CREATE TABLE text_check (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES user(id),
    text TEXT NOT NULL,
    label INTEGER NOT NULL,  -- 0: legitimate, 1: phishing
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 📊 Model Performance

### **XGBoost Model Metrics**

| Metric        | Value                            | Description                                         |
| ------------- | -------------------------------- | --------------------------------------------------- |
| **Accuracy**  | 77.0%                            | Overall prediction accuracy                         |
| **Precision** | 78% (legitimate), 76% (phishing) | True positives / (True positives + False positives) |
| **Recall**    | 78% (legitimate), 76% (phishing) | True positives / (True positives + False negatives) |
| **F1-Score**  | 78% (legitimate), 76% (phishing) | Harmonic mean of precision and recall               |

### **Confusion Matrix**

```
                Predicted
Actual    Legitimate  Phishing
Legitimate    914       263
Phishing      261       843
```

### **NLP Model Performance**

- **Validation Accuracy**: ~93%
- **Model Size**: TinyBERT (4 layers, 312 dimensions)
- **Training Time**: ~3 epochs, 2-5 minutes
- **Inference Speed**: <100ms per prediction

## 🔌 API Documentation

### **Check Message Endpoint**

```http
POST /api/check_message
Content-Type: application/json
Authorization: Bearer <session_token>

{
  "message": "Check this website: https://example.com/login"
}
```

**Response**:

```json
{
  "url_result": {
    "url": "https://example.com/login",
    "label": 0,
    "probabilities": [0.85, 0.15],
    "user_message": "This URL is safe. You can use this website without any problem."
  },
  "text_result": {
    "text": "Check this website:",
    "label": 0,
    "probabilities": [0.92, 0.08],
    "user_message": "The text content appears safe and does not indicate phishing."
  },
  "combined_message": "Both URL and text analysis indicate this is safe."
}
```

### **Authentication Endpoints**

```http
POST /api/auth/signup
{
  "username": "user123",
  "email": "user@example.com",
  "password": "securepassword"
}

POST /api/auth/verify-otp
{
  "email": "user@example.com",
  "otp": "123456"
}

POST /api/auth/login
{
  "username": "user123",
  "password": "securepassword"
}
```

## 🛠️ Development

### **Project Structure**

```
Phishing/
├── GUI/                          # Flask web application
│   ├── app.py                   # Application entry point
│   ├── routes.py                # API routes
│   ├── auth.py                  # Authentication
│   ├── models.py                # Database models
│   ├── FeatureExtraction.py     # URL feature extraction
│   ├── ml_models.py             # ML model loading
│   ├── nlp_models.py            # NLP model implementation
│   ├── train_nlp_model.py       # NLP training script
│   ├── XGBoostModel_12000.sav   # Trained XGBoost model
│   └── instance/                # Database files
├── chrome-extension/            # Browser extension
│   ├── manifest.json            # Extension config
│   ├── popup.html              # Extension UI
│   ├── popup.js                # Extension logic
│   └── background.js           # Service worker
├── extracted_csv_files/         # Processed datasets
├── raw_datasets2/              # Original datasets
├── text_csv_file/              # NLP training data
├── web_traffic_dataset/        # Domain traffic data
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

### **Adding New Features**

1. **New URL Features**:

   - Add feature extraction logic in `FeatureExtraction.py`
   - Update `ml_models.py` preprocessing
   - Retrain XGBoost model

2. **New Text Features**:

   - Modify `nlp_models.py` for new preprocessing
   - Update training data in `text_csv_file/`
   - Retrain TinyBERT model

3. **New API Endpoints**:
   - Add routes in `routes.py`
   - Update database models if needed
   - Test with Postman or curl

### **Testing**

```bash
# Test Flask application
cd GUI
python app.py

# Test API endpoints
curl -X POST http://localhost:5050/api/check_url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Test extension
# Load in Chrome and check browser console for errors
```

## 🔍 Troubleshooting

### **Common Issues**

1. **Model Loading Errors**:

   - Ensure model files exist in `GUI/` directory
   - Check file permissions
   - Verify model compatibility

2. **Database Errors**:

   - Delete `GUI/instance/phishing.db` and restart
   - Check database permissions
   - Verify SQLite installation

3. **Extension Not Working**:

   - Check backend server is running on port 5050
   - Verify CORS settings in `app.py`
   - Check browser console for errors

4. **Email Not Sending**:
   - Verify SMTP settings in `.env`
   - Check email provider app password
   - Test SMTP connection

### **Performance Optimization**

1. **Model Loading**:

   - Models are loaded once at startup
   - Consider model caching for production
   - Use GPU acceleration for NLP model

2. **Database Optimization**:

   - Add indexes for frequently queried columns
   - Implement connection pooling
   - Consider database migration for schema changes

3. **Extension Performance**:
   - Minimize API calls
   - Implement request caching
   - Use efficient DOM manipulation

## 📝 License

This project is part of an academic research project for phishing detection. Please ensure compliance with all applicable laws and regulations when using this system.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For technical support or questions:

1. Check the troubleshooting section
2. Review browser console logs
3. Verify all dependencies are installed
4. Ensure proper environment configuration

---

**PhishGuard Pro** - Protecting users with AI-powered security since 2024.

_Built with Flask, XGBoost, TinyBERT, and modern web technologies._
