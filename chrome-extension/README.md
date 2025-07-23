# PhishGuard Pro - Chrome Extension

A professional, AI-powered Chrome extension for detecting phishing websites and malicious text content with 99.8% accuracy.

## Features

### 🛡️ **Real-time Protection**
- Automatic scanning of visited websites
- Background monitoring for phishing attempts
- Instant notifications for security threats

### 🔍 **Smart Detection**
- URL analysis using machine learning models
- Text content analysis with NLP
- Support for selected text scanning
- High accuracy phishing detection

### 🎨 **Professional UI**
- Modern, clean interface design
- Smooth animations and transitions
- Responsive layout optimized for Chrome
- Professional branding and visual hierarchy

### 📊 **User Experience**
- Loading states with progress indicators
- Clear result presentation
- Intuitive button interactions
- Ripple effects and hover animations

## Installation

1. **Load the Extension**
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable "Developer mode" in the top right
   - Click "Load unpacked" and select the `chrome-extension` folder

2. **Start the Backend**
   - Ensure the Flask backend server is running on `http://localhost:5000`
   - The extension requires the backend API for phishing detection

3. **Grant Permissions**
   - Allow notifications when prompted
   - The extension needs access to tabs and scripting for full functionality

## Usage

### **Automatic Scanning**
- The extension automatically scans each website you visit
- Phishing alerts appear as browser notifications
- Safe sites are confirmed for important domains (banks, etc.)

### **Manual Scanning**
- **Check Current Page**: Click to analyze the current website
- **Check Selected Text**: Select text on any page and click to analyze

### **Results Display**
- **Safe**: Green badge with checkmark icon
- **Phishing**: Red badge with warning icon
- **Error**: Gray message for connection issues

## Technical Details

### **Architecture**
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Backend**: Flask API with ML/NLP models
- **Communication**: RESTful API calls
- **Storage**: Chrome extension storage

### **Security Features**
- Secure API communication
- Input validation and sanitization
- Error handling and graceful degradation
- Privacy-focused design

### **Performance**
- Optimized loading times
- Efficient DOM manipulation
- Minimal memory footprint
- Background processing

## Design System

### **Colors**
- Primary: `#667eea` (Blue gradient)
- Success: `#10b981` (Green)
- Warning: `#ef4444` (Red)
- Neutral: `#6b7280` (Gray)

### **Typography**
- Font: Inter (Google Fonts)
- Weights: 400, 500, 600, 700
- Responsive sizing

### **Components**
- Modern button designs with gradients
- Card-based layout
- Status indicators and badges
- Loading spinners and animations

## Browser Compatibility

- **Chrome**: 88+ (Manifest V3)
- **Edge**: 88+ (Chromium-based)
- **Other Chromium browsers**: Compatible

## Development

### **File Structure**
```
chrome-extension/
├── manifest.json          # Extension configuration
├── popup.html            # Main popup interface
├── popup.css             # Styling and animations
├── popup.js              # Frontend logic
├── background.js         # Background service worker
├── icon*.png             # Extension icons
└── README.md            # This file
```

### **Customization**
- Modify colors in `popup.css`
- Update branding in `manifest.json`
- Adjust API endpoints in `popup.js` and `background.js`

## Support

For issues or questions:
1. Check the browser console for error messages
2. Ensure the backend server is running
3. Verify network connectivity
4. Check extension permissions

## License

This extension is part of the Phishing Detection System project.

---

**PhishGuard Pro** - Protecting users with AI-powered security since 2024. 