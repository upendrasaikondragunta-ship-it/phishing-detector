# AI-Powered Fake Website / Phishing Detection Chrome Extension

Welcome to the **Fully Upgraded (V3)** AI-Powered Phishing Detector project! This system automatically detects whether a website is **SAFE**, **SUSPICIOUS**, or **PHISHING** in real-time. 

## 🎯 What's New in V3 (Fully Automated Edition)
- **Auto-Scanning:** The extension now passively runs in the background. Whenever you visit a new webpage, it automatically analyzes it using Machine Learning without requiring you to click the icon! If a site is dangerous, a native OS notification will slide in to warn you.
- **Email Link Scanner:** You can now **Right-Click** any suspicious link (like inside Gmail or Outlook) and select *“Analyze Link with AI Phishing Detector”*. The AI will verify the link's safety *before* you open it!
- **Demo Mode:** Perfect for presentations. Toggle "Demo Mode" in the UI to demonstrate instant, guaranteed Phishing alerts on any page. 

## 🏗️ Project Architecture
1. **Backend (`/backend`)**: A Flask-based REST API that houses the Machine Learning model (Random Forest trained on 600 records), URL Feature Extractor, HTML Content Analyzer, and Domain Age Checker.
2. **Frontend (`/extension`)**: A modern, beginner-friendly Chrome Extension running HTML/CSS/JS that communicates autonomously with the backend.

### 🧠 Features Extracted
- **URL Structure**: Hyphens, `@` symbols, lengths, raw IP addresses, and suspicious keywords.
- **Domain Age**: WHOIS protocol lookups detect domains registered recently (< 30 days).
- **Page Content**: Cross-domain form submissions, hidden inputs, multiple iframes, and multiple password fields.

---

## 🚀 Demo Workflow: How it works step-by-step
1. User receives a strange email containing a link: `http://paypal-verification-login.xyz`
2. **Without opening it**, the user right-clicks the link and selects *“Analyze Link with AI”*.
3. The Chrome Extension silently routes the link to the local Flask Backend.
4. The Backend rips apart the URL, checks the Domain Age, and executes the Machine Learning probability.
5. The Extension instantly triggers a Native Chrome Notification: **"🚨 DANGER! Threat Score 92/100"** 

---

## 🛠️ Installation & Setup Guide

### 1. Install Python Dependencies
Open your terminal or command prompt, navigate to the `backend` folder, and run:
```bash
cd phishing-detector/backend
pip install -r requirements.txt
```

### 2. Train the Machine Learning Model
Generate the datasets and train the AI Model for the first time:
```bash
python generate_dataset.py
python train_model.py
```

### 3. Run the Flask Backend Server
Start the API server so the Chrome extension can communicate with it:
```bash
python app.py
```
*(Keep this terminal window open while using the extension!)*

### 4. Load the Chrome Extension in Developer Mode
1. Open Google Chrome.
2. In the URL bar, type: `chrome://extensions/` and hit Enter.
3. Enable **Developer mode** (toggle switch in the top right corner).
4. Click the **Load unpacked** button in the top left.
5. Select the `phishing-detector/extension` folder inside this project.

*(Note: If you are upgrading from an older version of this project, simply click the **Refresh Circular UI Button** on the extension card inside `chrome://extensions/` to load the V3 background scripts!)*

---

## 🧪 Sample Test URLs

**Safe Websites (Should return Green / SAFE):**
- `https://github.com`
- `https://wikipedia.org`

**Fake/Phishing-like Examples (Should trigger Red Auto-Notifications):**
- `http://amaz0n-login-security.xyz`
- `http://paypal-verification-login.xyz`
