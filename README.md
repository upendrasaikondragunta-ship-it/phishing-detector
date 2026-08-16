# 🛡️ AI-Powered Phishing Website Detector

An AI-powered Chrome Extension that detects **SAFE, SUSPICIOUS, PHISHING, and BLOCKED websites** in real time using Machine Learning, URL analysis, website content analysis, and domain intelligence.

The system combines a **Flask REST API**, a trained **Machine Learning model**, security-oriented URL feature engineering, domain verification, content analysis, and a **Chrome Extension (Manifest V3)**.

---

## 🚀 Project Highlights

- 🤖 Machine Learning-based phishing detection
- 🌐 Real-time website URL analysis
- 🧠 27 security-oriented URL features
- 🔍 Website content analysis
- 🌎 Domain / WHOIS verification
- 🛡️ Private and reserved IP protection
- 🚨 SAFE / SUSPICIOUS / PHISHING classification
- ⛔ Security blocking for restricted URLs
- 🧪 Adversarial security test suite
- 🌲 HistGradientBoosting Machine Learning model
- 🔌 Chrome Extension using Manifest V3
- ☁️ Flask backend deployed for remote API access

---

# 🏗️ System Architecture

```text
                    ┌─────────────────────────┐
                    │      User Browser       │
                    │        Chrome           │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Chrome Extension      │
                    │      Manifest V3         │
                    │                          │
                    │  Popup / Background /   │
                    │  Content Analysis       │
                    └────────────┬────────────┘
                                 │
                         HTTP POST /predict
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Flask REST API     │
                    │        app.py           │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
      ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
      │ URL Feature  │   │   Content    │   │   Domain     │
      │  Extraction  │   │   Analyzer   │   │   Checker    │
      └──────┬───────┘   └──────────────┘   └──────────────┘
             │
             ▼
      ┌──────────────────┐
      │ Machine Learning │
      │      Model       │
      │ HistGradientBoost│
      └────────┬─────────┘
               │
               ▼
      ┌──────────────────┐
      │ Threat Scoring   │
      │ & Classification │
      └────────┬─────────┘
               │
               ▼
      ┌─────────────────────────┐
      │ SAFE / SUSPICIOUS /     │
      │ PHISHING / BLOCKED      │
      └─────────────────────────┘
