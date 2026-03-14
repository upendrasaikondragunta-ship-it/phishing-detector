from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os

from feature_extractor import extract_features, get_feature_names
from domain_checker import check_domain_age
from content_analyzer import analyze_webpage_content

app = Flask(__name__)
CORS(app)  # Enable CORS for the Chrome Extension to communicate

# Load the trained machine learning model
MODEL_PATH = "model.pkl"
try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print("Machine Learning Model Loaded Successfully.")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

def generate_mock_response(url):
    """
    Simulates a response for the Demo Mode (Improvement 10).
    Avoids slow network calls for instant demonstration.
    """
    if "paypal-verification" in url or "amaz0n-login" in url or "192.168" in url:
        return jsonify({
            "status": "PHISHING",
            "threat_score": 92,
            "reasons": [
                "[DEMO MODE] ML pattern matches known phishing structure",
                "[DEMO MODE] Domain is newly registered (< 30 days)",
                "[DEMO MODE] Hidden input fields detected",
                "[DEMO MODE] Forms submit to different domain"
            ]
        })
    else:
        return jsonify({
            "status": "SAFE",
            "threat_score": 5,
            "reasons": [
                "[DEMO MODE] No suspicious indicators found",
                "[DEMO MODE] Known safe structure"
            ]
        })

def calculate_threat_score(prob, domain_data, content_features):
    """
    Calculates a threat score (0-100) and compiles a list of reasons.
    (Improvement 6 & 7 - Smart threat scoring & explainable AI)
    """
    score = prob * 100
    reasons = []

    # Domain Age Checks
    if domain_data.get('is_suspicious', False):
        score += 20
        reasons.append(domain_data['reason']) # Append the exact reason from the module
        
    if domain_data.get('error'):
        reasons.append(f"Domain verification failed: {domain_data['error']}")

    # Content Analysis Checks
    if content_features.get('num_login_forms', 0) > 0:
        score += 15
        reasons.append(f"Found {content_features['num_login_forms']} login form(s)")
        
    if content_features.get('forms_submit_different_domain', 0) > 0:
        score += 30
        reasons.append("CRITICAL: Forms on this page submit data to a completely different domain")
    
    if content_features.get('has_password_fields', 0) > 0:
        score += 15
        reasons.append("Password input fields detected on page")
        
    if content_features.get('num_iframes', 0) > 0:
        reasons.append(f"Detected {content_features['num_iframes']} iframe elements")
        
    if content_features.get('has_hidden_fields', 0) > 0:
        score += 5
        reasons.append("Hidden input fields detected (common in phishing forms)")
        
    if content_features.get('suspicious_keyword_in_text', 0) > 0:
        score += 10
        reasons.append(f"Found {content_features['suspicious_keyword_in_text']} suspicious keywords in page text")

    # Normalize score to max 100
    score = min(score, 100)
    score = max(score, 0)
    
    return int(score), reasons

def determine_status(score):
    """(Improvement 6 - New Risk Categories)"""
    if score <= 30:
        return "SAFE"       # 0 - 30
    elif score <= 60:
        return "SUSPICIOUS" # 30 - 60
    else:
        return "PHISHING"   # 60 - 100

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({"error": "Model not loaded on server."}), 500
        
    data = request.json
    url = data.get('url')
    is_demo = data.get('demo_mode', False)
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Handle Demo Mode Fast-Path
    if is_demo:
        return generate_mock_response(url)

    try:
        # 1. Extract URL Features for ML Model (now returns dict)
        features_dict = extract_features(url)
        
        # Convert dict to exactly ordered list to match training shape
        ordered_keys = get_feature_names()
        features_list = [features_dict[k] for k in ordered_keys]
        
        # 2. Get ML Prediction Probability (Class 1 is Phishing)
        ml_prob = model.predict_proba([features_list])[0][1]
        
        # 3. Domain Age Analysis
        domain_data = check_domain_age(url)
        
        # 4. Webpage Content Analysis
        content_features = analyze_webpage_content(url)
        
        # 5. Generate Risk Score and Reasons
        threat_score, reasons = calculate_threat_score(ml_prob, domain_data, content_features)
        status = determine_status(threat_score)
        
        # Add ML specific explainers to the top
        if ml_prob > 0.6:
            reasons.insert(0, f"URL structure matches known phishing patterns ({int(ml_prob*100)}% match)")
            if features_dict.get('has_ip_address'):
                reasons.insert(1, "URL uses raw IP Address instead of a domain name")
        elif ml_prob > 0.3:
            reasons.insert(0, "URL structure looks slightly suspicious")
            
        if len(reasons) == 0:
            reasons.append("No suspicious indicators found")

        return jsonify({
            "status": status,
            "threat_score": threat_score,
            "reasons": reasons
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"message": "Phishing Detection API is running! (V2 Upgraded)"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
