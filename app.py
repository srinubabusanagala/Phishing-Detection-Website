# app.py - Complete and Corrected Version with Typosquatting Heuristic
from flask import Flask, request, render_template
import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import os
import Levenshtein
import requests
import time

app = Flask(__name__)

# --- CONFIGURATION ---
VT_API_KEY = '91a7edd65717f1bad6d7a1e773f3432aa616ffe33015829a590afefcdd48f006'

# --- LOAD THE MODEL ---
model_path = 'phishing_model_v3.joblib'
model = None
try:
    model = joblib.load(model_path)
    print(f"Model '{model_path}' loaded successfully.")
except FileNotFoundError:
    print(f"Error: Model file not found at '{model_path}'. The AI prediction will not work.")
except Exception as e:
    print(f"An error occurred while loading the model: {e}")

# --- FEATURE EXTRACTION ---
KNOWN_BRANDS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix', 'instagram',
    'paypal', 'ebay', 'walmart', 'chase', 'bankofamerica', 'wellsfargo',
    'sbi', 'icici', 'hdfcbank', 'twitter', 'linkedin'
]

def get_domain_part(url_part):
    """Extracts the main part of the domain, e.g., 'google' from 'www.google.com'."""
    try:
        parts = url_part.split('.')
        if len(parts) >= 2:
            return parts[-2].lower()
        return parts[0].lower()
    except:
        return ""

def extract_features(url):
    """Extracts all features required by the model and business logic."""
    features = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    features['url_len'] = len(url)
    features['has_ip_address'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
    features['num_dots'] = url.count('.')
    features['num_dashes_domain'] = domain.count('-')
    features['path_len'] = len(path)
    features['has_login_keyword'] = 1 if 'login' in url.lower() or 'signin' in url.lower() else 0
    features['num_slashes'] = url.count('/')
    features['num_at_symbol'] = url.count('@')
    features['num_query_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0

    domain_main_part = get_domain_part(domain)
    distances = [Levenshtein.distance(domain_main_part, brand) for brand in KNOWN_BRANDS]
    features['min_levenshtein_distance'] = min(distances) if distances else 100

    return features

# --- VirusTotal Check Function ---
def check_virustotal(api_key, domain):
    if not api_key or api_key == 'YOUR_VIRUSTOTAL_API_KEY_HERE':
        return {'positives': -1, 'total': -1, 'error': 'API Key not configured'}
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            positives = stats.get('malicious', 0)
            harmless = stats.get('harmless', 0)
            total = positives + harmless if (positives + harmless) > 0 else 1
            return {'positives': positives, 'total': total}
        else:
            return {'positives': 0, 'total': 0, 'error': f'HTTP Status {response.status_code}'}
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal API Error: {e}")
        return {'positives': -1, 'total': -1, 'error': str(e)}

# --- WEB ROUTES ---

@app.route('/')
def home():
    """Renders the home page with the input form."""
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url_to_check = request.form['url']
    if not url_to_check:
        return render_template('index.html', error="Please enter a URL.")

    if not url_to_check.startswith(('http://', 'https://')):
        url_to_check = 'http://' + url_to_check

    features = extract_features(url_to_check)

    # --- MULTI-LAYERED CHECKING LOGIC ---

    # 1. Business Logic: Exact Brand Match (Highest Priority)
    if features['min_levenshtein_distance'] == 0:
        result_text = "This URL is a known LEGITIMATE brand."
        confidence = "100.00% (Verified Brand)"
        return render_template('index.html', result=result_text, confidence=confidence, url=url_to_check)

    # 2. Heuristic: Typosquatting Detection (Very High Priority)
    # Checks if the domain is suspiciously close to a known brand (e.g., 'amazonn' vs 'amazon')
    if 0 < features['min_levenshtein_distance'] <= 2:
        result_text = "Warning! This URL is very similar to a known brand and is highly suspicious of being a PHISHING site."
        confidence = "99.00% (Heuristic Rule: Typosquatting)"
        return render_template('index.html', result=result_text, confidence=confidence, url=url_to_check)

    # 3. Threat Intelligence: VirusTotal Check
    domain_to_check = urlparse(url_to_check).netloc
    vt_result = check_virustotal(VT_API_KEY, domain_to_check)
    vt_positives = vt_result.get('positives', 0)

    if vt_positives > 0:
        result_text = "Warning! This URL is flagged as MALICIOUS by Threat Intelligence."
        confidence = f"({vt_positives} / {vt_result.get('total', 'N/A')} security vendors flagged this)"
        return render_template('index.html', result=result_text, confidence=confidence, url=url_to_check)
    
    # 4. AI Model Prediction (Final Fallback)
    if model is None:
        return render_template('index.html', error="AI Model is not loaded. Cannot perform prediction.")

    try:
        feature_order = [
            'url_len', 'has_ip_address', 'num_dots', 'num_dashes_domain', 'path_len',
            'has_login_keyword', 'num_slashes', 'num_at_symbol', 'num_query_params'
        ]
        features_df = pd.DataFrame([features], columns=feature_order)

        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]

        if prediction == 1:
            result_text = "Warning! Our AI model suspects this URL is a PHISHING site."
            confidence_val = f"{probability[1]*100:.2f}% Confidence"
        else:
            result_text = "This URL appears to be LEGITIMATE."
            confidence_val = f"{probability[0]*100:.2f}% Confidence"

        return render_template('index.html', result=result_text, confidence=confidence_val, url=url_to_check)

    except Exception as e:
        return render_template('index.html', error=f"An error occurred during AI prediction: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)