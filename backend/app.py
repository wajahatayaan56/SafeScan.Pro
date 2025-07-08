from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import pandas as pd
from urllib.parse import urlparse
import re
from datetime import datetime

app = Flask(__name__)
CORS(app) # Enable CORS for all routes, allowing frontend to access it

# --- Configuration ---
# Define paths relative to the script's location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'model')
MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest_model.pkl')

# List of common TLDs (must be consistent with model_trainer.py)
common_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'info', 'biz', 'us', 'ca', 'uk', 'de', 'jp', 'fr', 'au', 'ru'}

# --- Global Model and Feature Columns ---
model = None
feature_columns = None # This will store the exact feature names the model was trained on

# --- Feature Extraction Function (consistent with model_trainer.py) ---
def extract_features(url):
    """
    Extracts various features from a given URL for phishing detection.
    This function must be identical to the one used during model training.
    """
    features = {}
    
    # URL Length
    features['URLLength'] = len(url)
    features['URLLengthUnsafe'] = int(len(url) > 100)

    # Domain Length
    domain = urlparse(url).netloc
    features['DomainLength'] = len(domain)

    # Is HTTPS
    features['IsHTTPS'] = int(urlparse(url).scheme == 'https')
    
    # Number of Subdomains
    subdomains = domain.split('.')
    features['NoOfSubDomain'] = len(subdomains) - 1 if len(subdomains) > 1 else 0 # Fixed logic for subdomains
    features['SubdomainUnsafe'] = int(features['NoOfSubDomain'] > 3)
    
    # Number of Letters and Digits in URL
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    
    # Special Character Ratio in URL
    special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
    features['SpacialCharRatioInURL'] = special_chars / len(url) if len(url) > 0 else 0
    
    # Has Obfuscation (e.g., '@', '//', '..', hex encoding)
    features['HasObfuscation'] = int(
        ('@' in url) or 
        (url.count('//') > 1) or 
        ('..' in url) or 
        ('%' in url) or
        ('www.' in url and url.count('www.') > 1) # Example of multiple www.
    )
    
    # TLD Legitimacy
    tld = subdomains[-1] if len(subdomains) > 0 else ''
    features['TLDLegitimateProb'] = int(tld in common_tlds)
    
    return features

# --- Model Loading ---
def load_model():
    """
    Loads the pre-trained machine learning model and determines the expected
    feature columns from the model's internal feature_names_in_ attribute.
    """
    global model, feature_columns
    try:
        model = joblib.load(MODEL_PATH)
        print(f"Model loaded successfully from {MODEL_PATH}")
        
        # This is the most reliable way to get feature names if the model was trained with scikit-learn 0.23+
        if hasattr(model, 'feature_names_in_') and model.feature_names_in_ is not None:
            feature_columns = model.feature_names_in_.tolist()
            print(f"Expected feature columns from model: {feature_columns}")
        else:
            # Fallback if feature_names_in_ is not available (e.g., older scikit-learn or custom model)
            print("Warning: model.feature_names_in_ not found. Inferring feature columns from a dummy URL.")
            dummy_url = "http://www.example.com/test"
            dummy_features = extract_features(dummy_url)
            # Exclude 'label' if it was accidentally added here
            feature_columns = [f for f in dummy_features.keys() if f != 'label']
            print(f"Inferred feature columns: {feature_columns}")

    except FileNotFoundError:
        print(f"Error: Model file not found at {MODEL_PATH}. Please run model_trainer.py first to create it.")
        model = None # Ensure model is None so predict endpoint fails gracefully
        feature_columns = None
    except Exception as e:
        print(f"Error loading model: {e}")
        model = None
        feature_columns = None

# Load the model when the Flask app starts
with app.app_context():
    load_model()

# --- API Endpoint ---
@app.route('/predict', methods=['POST'])
def predict():
    """
    API endpoint to predict if a URL is phishing or benign.
    Expects a JSON payload with a 'url' key.
    Returns detailed features and a risk score.
    """
    if model is None or feature_columns is None:
        return jsonify({'error': 'Model not loaded or feature columns not initialized. Check backend logs.'}), 500

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Invalid request. Please provide a JSON payload with a "url" key.'}), 400

    url = data['url']
    
    try:
        # Extract features from the input URL
        extracted_features = extract_features(url)
        
        # Create a DataFrame from the extracted features, ensuring column order
        # It's crucial that features_df has the same columns in the same order as X_train during model training
        # We ensure this by explicitly providing feature_columns
        features_for_df = {k: extracted_features.get(k, 0) for k in feature_columns} # Use .get with default 0 for robustness
        features_df = pd.DataFrame([features_for_df], columns=feature_columns)
        
        # Ensure all columns are numeric, coercing errors to NaN and filling them
        for col in features_df.columns:
            features_df[col] = pd.to_numeric(features_df[col], errors='coerce')
        features_df = features_df.fillna(0) # Fill any NaNs that resulted from coercion
        
        # Make prediction
        prediction = model.predict(features_df)
        
        # Get prediction probabilities for risk score
        prediction_proba = model.predict_proba(features_df)
        # Assuming class 1 is 'phishing', the risk score is the probability of being phishing
        risk_score = prediction_proba[0][1] * 100 # Convert to percentage

        # Determine classification text based on prediction and risk score thresholds
        classification_text = 'Unsafe (Phishing)' if prediction[0] == 1 else 'Safe (Benign)'
        recommendation_text = ""
        
        # More nuanced classification for display
        if classification_text == 'Unsafe (Phishing)' or risk_score >= 70: # If model predicts phishing or high risk
            classification_display = 'PHISHING'
            recommendation_text = "Exercise extreme caution. This URL shows characteristics highly indicative of a phishing attempt. Do not proceed."
        elif risk_score >= 40: # If benign but with moderate risk characteristics
            classification_display = 'SUSPICIOUS'
            recommendation_text = "Exercise caution. This URL shows some suspicious characteristics. Verify its legitimacy before proceeding."
        else: # Low risk
            classification_display = 'BENIGN'
            recommendation_text = "This URL appears safe based on analysis. Always be vigilant and look for other red flags."


        # Prepare features for display (human-readable formatting)
        # Ensure that feature_details always contains the expected keys for the frontend
        display_features = {
            "HTTPS Security": "Secured" if extracted_features.get('IsHTTPS', 0) == 1 else "Not Secured",
            "URL Length": f"{extracted_features.get('URLLength', 0)} characters",
            "Subdomains": f"{extracted_features.get('NoOfSubDomain', 0)} detected",
            "Special Characters": f"{len(re.findall(r'[^a-zA-Z0-9]', url))} found", # Recalculate for precision if needed
            "Domain Length": f"{extracted_features.get('DomainLength', 0)} characters",
            "URL Length Unsafe": "Yes (URL too long)" if extracted_features.get('URLLengthUnsafe', 0) == 1 else "No",
            "Subdomain Unsafe": "Yes (Too many subdomains)" if extracted_features.get('SubdomainUnsafe', 0) == 1 else "No",
            "Has Obfuscation": "Yes (Obfuscation detected)" if extracted_features.get('HasObfuscation', 0) == 1 else "No",
            "TLD Legitimacy": "Legitimate" if extracted_features.get('TLDLegitimateProb', 0) == 1 else "Suspicious/Uncommon",
            "No of Letters In URL": f"{extracted_features.get('NoOfLettersInURL', 0)}",
            "No of Digits In URL": f"{extracted_features.get('NoOfDegitsInURL', 0)}",
            "Special Char Ratio In URL": f"{extracted_features.get('SpacialCharRatioInURL', 0):.2f}"
        }
        
        # Get current analysis date and time
        analyzed_date = datetime.now().strftime("%m/%d/%Y, %I:%M %p")

        return jsonify({
            'analyzed_url': url,
            'risk_score': round(risk_score), # Round to nearest integer for display
            'classification': classification_display,
            'recommendation': recommendation_text,
            'feature_details': display_features,
            'ml_summary': "Random Forest model analyzes key features for advanced pattern recognition and real-time feature extraction and classification.",
            'analyzed_date': analyzed_date
        })

    except Exception as e:
        # Log the full error traceback for debugging
        import traceback
        traceback.print_exc()
        print(f"Error during prediction for URL '{url}': {e}")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

# --- Health Check Endpoint ---
@app.route('/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint to verify the server is running.
    """
    return jsonify({'status': 'healthy', 'model_loaded': model is not None}), 200

if __name__ == '__main__':
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
