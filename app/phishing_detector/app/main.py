from flask import Flask, request, jsonify
from app.url_feature_extraction_functions import extract_features
import joblib
import os
import pandas as pd
import logging

app = Flask(__name__)

# Configure logging
log_file = os.path.join(os.path.dirname(__file__), 'flask_app.log')
logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

# Load the pre-trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
model = joblib.load(MODEL_PATH)

@app.route('/analyze', methods=['POST'])
def analyze():
    logging.debug("Received request to analyze URL")
    data = request.json
    url = data.get('url')
    
    if not url:
        logging.error("URL is required but not provided")
        return jsonify({'error': 'URL is required'}), 400

    try:
        # Extract features from the URL
        feature_series = extract_features(url)

        # Convert pd.Series to DataFrame for model prediction
        feature_df = pd.DataFrame([feature_series])

        # Predict using the loaded model
        prediction = model.predict(feature_df)[0]
        
        # Return prediction result
        result = {'is_phishing': bool(prediction)}  # Assuming binary classification (0 or 1)
        logging.info(f"Prediction result for URL {url}: {result}")
        return jsonify(result)
    except Exception as e:
        logging.exception("Exception occurred during URL analysis")
        return jsonify({'error': 'An error occurred during URL analysis'}), 500

if __name__ == '__main__':
    app.run(debug=True)
