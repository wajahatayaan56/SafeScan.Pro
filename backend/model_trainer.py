import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, roc_curve, auc # Added roc_curve, auc
import seaborn as sns
import matplotlib.pyplot as plt
import joblib
import os # Import os for path handling

# Define paths for data and model
# IMPORTANT: Adjust these paths if your project structure is different
# Ensure 'data' and 'model' directories exist within your 'backend' folder.
DATA_DIR = 'data'
MODEL_DIR = 'model'
RAW_DATA_PATH = os.path.join(DATA_DIR, 'raw_data.csv')
EXTRACTED_FEATURES_PATH = os.path.join(DATA_DIR, 'extracted_features.csv')
CLEANED_DATA_PATH = os.path.join(DATA_DIR, 'clean_data.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest_model.pkl')

# Ensure necessary directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)


# --- 4. Feature Extraction Function ---
# List of common TLDs (you can expand this list)
common_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'co', 'biz', 'info', 'xyz', 'online', 'app'}

def extract_features(url):
    """
    Extracts various features from a given URL string.
    These features are used as input for the machine learning model.
    """
    features = {}

    # 1. URL Length
    features['URLLength'] = len(url)
    features['URLLengthUnsafe'] = int(len(url) > 100) # Binary: 1 if long, 0 otherwise

    # 2. Domain Length
    try:
        domain = urlparse(url).netloc
    except ValueError: # Handle malformed URLs
        domain = ''
    features['DomainLength'] = len(domain)

    # 3. Is HTTPS
    features['IsHTTPS'] = int(urlparse(url).scheme == 'https')

    # 4. Number of Subdomains
    # Split by '.' and count parts before the last two (domain.tld)
    subdomains_parts = domain.split('.')
    # Handle cases like 'example.com' (no subdomains) or 'www.example.com'
    if len(subdomains_parts) > 2 and subdomains_parts[0] != 'www': # Exclude 'www' as a true subdomain for simple count
         features['NoOfSubDomain'] = len(subdomains_parts) - 2 # Subtract domain and tld
    elif len(subdomains_parts) > 2 and subdomains_parts[0] == 'www':
         features['NoOfSubDomain'] = len(subdomains_parts) - 2 # Count only if more than just www
    else:
        features['NoOfSubDomain'] = 0

    features['SubdomainUnsafe'] = int(features['NoOfSubDomain'] > 3) # Binary: 1 if many subdomains, 0 otherwise

    # 5. Number of Letters and Digits in URL
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)

    # 6. Special Character Ratio in URL
    special_chars_count = len(re.findall(r'[^a-zA-Z0-9]', url))
    features['SpacialCharRatioInURL'] = special_chars_count / len(url) if len(url) > 0 else 0.0

    # 7. Has Obfuscation (e.g., '@', '//', '..', hex encoding '%')
    # Updated to be more specific to common obfuscation patterns
    features['HasObfuscation'] = int(
        ('@' in url) or
        ('//' in url[url.find('://')+3:]) or # Check for extra // after http:// or https://
        ('..' in url) or
        ('%' in url)
    )

    # 8. TLD Legitimacy (checking if TLD is common/known)
    tld = subdomains_parts[-1] if len(subdomains_parts) > 1 else ''
    features['TLDLegitimateProb'] = int(tld in common_tlds) # Binary: 1 if common TLD, 0 otherwise

    return features

# --- Main training function ---
def train_model():
    """
    Trains the Random Forest Classifier model for phishing URL detection.
    Loads data, extracts features, cleans, trains, evaluates, and saves the model.
    """
    print("Starting model training process...")

    # --- 3. Load Dataset ---
    # Load the dataset
    try:
        df = pd.read_csv(RAW_DATA_PATH, header=None, names=["url", "type"])
        print(f"Dataset loaded from {RAW_DATA_PATH}. First 5 rows:\n{df.head()}")
    except FileNotFoundError:
        print(f"Error: raw_data.csv not found at {RAW_DATA_PATH}.")
        print("Please ensure 'raw_data.csv' is in the 'backend/data/' directory.")
        return

    # --- 4. Apply Feature Extraction ---
    print("Extracting features from URLs...")
    df['features'] = df['url'].apply(extract_features)
    feature_df = pd.DataFrame(df['features'].tolist())

    # Combine features with the original dataset
    final_df = pd.concat([df, feature_df], axis=1)
    final_df.drop(columns=['features'], inplace=True) # Remove the temporary 'features' column
    
    # Save the extracted features to a new CSV file (optional, for inspection)
    final_df.to_csv(EXTRACTED_FEATURES_PATH, index=False)
    print(f"Extracted features saved to {EXTRACTED_FEATURES_PATH}. First 5 rows:\n{final_df.head()}")


    # --- 5. Clean the Dataset ---
    print("Cleaning the dataset (handling missing values)...")
    cleaned_df = final_df.dropna()
    
    # Save the cleaned dataset to a new CSV file (optional)
    cleaned_df.to_csv(CLEANED_DATA_PATH, index=False)
    print(f"Cleaned dataset saved to: {CLEANED_DATA_PATH}. First 5 rows:\n{cleaned_df.head()}")


    # --- 6. Prepare and Train the Model ---
    print("Preparing data for model training...")
    # X will contain all the numerical features
    X = cleaned_df.drop(columns=['url', 'type'])
    # y will contain the labels: 1 for 'phishing', 0 for 'benign'
    y = cleaned_df['type'].apply(lambda x: 1 if x == 'phishing' else 0)

    # Split the data into training (80%) and testing (20%) sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.01, random_state=42) # Reduced test_size to 1% for faster evaluation if needed.

    print("Training the Random Forest model...")
    model = RandomForestClassifier(random_state=42, n_estimators=100) # Added n_estimators for robustness
    model.fit(X_train, y_train)

    # Save the trained model
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved successfully to: {MODEL_PATH}")

    # Display the classes learned by the model (important for prediction mapping in app.py)
    print(f"Model classes: {model.classes_}")

    # --- 7. Evaluate the Model ---
    print("\nEvaluating model performance on the test set...")
    # Predict on the test set
    y_pred = model.predict(X_test)

    # Confusion Matrix
    conf_matrix = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(conf_matrix)
    # Visualize Confusion Matrix
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign (Predicted 0)', 'Phishing (Predicted 1)'],
                yticklabels=['Benign (Actual 0)', 'Phishing (Actual 1)'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Confusion Matrix for URL Phishing Detection')
    plt.show()

    # Classification Report
    # Ensure target_names match the mapping in y (0 -> Benign, 1 -> Phishing)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Phishing']))

    # Overall Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nOverall Accuracy: {accuracy:.4f}")

    # --- ROC Curve ---
    print("\nGenerating ROC Curve...")
    # Get prediction probabilities for the positive class (phishing, which is class 1)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Calculate ROC curve metrics
    fpr, tpr, thresholds = roc_curve(y_test, y_proba)
    roc_auc = auc(fpr, tpr)

    # Plot ROC curve
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.show()

    print("Model training and evaluation finished successfully.")

# Entry point for the script
if __name__ == "__main__":
    train_model()
