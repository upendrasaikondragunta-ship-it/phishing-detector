import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import pickle
import os

from feature_extractor import extract_features, get_feature_names

def load_data(filepath):
    """Loads data from a CSV file."""
    df = pd.read_csv(filepath)
    return df

def train_and_evaluate_model():
    """
    Trains a robust Random Forest classifier and outputs comprehensive evaluation metrics
    (Improvement 2 - Better Machine Learning Pipeline)
    """
    print("Loading dataset...")
    data_path = os.path.join("..", "dataset", "phishing_dataset.csv")
    
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return
        
    df = load_data(data_path)
    print(f"Dataset loaded. Total records: {len(df)}")
    
    print("Extracting features from URLs (this may take a moment)...")
    
    # We apply our feature extraction function to each URL
    # Now that extract_features returns a dict, we extract values in correct order
    X = []
    y = df['label'].values
    
    feature_keys = get_feature_names()
    
    for url in df['url']:
        features_dict = extract_features(url)
        # Convert dictionary to ordered list for ML model input
        features_list = [features_dict[key] for key in feature_keys]
        X.append(features_list)
        
    print("Features extracted successfully.")
    
    # Split the dataset into training and testing sets (80% train, 20% test)
    print("\n[ML PIPELINE] Splitting data into 80% Train / 20% Test...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize the RandomForestClassifier with optimized parameters
    print("[ML PIPELINE] Training RandomForest model...")
    model = RandomForestClassifier(
        n_estimators=150,       # Increased number of trees
        max_depth=15,           # Prevent severe overfitting
        random_state=42,
        class_weight='balanced' # Handle potential slight imbalances
    )
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Make predictions on the test set
    predictions = model.predict(X_test)
    
    # Calculate evaluation metrics
    print("\n================= MODEL EVALUATION =================")
    
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    conf_matrix = confusion_matrix(y_test, predictions)
    
    print(f"Accuracy Score:   {accuracy * 100:.2f}%")
    print(f"Precision Score:  {precision * 100:.2f}%  (When it says Phishing, how often is it right?)")
    print(f"Recall Score:     {recall * 100:.2f}%  (Out of all Phishing sites, how many did it catch?)")
    
    print("\nConfusion Matrix:")
    print(f"True  SAFE (TN)      : {conf_matrix[0][0]}")
    print(f"False PHISHING (FP)  : {conf_matrix[0][1]}  <-- Safe sites blocked (Annoying)")
    print(f"False SAFE (FN)      : {conf_matrix[1][0]}  <-- Phishing sites missed (Dangerous)")
    print(f"True  PHISHING (TP)  : {conf_matrix[1][1]}")
    print("====================================================")
    
    # Save the trained model
    model_filename = 'model.pkl'
    print(f"\nSaving model as {model_filename}...")
    with open(model_filename, 'wb') as file:
        pickle.dump(model, file)
        
    print("Done! Model is fully trained and ready for the real-time API.")

if __name__ == "__main__":
    train_and_evaluate_model()
