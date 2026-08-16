import os
import pickle
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from feature_extractor import extract_features, get_feature_names


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "..",
    "dataset",
    "phishing_dataset_real.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model.pkl"
)


# =========================================================
# LOAD DATASET
# =========================================================

def load_dataset():

    print("=" * 60)
    print("PHISHING DETECTOR - MODEL COMPARISON")
    print("=" * 60)

    print("\n[1/6] Loading real-world dataset...")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found:\n{DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    df = df.dropna(
        subset=["url", "label"]
    )

    df = df.drop_duplicates(
        subset=["url"]
    )

    print(f"Records: {len(df)}")
    print(f"Safe: {sum(df['label'] == 0)}")
    print(f"Phishing: {sum(df['label'] == 1)}")

    return df


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_dataset_features(df):

    print("\n[2/6] Extracting URL features...")

    feature_names = get_feature_names()

    X = []

    for index, url in enumerate(df["url"]):

        features = extract_features(url)

        X.append([
            features[name]
            for name in feature_names
        ])

        if (index + 1) % 10000 == 0:
            print(
                f"Processed {index + 1}/{len(df)} URLs..."
            )

    X = pd.DataFrame(
        X,
        columns=feature_names
    )

    y = df["label"].astype(int)

    print(f"Features: {len(feature_names)}")

    return X, y


# =========================================================
# MODEL EVALUATION
# =========================================================

def evaluate_model(name, model, X_test, y_test):

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print(
        f"Accuracy : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision: {precision * 100:.2f}%"
    )

    print(
        f"Recall   : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score : {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print("\nConfusion Matrix:")
    print(matrix)

    return {
        "model": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc
    }


# =========================================================
# TRAINING
# =========================================================

def train_models():

    df = load_dataset()

    X, y = extract_dataset_features(
        df
    )

    # -----------------------------------------------------
    # Train/test split
    # -----------------------------------------------------

    print("\n[3/6] Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples : {len(X_test)}"
    )

    # -----------------------------------------------------
    # Random Forest
    # -----------------------------------------------------

    print(
        "\n[4/6] Training Random Forest..."
    )

    random_forest = RandomForestClassifier(
        n_estimators=250,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    random_forest.fit(
        X_train,
        y_train
    )

    # -----------------------------------------------------
    # HistGradientBoosting
    # -----------------------------------------------------

    print(
        "\n[5/6] Training HistGradientBoosting..."
    )

    gradient_boosting = HistGradientBoostingClassifier(
        max_iter=250,
        learning_rate=0.08,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        random_state=42
    )

    gradient_boosting.fit(
        X_train,
        y_train
    )

    # -----------------------------------------------------
    # Evaluation
    # -----------------------------------------------------

    print(
        "\n[6/6] Evaluating models..."
    )

    rf_results = evaluate_model(
        "RANDOM FOREST",
        random_forest,
        X_test,
        y_test
    )

    gb_results = evaluate_model(
        "HIST GRADIENT BOOSTING",
        gradient_boosting,
        X_test,
        y_test
    )

    # -----------------------------------------------------
    # Compare
    # -----------------------------------------------------

    print("\n" + "=" * 60)
    print("MODEL COMPARISON")
    print("=" * 60)

    results = [
        rf_results,
        gb_results
    ]

    results.sort(
        key=lambda x: (
            x["roc_auc"],
            x["f1"],
            x["recall"]
        ),
        reverse=True
    )

    for position, result in enumerate(
        results,
        start=1
    ):

        print(
            f"{position}. {result['model']}"
        )

        print(
            f"   ROC-AUC : {result['roc_auc']:.4f}"
        )

        print(
            f"   F1      : {result['f1'] * 100:.2f}%"
        )

        print(
            f"   Recall  : {result['recall'] * 100:.2f}%"
        )

    # -----------------------------------------------------
    # Select best model
    # -----------------------------------------------------

    best_result = results[0]

    if best_result["model"] == "RANDOM FOREST":

        best_model = random_forest

    else:

        best_model = gradient_boosting

    print(
        f"\nBEST MODEL: {best_result['model']}"
    )

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

    print(
        f"\nSaving best model to:\n{MODEL_PATH}"
    )

    with open(
        MODEL_PATH,
        "wb"
    ) as file:

        pickle.dump(
            best_model,
            file
        )

    print(
        "\nModel saved successfully."
    )

    print("\n" + "=" * 60)
    print("MODEL TRAINING COMPLETE")
    print("=" * 60)


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    train_models()