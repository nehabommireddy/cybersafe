"""
train_model.py
--------------
Trains a simple phishing text classifier and saves it to model.pkl.

Pipeline: TF-IDF (word + char n-grams) -> Logistic Regression.

This ships with a tiny demo dataset (sample_data.csv) so the project runs
end to end. A 50-row dataset is NOT accurate enough for real use -- it is here
to prove the pipeline. To make this genuinely good, replace sample_data.csv
with a real labeled corpus (same two columns: `text`, `label`), for example:

  - "Phishing Email Dataset" on Kaggle
  - The Nazario phishing corpus (phishing) + Enron emails (legitimate)
  - Any CSV where label = 1 means phishing and label = 0 means legitimate.

Then just re-run:  python train_model.py
"""

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

DATA_PATH = "sample_data.csv"
MODEL_PATH = "model.pkl"


def build_pipeline() -> Pipeline:
    """TF-IDF features feeding a logistic regression classifier."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),     # unigrams + bigrams
            min_df=1,
            sublinear_tf=True,
            stop_words="english",
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",  # don't let one class dominate
            C=4.0,
        )),
    ])


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["text", "label"])
    X, y = df["text"].astype(str), df["label"].astype(int)

    pipe = build_pipeline()

    # With a tiny dataset, hold out a small test split just to print a sanity score.
    if len(df) >= 20 and y.nunique() == 2:
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        pipe.fit(X_tr, y_tr)
        print("Held-out evaluation (tiny demo set -- not meaningful at scale):")
        print(classification_report(y_te, pipe.predict(X_te),
                                    target_names=["legit", "phishing"],
                                    zero_division=0))

    # Refit on ALL data so the shipped model uses every example.
    pipe.fit(X, y)
    joblib.dump(pipe, MODEL_PATH)
    print(f"Saved trained model -> {MODEL_PATH}  ({len(df)} training rows)")


if __name__ == "__main__":
    main()
