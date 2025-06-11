import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    RocCurveDisplay,
    classification_report
)
from utils.feature_extraction import extract_features
df = pd.read_csv("phishing_dataset.csv")
def safe_extract(url):
    try:
        return extract_features(url)
    except Exception as e:
        print(f" Extraction failed for {url}: {e}")
        return [0] * 10 
X = np.array([safe_extract(url) for url in df["url"]])
y = df["label"].values
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
param_grid = {
    "max_depth": [3, 5, 10, None],
    "min_samples_split": [2, 5, 10],
    "criterion": ["gini", "entropy"]
}

grid_search = GridSearchCV(
    DecisionTreeClassifier(random_state=42),
    param_grid,
    cv=5,
    n_jobs=-1,
    verbose=1
)
grid_search.fit(X_train, y_train)
model = grid_search.best_estimator_
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]
print("\n Accuracy:", accuracy_score(y_test, y_pred))
print(" Precision:", precision_score(y_test, y_pred))
print(" Recall:", recall_score(y_test, y_pred))
print(" F1 Score:", f1_score(y_test, y_pred))
print(" ROC-AUC Score:", roc_auc_score(y_test, y_proba))
print("\n Classification Report:\n", classification_report(y_test, y_pred))
os.makedirs("report", exist_ok=True)
os.makedirs("model", exist_ok=True)
with open("report/classification_report.txt", "w") as f:
    f.write(classification_report(y_test, y_pred))
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=["Benign", "Phishing"],
            yticklabels=["Benign", "Phishing"])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title(" Confusion Matrix")
plt.tight_layout()
plt.savefig("report/confusion_matrix.png")
plt.show()
RocCurveDisplay.from_estimator(model, X_test, y_test)
plt.title(" ROC Curve")
plt.tight_layout()
plt.savefig("report/roc_curve.png")
plt.show()
joblib.dump(model, "model/dt_phishing_model.pkl")
print(" Model saved as: model/dt_phishing_model.pkl")
