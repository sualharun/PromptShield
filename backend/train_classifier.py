import json
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

# Load prompts
with open("prompts.json", "r") as f:
    prompts = json.load(f)

texts = [p["text"] for p in prompts]
labels = [1 if p["expected"] == "vulnerable" else 0 for p in prompts]

print(f"Dataset: {len(texts)} prompts ({sum(labels)} vulnerable, {len(labels)-sum(labels)} safe)")

# TF-IDF vectorizer
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=500,
    sublinear_tf=True
)
X = vectorizer.fit_transform(texts)
y = np.array(labels)

# Train logistic regression
clf = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
clf.fit(X, y)

# Cross validation
cv_scores = cross_val_score(clf, X, y, cv=5, scoring="f1")
print(f"\nCross-validation F1 scores: {cv_scores}")
print(f"Mean F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

# Full dataset evaluation
y_pred = clf.predict(X)
print(f"\nClassification Report:")
print(classification_report(y, y_pred, target_names=["safe", "vulnerable"]))

print(f"\nConfusion Matrix:")
cm = confusion_matrix(y, y_pred)
print(f"TN: {cm[0][0]}  FP: {cm[0][1]}")
print(f"FN: {cm[1][0]}  TP: {cm[1][1]}")

# Top features
feature_names = vectorizer.get_feature_names_out()
coefs = clf.coef_[0]
top_vulnerable = np.argsort(coefs)[-15:][::-1]
top_safe = np.argsort(coefs)[:15]

print(f"\nTop features indicating VULNERABLE:")
for i in top_vulnerable:
    print(f"  {feature_names[i]}: {coefs[i]:.3f}")

print(f"\nTop features indicating SAFE:")
for i in top_safe:
    print(f"  {feature_names[i]}: {coefs[i]:.3f}")

# Save model
with open("ml_classifier.pkl", "wb") as f:
    pickle.dump({"vectorizer": vectorizer, "classifier": clf}, f)
print(f"\nModel saved to ml_classifier.pkl")