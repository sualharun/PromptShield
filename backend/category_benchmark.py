import json
import pickle
import numpy as np
from sklearn.metrics import classification_report, f1_score

with open("ml_classifier.pkl", "rb") as f:
    model = pickle.load(f)
vectorizer = model["vectorizer"]
clf = model["classifier"]

with open("prompts.json") as f:
    data = json.load(f)

categories = sorted(set(p.get("category") for p in data if p.get("category") != "benign"))

print(f"{'Category':<30} {'Samples':>7} {'F1':>6} {'Precision':>10} {'Recall':>8}")
print("-" * 65)

for cat in categories:
    cat_data = [p for p in data if p.get("category") in [cat, "benign"]]
    texts = [p["text"] for p in cat_data]
    labels = [0 if p["category"] == "benign" else 1 for p in cat_data]
    
    if sum(labels) < 2:
        print(f"{cat:<30} {'<2 samples':>7} {'N/A':>6}")
        continue
    
    X = vectorizer.transform(texts)
    preds = clf.predict(X)
    
    attack_count = sum(labels)
    f1 = f1_score(labels, preds, zero_division=0)
    from sklearn.metrics import precision_score, recall_score
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)
    
    print(f"{cat:<30} {attack_count:>7} {f1:>6.3f} {prec:>10.3f} {rec:>8.3f}")

