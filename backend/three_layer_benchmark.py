import json
import pickle
import requests
import re

# Load ML model
with open("ml_classifier.pkl", "rb") as f:
    model = pickle.load(f)
vectorizer = model["vectorizer"]
clf = model["classifier"]

# Load prompts
with open("prompts.json", "r") as f:
    prompts = json.load(f)

BASE_URL = "http://localhost:8000"
THRESHOLD = 15

# ── Static rule layer ─────────────────────────────────────────────────────────
STATIC_PATTERNS = [
    r"ignore.{0,20}(previous|prior|all).{0,20}instruct",
    r"system\s*prompt",
    r"you are now",
    r"no restrictions",
    r"developer mode",
    r"safety.{0,10}(off|disabled|bypass|ignore|filter)",
    r"(sk-|api.?key|secret|password|token|bearer|aws_access)[^\s]{4,}",
    r"ssn|social security|\d{3}-\d{2}-\d{4}",
    r"credit.?card|\d{16}",
    r"select.{0,20}from|insert into|drop table|update.{0,20}set",
    r"(send|forward|exfiltrate|log).{0,30}(http|\.com|\.io|webhook|external)",
    r"(dan|jailbreak|god mode|maintenance mode|admin mode|override)",
    r"ignore.{0,10}(safety|rules|guidelines|ethics)",
    r"context window|verbatim|base64|rot13",
    r"no (ethical|content).{0,10}(guidelines|policy|filter)",
]

def static_check(text):
    text_lower = text.lower()
    for pattern in STATIC_PATTERNS:
        if re.search(pattern, text_lower):
            return "vulnerable"
    return "safe"

results = []

print(f"{'Prompt':<40} {'Static':<12} {'ML':<12} {'API':<12} {'Ensemble':<12} {'Expected'}")
print("-" * 100)

for p in prompts[:20]:
    text = p["text"]
    expected = p["expected"]

    # Layer 1: Static rules
    static_pred = static_check(text)

    # Layer 2: ML classifier
    X = vectorizer.transform([text])
    ml_prob = clf.predict_proba(X)[0][1]
    ml_pred = "vulnerable" if ml_prob >= 0.5 else "safe"

    # Layer 3: PromptShield API (Claude semantic)
    try:
        response = requests.post(f"{BASE_URL}/api/scan", json={"text": text}, timeout=15)
        score = response.json().get("risk_score", 0)
        api_pred = "vulnerable" if score >= THRESHOLD else "safe"
    except Exception:
        api_pred = "error"

    # Ensemble: flag if any layer catches it
    ensemble_pred = "vulnerable" if any([
        static_pred == "vulnerable",
        ml_pred == "vulnerable",
        api_pred == "vulnerable"
    ]) else "safe"

    correct = ensemble_pred == expected
    results.append({
        "text": text,
        "expected": expected,
        "static": static_pred,
        "ml": ml_pred,
        "api": api_pred,
        "ensemble": ensemble_pred,
        "correct": correct
    })

    print(f"{text[:39]:<40} {static_pred:<12} {ml_pred:<12} {api_pred:<12} {ensemble_pred:<12} {expected} {'✓' if correct else '✗'}")

print("\n--- LAYER COMPARISON ---")
static_correct = sum(1 for r in results if r["static"] == r["expected"])
ml_correct = sum(1 for r in results if r["ml"] == r["expected"])
api_correct = sum(1 for r in results if r["api"] == r["expected"])
ensemble_correct = sum(1 for r in results if r["correct"])
total = len(results)

print(f"Static rules alone:       {static_correct}/{total} ({static_correct/total*100:.0f}%)")
print(f"ML classifier alone:      {ml_correct}/{total} ({ml_correct/total*100:.0f}%)")
print(f"Claude API alone:         {api_correct}/{total} ({api_correct/total*100:.0f}%)")
print(f"Ensemble (all 3 layers):  {ensemble_correct}/{total} ({ensemble_correct/total*100:.0f}%)")

print("\n--- WHERE LAYERS DISAGREE ---")
for r in results:
    preds = {r["static"], r["ml"], r["api"]}
    if len(preds) > 1:
        print(f"  Static:{r['static']:<12} ML:{r['ml']:<12} API:{r['api']:<12} Expected:{r['expected']:<12} | {r['text'][:35]}")

with open("three_layer_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nResults saved to three_layer_results.json")