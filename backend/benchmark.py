import requests
import json

def evaluate():
    import requests
    BASE_URL = "http://localhost:8000"
    THRESHOLD = 15
    try:
        with open("prompts.json", "r") as f:
            prompts = json.load(f)
    except FileNotFoundError:
        return {"f1": 0, "precision": 0, "recall": 0}
    
    results = []
    for p in prompts:
        try:
            response = requests.post(f"{BASE_URL}/api/scan", json={"text": p["text"]}, timeout=10)
            data = response.json()
            score = data.get("risk_score", 0)
        except Exception:
            score = 0
        predicted = "vulnerable" if score >= THRESHOLD else "safe"
        results.append({"expected": p["expected"], "predicted": predicted})
    
    tp = sum(1 for r in results if r["expected"] == "vulnerable" and r["predicted"] == "vulnerable")
    fp = sum(1 for r in results if r["expected"] == "safe" and r["predicted"] == "vulnerable")
    fn = sum(1 for r in results if r["expected"] == "vulnerable" and r["predicted"] == "safe")
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {"f1": f1, "precision": precision, "recall": recall}

if __name__ == "__main__":
    BASE_URL = "http://localhost:8000"
    THRESHOLD = 15

    with open("prompts.json", "r") as f:
        prompts = json.load(f)

    results = []

    for p in prompts:
        print(f"Scanning [{p['category']}]: {p['text'][:50]}...")
        response = requests.post(f"{BASE_URL}/api/scan", json={"text": p["text"]})
        data = response.json()
        score = data.get("risk_score", 0)
        predicted = "vulnerable" if score >= THRESHOLD else "safe"
        correct = predicted == p["expected"]
        results.append({
            "category": p["category"],
            "expected": p["expected"],
            "predicted": predicted,
            "score": score,
            "correct": correct
        })
        print(f"  {'✓' if correct else '✗'} Score:{score} | Expected:{p['expected']} | Got:{predicted}")

    tp = sum(1 for r in results if r["expected"] == "vulnerable" and r["predicted"] == "vulnerable")
    fp = sum(1 for r in results if r["expected"] == "safe" and r["predicted"] == "vulnerable")
    fn = sum(1 for r in results if r["expected"] == "vulnerable" and r["predicted"] == "safe")
    tn = sum(1 for r in results if r["expected"] == "safe" and r["predicted"] == "safe")
    correct_count = sum(1 for r in results if r["correct"])
    total = len(results)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n--- CONFUSION MATRIX ---")
    print(f"TP: {tp}  FP: {fp}")
    print(f"FN: {fn}  TN: {tn}")
    print(f"\n--- RESULTS ---")
    print(f"Accuracy:  {correct_count}/{total} ({correct_count/total*100:.1f}%)")
    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1 Score:  {f1:.2f}")

    with open("benchmark_results.json", "w") as f:
        json.dump({"accuracy": correct_count/total, "precision": precision, "recall": recall, "f1": f1, "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}, "results": results}, f, indent=2)
    print("\nResults saved to benchmark_results.json")