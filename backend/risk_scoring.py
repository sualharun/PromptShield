import pickle
from typing import List

from fastapi import APIRouter
from pydantic import BaseModel

with open("ml_classifier.pkl", "rb") as f:
    model = pickle.load(f)
vectorizer = model["vectorizer"]
clf = model["classifier"]

router = APIRouter()

class RepoPrompt(BaseModel):
    repo: str
    prompts: List[str]

class RepoRiskRequest(BaseModel):
    repos: List[RepoPrompt]

@router.post("/api/risk-scoring")
def score_repos(request: RepoRiskRequest):
    results = []

    for repo in request.repos:
        if not repo.prompts:
            avg_score = 0.0
            max_score = 0.0
            flagged = 0
        else:
            X = vectorizer.transform(repo.prompts)
            probs = clf.predict_proba(X)[:, 1]
            avg_score = float(probs.mean())
            max_score = float(probs.max())
            flagged = int((probs >= 0.5).sum())

        results.append({
            "repo": repo.repo,
            "avg_risk_score": round(avg_score, 3),
            "max_risk_score": round(max_score, 3),
            "flagged_prompts": flagged,
            "total_prompts": len(repo.prompts),
            "priority": "CRITICAL" if avg_score >= 0.8 else
                       "HIGH" if avg_score >= 0.6 else
                       "MEDIUM" if avg_score >= 0.3 else "LOW"
        })

    results.sort(key=lambda x: x["avg_risk_score"], reverse=True)

    return {
        "ranked_repos": results,
        "total_repos": len(results),
        "critical_count": sum(1 for r in results if r["priority"] == "CRITICAL"),
        "high_count": sum(1 for r in results if r["priority"] == "HIGH"),
    }