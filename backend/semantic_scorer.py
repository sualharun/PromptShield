"""
Semantic classifier using DeBERTa-v3 fine-tuned on prompt injection data.
Used as second layer in ensemble with TF-IDF classifier.
"""
import pickle
import logging
from typing import Optional

logger = logging.getLogger("promptshield.semantic")

_pipeline = None

def _load():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    try:
        from transformers import pipeline
        _pipeline = pipeline(
            'text-classification',
            model='protectai/deberta-v3-base-prompt-injection-v2'
        )
        logger.info("DeBERTa semantic classifier loaded")
    except Exception as e:
        logger.warning(f"DeBERTa unavailable: {e}")
        _pipeline = None
    return _pipeline

def semantic_score(text: str) -> Optional[float]:
    """Return injection probability from DeBERTa. None if unavailable."""
    clf = _load()
    if clf is None:
        return None
    try:
        result = clf(text[:512])[0]
        if result['label'] == 'INJECTION':
            return result['score']
        return 1.0 - result['score']
    except Exception as e:
        logger.warning(f"Semantic scoring failed: {e}")
        return None

def ensemble_score(text: str, tfidf_score: float, threshold: float = 0.6) -> dict:
    """
    Ensemble TF-IDF and DeBERTa scores.
    TF-IDF runs first. If score is uncertain (0.3-0.7), DeBERTa breaks the tie.
    """
    sem_score = semantic_score(text)
    
    if sem_score is None:
        return {
            'tfidf_score': tfidf_score,
            'semantic_score': None,
            'ensemble_score': tfidf_score,
            'flagged': tfidf_score >= threshold,
            'model': 'tfidf_only'
        }
    
    # Uncertain zone: let DeBERTa decide
    if 0.3 <= tfidf_score <= 0.7:
        final = (tfidf_score * 0.4) + (sem_score * 0.6)
        model = 'ensemble'
    else:
        final = tfidf_score
        model = 'tfidf_primary'
    
    return {
        'tfidf_score': round(tfidf_score, 3),
        'semantic_score': round(sem_score, 3),
        'ensemble_score': round(final, 3),
        'flagged': final >= threshold,
        'model': model
    }
