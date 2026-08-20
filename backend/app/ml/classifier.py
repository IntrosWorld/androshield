"""ML inference: malware probability for an analysed APK.

Loads the trained model bundle (model.pkl) lazily. Entirely optional — if the model
file is missing or scikit-learn isn't importable, `available()` is False and the
analyzer skips ML, so the platform always runs on rules alone.
"""
import logging
import os

from . import features as F

log = logging.getLogger("ml_classifier")

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
_bundle = None
_load_attempted = False


def model_path() -> str:
    return os.path.abspath(_MODEL_PATH)


def available() -> bool:
    if not os.path.exists(_MODEL_PATH):
        return False
    return _load() is not None


def _load():
    global _bundle, _load_attempted
    if _load_attempted:
        return _bundle
    _load_attempted = True
    try:
        import joblib
        _bundle = joblib.load(_MODEL_PATH)
    except Exception as e:
        log.error("Failed to load ML model: %s", e)
        _bundle = None
    return _bundle


def metrics():
    b = _load()
    return (b or {}).get("metrics", {})


def predict(analysis: dict) -> dict:
    """Return malware probability + the permission signals that drove it."""
    if not available():
        return {"available": False}

    bundle = _load()
    vocab = bundle["vocabulary"]
    clf = bundle["model"]

    perm_set = F.perms_from_analysis(analysis)
    try:
        import numpy as np
        x = np.array([F.vectorize(perm_set, vocab)])
        proba = float(clf.predict_proba(x)[0][1])
    except Exception as e:
        log.exception("ML prediction failed")
        return {"available": True, "error": str(e)}

    # Which model-important permissions are actually present in this APK?
    present = []
    for feat in bundle.get("top_features", []):
        if feat["permission"] in perm_set:
            present.append(feat)
    present = present[:8]

    decision_threshold = float(bundle.get("operating_threshold", 0.8))
    # Below a conservative alert threshold means "no ML alert", not proof that an
    # APK is benign. Other static evidence can still establish high risk.
    prediction = "flagged" if proba >= decision_threshold else "not_flagged"
    confidence = proba if prediction == "flagged" else None
    return {
        "available": True,
        "malware_probability": round(proba, 4),
        "prediction": prediction,
        "decision_threshold": round(decision_threshold, 4),
        "confidence": round(confidence, 4) if confidence is not None else None,
        "contributing_permissions": present,
        "model_metrics": bundle.get("metrics", {}),
        "trained_at": bundle.get("trained_at"),
    }
