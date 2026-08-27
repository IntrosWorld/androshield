"""ML inference: malware probability for an analysed APK.

Loads the trained model bundle (model.pkl) lazily. Entirely optional — if the model
file is missing or scikit-learn isn't importable, `available()` is False and the
analyzer skips ML, so the platform always runs on rules alone.
"""
import logging
import os
import threading
import warnings

from . import features as F
from . import static_features

log = logging.getLogger("ml_classifier")

_RICH_MODEL_PATH = os.path.join(os.path.dirname(__file__), "apk_static_model.joblib")
_LEGACY_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
_MODEL_PATH = os.getenv("APK_STATIC_MODEL_PATH", "").strip() or (
    _RICH_MODEL_PATH if os.path.exists(_RICH_MODEL_PATH) else _LEGACY_MODEL_PATH
)
_bundle = None
_load_attempted = False
_load_lock = threading.Lock()


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
    with _load_lock:
        if _load_attempted:
            return _bundle
        try:
            import joblib
            # scikit-learn emits an InconsistentVersionWarning for the Kaggle artifact.
            # We validate the bundle schema below and cover inference with regression tests;
            # suppress only this noisy persistence warning, not arbitrary warnings.
            try:
                from sklearn.exceptions import InconsistentVersionWarning
            except ImportError:  # pragma: no cover - older supported sklearn
                InconsistentVersionWarning = Warning
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InconsistentVersionWarning)
                candidate = joblib.load(_MODEL_PATH)
            if not isinstance(candidate, dict) or "model" not in candidate:
                raise ValueError("unsupported ML model bundle")
            if candidate.get("feature_kind") == "apk_static_evidence":
                if "vectorizer" not in candidate:
                    raise ValueError("rich model bundle is missing its vectorizer")
            elif "vocabulary" not in candidate:
                raise ValueError("legacy model bundle is missing its permission vocabulary")
            _bundle = candidate
        except Exception as e:
            log.error("Failed to load ML model: %s", e)
            _bundle = None
        finally:
            _load_attempted = True
    return _bundle


def metrics():
    b = _load()
    return (b or {}).get("metrics", {})


def model_info():
    b = _load() or {}
    return {
        "loaded": bool(b),
        "kind": b.get("feature_kind", "permission_multihot") if b else None,
        "path": model_path(),
        "feature_count": len(b.get("vectorizer").get_feature_names_out())
        if b.get("vectorizer") is not None else len(b.get("vocabulary", [])),
    }


def predict(analysis: dict) -> dict:
    """Return malware probability plus locally present influential features."""
    if not available():
        return {"available": False}

    bundle = _load()
    clf = bundle["model"]

    try:
        import numpy as np
        if bundle.get("feature_kind") == "apk_static_evidence":
            vectorizer = bundle["vectorizer"]
            x = vectorizer.transform([static_features.from_analysis(analysis)])
        else:
            perm_set = F.perms_from_analysis(analysis)
            x = np.array([F.vectorize(perm_set, bundle["vocabulary"])])
        proba = float(clf.predict_proba(x)[0][1])
    except Exception as e:
        log.exception("ML prediction failed")
        return {"available": True, "error": str(e)}

    present = []
    contributing_permissions = []
    if bundle.get("feature_kind") == "apk_static_evidence":
        names = bundle["vectorizer"].get_feature_names_out()
        importances = getattr(clf, "feature_importances_", [])
        active = set(x.indices.tolist()) if hasattr(x, "indices") else set()
        ranked = sorted(
            ((str(names[i]), float(importances[i])) for i in active),
            key=lambda item: item[1], reverse=True,
        )[:10]
        present = [{"feature": name, "importance": round(weight, 6)}
                   for name, weight in ranked]
        contributing_permissions = [
            {"permission": name.split("=", 1)[1], "importance": round(weight, 6)}
            for name, weight in ranked if name.startswith("perm=")
        ][:8]
    else:
        for feat in bundle.get("top_features", []):
            if feat["permission"] in perm_set:
                contributing_permissions.append(feat)
        contributing_permissions = contributing_permissions[:8]

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
        "model_kind": bundle.get("feature_kind", "permission_multihot"),
        "contributing_features": present,
        "contributing_permissions": contributing_permissions,
        "model_metrics": bundle.get("metrics", {}),
        "trained_at": bundle.get("trained_at"),
    }
