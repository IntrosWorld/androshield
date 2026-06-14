"""Shared feature space for the ML classifier.

The model is trained on **permission multi-hot vectors** because permissions are the
one feature both the Drebin dataset (`permission::` / `real_permission::` tokens) and
our androguard extractor (`analysis['permissions']['all_permissions']`) express the
*same way* — so a model trained on Drebin can be applied to our live analysis output
with no feature drift. The fitted vocabulary is saved alongside the model.

(Numeric features such as suspicious-API or IOC counts are deliberately omitted: their
scale differs between Drebin's raw token counts and our matched-label counts, which
would bias the model. Extend here only with features computable identically on both
sides.)
"""


def short_perm(p: str) -> str:
    """android.permission.SEND_SMS -> SEND_SMS (upper-cased, last segment)."""
    return p.rsplit(".", 1)[-1].strip().upper()


def perms_from_tokens(tokens):
    """Training side: extract the permission set from Drebin 'type::value' tokens."""
    perms = set()
    for t in tokens:
        t = t.strip()
        for prefix in ("permission::", "real_permission::"):
            if t.startswith(prefix):
                perms.add(short_perm(t[len(prefix):]))
    return perms


def perms_from_analysis(analysis) -> set:
    """Inference side: extract the permission set from our analysis dict."""
    perms = (analysis or {}).get("permissions", {}).get("all_permissions", []) or []
    return {short_perm(p) for p in perms}


def vectorize(perm_set, vocabulary):
    """Multi-hot vector for a permission set against a fixed ordered vocabulary."""
    s = set(perm_set)
    return [1 if v in s else 0 for v in vocabulary]
