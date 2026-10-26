"""Opt-in native text kernels. Missing/incompatible extensions use Python safely."""
import logging
import os

log = logging.getLogger(__name__)
try:
    import _androshield_native as _extension
    if _extension.API_VERSION != 1:
        _extension = None
except (ImportError, OSError, AttributeError):
    _extension = None


def enabled() -> bool:
    return _extension is not None and os.getenv("ANDROSHIELD_NATIVE", "0") == "1"


def keyword_counts(strings, keywords, matchers):
    if not enabled():
        return _python_keywords(strings, keywords, matchers)
    strings = list(strings or [])
    counts, first = {}, {}
    fallback = range(len(strings))
    try:
        native_counts, native_first, fallback = _extension.keyword_stats(strings, keywords)
        for index, key in enumerate(keywords):
            if native_counts[index]:
                counts[key], first[key] = native_counts[index], native_first[index]
    except (TypeError, ValueError):
        return _python_keywords(strings, keywords, matchers)
    except Exception:
        log.warning("Native keyword kernel failed; using Python", exc_info=True)
        return _python_keywords(strings, keywords, matchers)
    for index in fallback:
        text = strings[index]
        if not text or len(text) > 4000:
            continue
        lower = text.lower()
        for key in keywords:
            if matchers[key].search(lower):
                counts[key] = counts.get(key, 0) + 1
                first[key] = min(first.get(key, index), index)
    # Preserve first-seen order, including tied keyword counts in report output.
    order = {key: index for index, key in enumerate(keywords)}
    return dict(sorted(counts.items(), key=lambda item: (first[item[0]], order[item[0]])))


def _python_keywords(strings, keywords, matchers):
    counts = {}
    for text in strings or []:
        if not text or len(text) > 4000:
            continue
        lower = text.lower()
        for key in keywords:
            if matchers[key].search(lower):
                counts[key] = counts.get(key, 0) + 1
    return counts


def entropy_counts(strings, entropy):
    strings = list(strings or [])
    high, candidates = 0, 0
    fallback = range(len(strings))
    if enabled():
        try:
            high, candidates, fallback = _extension.entropy_stats(strings)
        except (TypeError, ValueError):
            high, candidates, fallback = 0, 0, range(len(strings))
        except Exception:
            log.warning("Native entropy kernel failed; using Python", exc_info=True)
            high, candidates, fallback = 0, 0, range(len(strings))
    for index in fallback:
        text = strings[index]
        if 24 <= len(text) <= 512 and " " not in text:
            candidates += 1
            high += entropy(text) > 4.5
    return high, candidates
