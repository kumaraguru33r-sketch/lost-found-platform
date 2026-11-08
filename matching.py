"""Basic item matching. Pure Python (no Flask), so it is easy to test.

Score (0-100) = name 35 + category 20 + description 20 + location 15 + date 10.
A match is only a *suggestion*: nothing is ever marked as matched automatically.
"""
import re
from difflib import SequenceMatcher

STOPWORDS = {
    "the", "and", "for", "with", "was", "has", "have", "this", "that", "from", "are",
    "its", "near", "found", "lost", "item", "left", "got", "very", "some", "any",
    "inside", "into", "there", "had", "can", "you", "your", "his", "her", "their",
}

WEIGHTS = {"name": 35, "category": 20, "description": 20, "location": 15, "date": 10}


def _stem(word):
    return word[:-1] if len(word) > 3 and word.endswith("s") else word


def tokens(text):
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {_stem(w) for w in words if len(w) > 2 and w not in STOPWORDS}


def _overlap(a, b):
    """Token overlap relative to the smaller set (0..1)."""
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def _ratio(a, b):
    return SequenceMatcher(None, (a or "").lower().strip(), (b or "").lower().strip()).ratio()


def score_pair(lost, found):
    """Return (score, reasons) comparing a lost item with a found item."""
    reasons = []

    name_sim = max(_overlap(tokens(lost.item_name), tokens(found.item_name)),
                   _ratio(lost.item_name, found.item_name))
    name_pts = WEIGHTS["name"] * name_sim
    if name_sim >= 0.5:
        reasons.append("Similar item name")

    cat_pts = 0
    if (lost.category or "").lower() == (found.category or "").lower():
        cat_pts = WEIGHTS["category"]
        reasons.append("Same category")

    desc_sim = _overlap(tokens(lost.description), tokens(found.description))
    desc_pts = WEIGHTS["description"] * min(1.0, desc_sim * 1.5)
    if desc_sim >= 0.25:
        reasons.append("Shared description keywords")

    loc_sim = max(_overlap(tokens(lost.location), tokens(found.location)),
                  _ratio(lost.location, found.location))
    loc_pts = WEIGHTS["location"] * loc_sim
    if loc_sim >= 0.5:
        reasons.append("Similar location")

    date_pts = 0
    if lost.report_date and found.report_date:
        delta = (found.report_date - lost.report_date).days  # found should be on/after lost
        if 0 <= delta <= 45:
            date_pts = WEIGHTS["date"] * (1 - delta / 45)
            if delta <= 14:
                reasons.append("Dates are close")
        elif -2 <= delta < 0:
            date_pts = WEIGHTS["date"] * 0.3

    total = round(name_pts + cat_pts + desc_pts + loc_pts + date_pts)
    return min(100, total), reasons


def find_matches(item, candidates, min_score=30, limit=6):
    """Compare `item` with opposite-type `candidates`.

    Returns a list of dicts: {"item", "score", "reasons"} sorted best-first.
    """
    results = []
    for other in candidates:
        if other.id == item.id or other.item_type == item.item_type:
            continue
        lost, found = (item, other) if item.item_type == "Lost" else (other, item)
        score, reasons = score_pair(lost, found)
        if score >= min_score:
            results.append({"item": other, "score": score, "reasons": reasons})
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:limit]
