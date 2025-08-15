"""Centralized heuristic threat scoring for DNS queries.
Returns a float 0.0-1.0 and suggested status ('allowed'/'blocked').
"""
from __future__ import annotations

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf"}
SUSPICIOUS_KEYWORDS = ("phish", "malware", "scam", "spam")


def compute_threat_score(domain: str) -> tuple[float, str]:
    if not domain:
        return 0.0, "allowed"
    name = domain.lower()
    score = 0.0
    # TLD heuristic
    parts = name.rsplit(".", 1)
    if len(parts) == 2 and parts[1] in SUSPICIOUS_TLDS:
        score += 0.4
    # keyword heuristic
    if any(k in name for k in SUSPICIOUS_KEYWORDS):
        score += 0.3
    # length / subdomain depth
    if len(name) > 50:
        score += 0.2
    if name.count('.') > 4:
        score += 0.2
    score = min(score, 1.0)
    status = "blocked" if score >= 0.7 else "allowed"
    return score, status
