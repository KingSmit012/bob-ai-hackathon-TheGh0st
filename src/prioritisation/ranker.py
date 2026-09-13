"""
prioritisation/ranker.py — Rank incidents by priority score.

After incidents are classified and MITRE-mapped, this module computes
a priority score for each one. The score determines the order in which
incidents appear in the final BLUF report — highest priority first.

PRIORITY SCORE FORMULA:
    priority = (severity_score * W_sev)
             + (confidence     * W_conf)
             + (asset_crit     * W_asset)
             + (alert_density  * W_density)

Where:
    severity_score:  critical=4, high=3, medium=2, low=1 (normalised to 0-1)
    confidence:      LLM confidence 0-100 (normalised to 0-1)
    asset_criticality: from asset_criticality.json (1-5, normalised to 0-1)
    alert_density:   number of alerts in the incident (capped and normalised)

The weights default to: severity=0.35, confidence=0.25, asset=0.25, density=0.15
and can be tuned via environment variables.

FALSE POSITIVES get a large penalty so they always rank below genuine threats.
"""

import json
import os
import sys
from typing import List, Dict, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from correlation.correlator import Incident
from config import (
    WEIGHT_SEVERITY,
    WEIGHT_CONFIDENCE,
    WEIGHT_ASSET_CRITICALITY,
    WEIGHT_ALERT_DENSITY,
    ASSET_CRITICALITY_FILE,
)


# Severity to numeric score
SEVERITY_SCORES = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _load_asset_criticality() -> Dict[str, int]:
    """
    Load the asset criticality lookup from JSON.

    Returns a dict mapping asset_name -> criticality (1-5).
    """
    try:
        with open(ASSET_CRITICALITY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Extract just the criticality values
        return {
            name: info.get("criticality", 2)
            for name, info in data.items()
        }
    except FileNotFoundError:
        print("WARNING: asset_criticality.json not found, defaulting all to 2")
        return {}


def compute_priority(
    incident: Incident,
    classification: Dict[str, Any],
) -> float:
    """
    Compute a priority score for a single incident.

    Args:
        incident:        The correlated Incident
        classification:  Dict with 'classification', 'confidence', 'reasoning'

    Returns:
        Priority score as a float (0.0 to 1.0). Higher = more urgent.
    """
    asset_criticality = _load_asset_criticality()

    # ── Factor 1: Severity (0.0 to 1.0) ──
    severity_raw = SEVERITY_SCORES.get(incident.max_severity, 2)
    severity_norm = severity_raw / 4.0  # max is 4 (critical)

    # ── Factor 2: Confidence (0.0 to 1.0) ──
    confidence_raw = classification.get("confidence", 50)
    confidence_norm = confidence_raw / 100.0

    # ── Factor 3: Asset Criticality (0.0 to 1.0) ──
    # Use the HIGHEST criticality among all involved assets
    max_asset_crit = 2  # default
    for asset in incident.involved_assets:
        crit = asset_criticality.get(asset, 2)
        max_asset_crit = max(max_asset_crit, crit)
    asset_crit_norm = max_asset_crit / 5.0  # max is 5

    # ── Factor 4: Alert Density (0.0 to 1.0) ──
    # More alerts = potentially more significant (capped at 20)
    alert_count_capped = min(incident.alert_count, 20)
    density_norm = alert_count_capped / 20.0

    # ── Compute weighted score ──
    score = (
        severity_norm * WEIGHT_SEVERITY
        + confidence_norm * WEIGHT_CONFIDENCE
        + asset_crit_norm * WEIGHT_ASSET_CRITICALITY
        + density_norm * WEIGHT_ALERT_DENSITY
    )

    # ── FALSE POSITIVE PENALTY ──
    # If classified as false positive, heavily penalise the score
    # so genuine threats always appear first in the ranking
    if classification.get("classification") == "false_positive":
        score *= 0.2  # reduce to 20% of original

    return round(score, 4)


def rank_incidents(
    incidents: List[Incident],
    classifications: Dict[str, Dict[str, Any]],
) -> List[Tuple[Incident, float]]:
    """
    Rank all incidents by priority score (highest first).

    Args:
        incidents:        List of correlated Incidents
        classifications:  Dict mapping incident_id -> classification result

    Returns:
        List of (Incident, priority_score) tuples, sorted descending.
    """
    scored = []
    for incident in incidents:
        classification = classifications.get(
            incident.incident_id,
            {"classification": "genuine_threat", "confidence": 50, "reasoning": "Unclassified"}
        )
        score = compute_priority(incident, classification)
        scored.append((incident, score))

    # Sort by score descending (highest priority first)
    scored.sort(key=lambda x: x[1], reverse=True)

    print(f"Ranked {len(scored)} incidents by priority")
    for inc, score in scored:
        cls = classifications.get(inc.incident_id, {})
        label = cls.get("classification", "?")
        print(f"  {inc.incident_id}: score={score:.4f} ({label}, "
              f"{inc.alert_count} alerts, severity={inc.max_severity})")

    return scored
