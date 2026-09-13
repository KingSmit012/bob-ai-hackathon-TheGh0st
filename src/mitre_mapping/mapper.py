"""
mitre_mapping/mapper.py — Map incidents to MITRE ATT&CK techniques.

Two-stage approach:
  1. KEYWORD MATCH (fast, deterministic):
     Scan the incident's alert types and raw messages for keywords that
     match entries in our mitre_attack.json lookup table. This gives us
     a "candidate list" of possible techniques.

  2. LLM REFINEMENT (smart, contextual):
     Send the incident details + candidate list to the LLM and ask it
     to confirm/refine the mapping. The LLM can:
     - Remove false-match candidates
     - Add techniques it recognises from context
     - Rank them by relevance

WHY TWO STAGES?
  - Keyword matching alone is too rigid (misses context)
  - LLM alone is too expensive to run against the full MITRE catalogue
  - Combining them: fast pre-filter + smart refinement = best results
"""

import json
import re
import os
import sys
from typing import List, Dict, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from correlation.correlator import Incident
from llm.llm_client import LLMClient
from config import MITRE_ATTACK_FILE


def _load_mitre_data() -> List[Dict[str, Any]]:
    """Load the MITRE ATT&CK technique lookup table from JSON."""
    with open(MITRE_ATTACK_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


# ─── STAGE 1: KEYWORD MATCHING ──────────────────────────────────────────

def _keyword_match(incident: Incident) -> List[Dict[str, Any]]:
    """
    Find MITRE ATT&CK techniques whose keywords appear in the incident.

    We check both the alert_type fields and the raw_message text of
    every alert in the incident.

    Returns:
        List of matching technique dicts from mitre_attack.json,
        with an added 'match_score' field (number of keyword hits).
    """
    mitre_data = _load_mitre_data()
    matches = []

    # Build a big text blob from all alert content in this incident
    # so we can search it all at once
    text_blob = " ".join(
        f"{a.alert_type} {a.raw_message}".lower()
        for a in incident.alerts
    )

    for technique in mitre_data:
        match_count = 0
        for keyword in technique.get("keywords", []):
            if keyword.lower() in text_blob:
                match_count += 1

        if match_count > 0:
            # Add match score and include this technique
            tech_copy = dict(technique)
            tech_copy["match_score"] = match_count
            matches.append(tech_copy)

    # Sort by match score (most matches first)
    matches.sort(key=lambda t: t["match_score"], reverse=True)

    return matches


# ─── STAGE 2: LLM REFINEMENT ────────────────────────────────────────────

MITRE_PROMPT_TEMPLATE = """You are a cybersecurity analyst mapping a security incident to the MITRE ATT&CK framework.

## Incident Summary
- Incident ID: {incident_id}
- Alert Count: {alert_count}
- Primary Source IP: {primary_source_ip}
- Primary Destination IP: {primary_dest_ip}
- Involved Assets: {involved_assets}
- Alert Types: {alert_types}
- Max Severity: {max_severity}

## Key Alert Messages
{key_messages}

## Candidate MITRE ATT&CK Techniques (from keyword matching)
{candidates}

## Instructions
Based on the incident details above, select the MOST RELEVANT MITRE ATT&CK techniques from the candidates list. You may also suggest additional techniques not in the candidate list if the incident clearly maps to them.

For each technique, explain briefly WHY it applies to this incident.

## Required Output Format
Respond with ONLY a JSON array (no markdown, no explanation outside the JSON):
[
    {{
        "technique_id": "TXXXX",
        "name": "Technique Name",
        "tactic": "Tactic Name",
        "relevance": "<1 sentence explaining why this technique applies>"
    }}
]

Select 1-5 most relevant techniques. If none apply, return an empty array [].
"""


def _format_mitre_prompt(
    incident: Incident,
    candidates: List[Dict[str, Any]]
) -> str:
    """Build the MITRE mapping prompt from incident data and candidates."""

    # Include up to 10 key alert messages (to keep prompt reasonable)
    key_alerts = incident.alerts[:10]
    key_messages = "\n".join(
        f"  [{a.source}] {a.alert_type}: {a.raw_message[:200]}"
        for a in key_alerts
    )

    # Format candidate techniques
    if candidates:
        candidates_text = "\n".join(
            f"  - {t['technique_id']} — {t['name']} (Tactic: {t['tactic']}, "
            f"Keyword hits: {t['match_score']})"
            for t in candidates[:10]  # top 10 candidates
        )
    else:
        candidates_text = "  (No keyword matches found — use your judgement)"

    return MITRE_PROMPT_TEMPLATE.format(
        incident_id=incident.incident_id,
        alert_count=incident.alert_count,
        primary_source_ip=incident.primary_source_ip,
        primary_dest_ip=incident.primary_dest_ip,
        involved_assets=", ".join(sorted(incident.involved_assets)),
        alert_types=", ".join(sorted(incident.alert_types)),
        max_severity=incident.max_severity,
        key_messages=key_messages,
        candidates=candidates_text,
    )


def _parse_mitre_response(response_text: str) -> List[Dict[str, str]]:
    """Parse the LLM's MITRE mapping response (JSON array)."""

    # Try direct parse
    try:
        result = json.loads(response_text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try to extract from markdown code fences
    json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', response_text, re.DOTALL)
    if json_match:
        try:
            result = json.loads(json_match.group(1))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Try to find any JSON array
    json_match = re.search(r'\[.*\]', response_text, re.DOTALL)
    if json_match:
        try:
            result = json.loads(json_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    print(f"WARNING: Could not parse MITRE mapping response: {response_text[:200]}...")
    return []


# ─── PUBLIC API ──────────────────────────────────────────────────────────

def map_to_mitre(
    incident: Incident,
    llm_client: LLMClient,
) -> List[Dict[str, str]]:
    """
    Map an incident to MITRE ATT&CK techniques using keyword match + LLM.

    Args:
        incident:    The correlated Incident to map
        llm_client:  An initialised LLM client

    Returns:
        List of dicts, each with:
            technique_id: str (e.g. "T1110")
            name:         str (e.g. "Brute Force")
            tactic:       str (e.g. "Credential Access")
            relevance:    str (why this technique applies)
    """
    print(f"  Mapping {incident.incident_id} to MITRE ATT&CK...")

    # Stage 1: keyword matching
    candidates = _keyword_match(incident)
    print(f"    Keyword match found {len(candidates)} candidate techniques")

    # Stage 2: LLM refinement
    prompt = _format_mitre_prompt(incident, candidates)
    response = llm_client.generate(prompt)
    techniques = _parse_mitre_response(response)

    # Ensure each technique has the required fields
    cleaned = []
    for t in techniques:
        cleaned.append({
            "technique_id": t.get("technique_id", "Unknown"),
            "name": t.get("name", "Unknown"),
            "tactic": t.get("tactic", "Unknown"),
            "relevance": t.get("relevance", ""),
        })

    print(f"    Final mapping: {len(cleaned)} techniques")
    return cleaned
