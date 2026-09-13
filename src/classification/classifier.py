"""
classification/classifier.py — Classify incidents as genuine threat or false positive.

This module takes a correlated Incident and asks the LLM:
  "Is this a genuine threat or a likely false positive?"

The LLM receives a structured prompt containing:
  - Summary of the incident (alert count, IPs, assets, time range)
  - All raw alert messages in the incident
  - Instructions to respond in a specific JSON format

The response includes:
  - classification: "genuine_threat" or "false_positive"
  - confidence: 0-100 (how confident the LLM is)
  - reasoning: why it classified this way

PROMPT ENGINEERING NOTES:
  - We use a very explicit output format (JSON) so we can parse it
  - We give the LLM domain context (SOC analyst role)
  - We list specific indicators of genuine threats vs false positives
  - The prompt template is a plain string constant — easy to inspect/tune
"""

import json
import re
import os
import sys
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from correlation.correlator import Incident
from llm.llm_client import LLMClient


# ─── PROMPT TEMPLATE ────────────────────────────────────────────────────
# This is the prompt sent to the LLM for each incident.
# You can edit this to tune the classification behaviour.

CLASSIFICATION_PROMPT_TEMPLATE = """You are an expert Security Operations Centre (SOC) analyst performing alert triage. Your job is to determine whether a correlated incident represents a GENUINE THREAT or is a LIKELY FALSE POSITIVE.

## Incident Summary
- Incident ID: {incident_id}
- Time Range: {time_start} to {time_end}
- Alert Count: {alert_count}
- Sources: {sources}
- Primary Source IP: {primary_source_ip}
- Primary Destination IP: {primary_dest_ip}
- Involved Assets: {involved_assets}
- Alert Types: {alert_types}
- Maximum Severity: {max_severity}

## Raw Alert Messages
{raw_messages}

## Classification Guidelines

GENUINE THREAT indicators:
- Multiple related alerts forming an attack chain (recon -> exploit -> action)
- Known malicious IPs or domains (from threat intelligence)
- Successful authentication after multiple failures (brute force success)
- Unusual login locations or times for a user
- Data exfiltration patterns (large outbound transfers)
- Command & control beacon patterns (periodic callbacks)
- Privilege escalation attempts
- Lateral movement between internal systems

FALSE POSITIVE indicators:
- Alerts from authorised vulnerability scanners
- Routine system operations (backups, updates, certificate renewals)
- Single failed logins with no follow-up
- DNS spikes from legitimate software updates
- Firewall blocks of routine traffic (DEFAULT-DENY rules)
- Known benign sources (internal scanners, monitoring tools)
- Informational/operational alerts with no security impact

## Required Output Format
Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{{
    "classification": "genuine_threat" or "false_positive",
    "confidence": <number 0-100>,
    "reasoning": "<2-3 sentence explanation of your classification>"
}}
"""


def _format_incident_for_prompt(incident: Incident) -> str:
    """
    Format an Incident's data into the prompt template.

    This creates the full prompt string by filling in all the
    placeholders in CLASSIFICATION_PROMPT_TEMPLATE.
    """
    # Format all raw messages with numbering
    raw_messages = "\n".join(
        f"  [{i+1}] [{a.source}] [{a.severity_reported.upper()}] {a.raw_message}"
        for i, a in enumerate(incident.alerts)
    )

    # Get unique sources
    sources = ", ".join(sorted({a.source for a in incident.alerts}))

    return CLASSIFICATION_PROMPT_TEMPLATE.format(
        incident_id=incident.incident_id,
        time_start=incident.time_start.strftime("%Y-%m-%d %H:%M:%S"),
        time_end=incident.time_end.strftime("%Y-%m-%d %H:%M:%S"),
        alert_count=incident.alert_count,
        sources=sources,
        primary_source_ip=incident.primary_source_ip,
        primary_dest_ip=incident.primary_dest_ip,
        involved_assets=", ".join(sorted(incident.involved_assets)),
        alert_types=", ".join(sorted(incident.alert_types)),
        max_severity=incident.max_severity,
        raw_messages=raw_messages,
    )


def _parse_llm_response(response_text: str) -> Dict[str, Any]:
    """
    Parse the LLM's JSON response into a Python dict.

    The LLM should return a JSON object, but sometimes it wraps it in
    markdown code fences or adds extra text. This function handles those
    edge cases gracefully.
    """
    # Try to extract JSON from the response
    # First, try direct JSON parse
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON in markdown code fences
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response_text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find any JSON object in the text
    json_match = re.search(r'\{[^{}]*"classification"[^{}]*\}', response_text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # If all parsing fails, return a default (mark as uncertain)
    print(f"WARNING: Could not parse LLM response as JSON: {response_text[:200]}...")
    return {
        "classification": "genuine_threat",  # err on side of caution
        "confidence": 50,
        "reasoning": f"LLM response could not be parsed. Raw: {response_text[:200]}"
    }


def classify_incident(
    incident: Incident,
    llm_client: LLMClient,
) -> Dict[str, Any]:
    """
    Classify a single incident as genuine threat or false positive.

    Args:
        incident:    The correlated Incident to classify
        llm_client:  An initialised LLM client (watsonx or Anthropic)

    Returns:
        Dict with keys:
            classification: "genuine_threat" or "false_positive"
            confidence:     int 0-100
            reasoning:      str explanation
    """
    # Build the prompt
    prompt = _format_incident_for_prompt(incident)

    # Call the LLM
    print(f"  Classifying {incident.incident_id} ({incident.alert_count} alerts)...")
    response = llm_client.generate(prompt)

    # Parse the response
    result = _parse_llm_response(response)

    # Validate and normalise
    result["classification"] = result.get("classification", "genuine_threat").lower()
    if result["classification"] not in ("genuine_threat", "false_positive"):
        result["classification"] = "genuine_threat"  # err on side of caution

    result["confidence"] = max(0, min(100, int(result.get("confidence", 50))))
    result["reasoning"] = result.get("reasoning", "No reasoning provided")

    return result
