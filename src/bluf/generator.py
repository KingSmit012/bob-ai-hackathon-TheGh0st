"""
bluf/generator.py — Generate BLUF (Bottom Line Up Front) summaries.

BLUF is a military/intelligence briefing format where the most important
conclusion comes FIRST, followed by supporting detail. This is exactly
what a defence decision-maker needs — they should get the picture in
seconds, not minutes.

BLUF format:
    BOTTOM LINE: [One sentence — what happened and what's the risk]

    SUPPORTING DETAIL:
    - [Key facts supporting the bottom line]

    MITRE ATT&CK MAPPING:
    - [Technique IDs and names]

    RECOMMENDED ACTION:
    - [What should the analyst/commander do next]

This module sends the classified, MITRE-mapped incident to the LLM
and asks it to generate a BLUF summary.
"""

import json
import os
import sys
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from correlation.correlator import Incident
from llm.llm_client import LLMClient


# ─── PROMPT TEMPLATE ────────────────────────────────────────────────────
# This prompt instructs the LLM to generate a BLUF-format summary.
# The format is very specific — decision-makers expect this exact structure.

BLUF_PROMPT_TEMPLATE = """You are a senior intelligence analyst writing a BLUF (Bottom Line Up Front) briefing for a defence decision-maker. The reader has 30 seconds to understand the situation and decide on action.

## Incident Data
- Incident ID: {incident_id}
- Classification: {classification} (Confidence: {confidence}%)
- Time Range: {time_start} to {time_end}
- Alert Count: {alert_count}
- Primary Attacker IP: {primary_source_ip}
- Primary Target: {primary_dest_ip} ({involved_assets})
- Maximum Severity: {max_severity}
- Classification Reasoning: {reasoning}

## MITRE ATT&CK Techniques Identified
{mitre_techniques}

## Alert Details
{alert_details}

## Instructions
Write a BLUF-format intelligence summary using EXACTLY this structure:

BOTTOM LINE: [One clear sentence stating what happened, the threat level, and immediate risk. Be specific — mention the asset, attacker, and attack type.]

SUPPORTING DETAIL:
- [Fact 1: What triggered the incident]
- [Fact 2: Key indicators of compromise]
- [Fact 3: Timeline of events]
- [Fact 4: Scope/impact assessment]

MITRE ATT&CK: [List the technique IDs and names, comma-separated]

RECOMMENDED ACTION:
- [Action 1: Immediate response step]
- [Action 2: Investigation step]
- [Action 3: Remediation/hardening step]

Rules:
- Be concise and factual — no speculation, no jargon
- Use active voice ("Block IP X" not "It is recommended that IP X be blocked")
- Prioritise actionable intelligence
- If this is a false positive, say so clearly in the BOTTOM LINE
"""


def generate_bluf(
    incident: Incident,
    classification: Dict[str, Any],
    mitre_techniques: List[Dict[str, str]],
    llm_client: LLMClient,
) -> str:
    """
    Generate a BLUF summary for a classified, MITRE-mapped incident.

    Args:
        incident:          The correlated Incident
        classification:    Dict from classifier (classification, confidence, reasoning)
        mitre_techniques:  List of MITRE technique dicts from mapper
        llm_client:        An initialised LLM client

    Returns:
        BLUF summary as a formatted string.
    """
    print(f"  Generating BLUF for {incident.incident_id}...")

    # Format MITRE techniques for the prompt
    if mitre_techniques:
        mitre_text = "\n".join(
            f"  - {t['technique_id']} — {t['name']} ({t['tactic']}): {t.get('relevance', '')}"
            for t in mitre_techniques
        )
    else:
        mitre_text = "  (No MITRE ATT&CK techniques mapped)"

    # Format alert details (include up to 15 for context, avoid huge prompts)
    alert_details = "\n".join(
        f"  [{a.timestamp.strftime('%H:%M:%S')}] [{a.source}] [{a.severity_reported.upper()}] "
        f"{a.alert_type}: {a.raw_message[:250]}"
        for a in incident.alerts[:15]
    )
    if len(incident.alerts) > 15:
        alert_details += f"\n  ... and {len(incident.alerts) - 15} more alerts"

    # Build the prompt
    prompt = BLUF_PROMPT_TEMPLATE.format(
        incident_id=incident.incident_id,
        classification=classification.get("classification", "unknown").replace("_", " ").title(),
        confidence=classification.get("confidence", 50),
        time_start=incident.time_start.strftime("%Y-%m-%d %H:%M:%S"),
        time_end=incident.time_end.strftime("%Y-%m-%d %H:%M:%S"),
        alert_count=incident.alert_count,
        primary_source_ip=incident.primary_source_ip,
        primary_dest_ip=incident.primary_dest_ip,
        involved_assets=", ".join(sorted(incident.involved_assets)),
        max_severity=incident.max_severity,
        reasoning=classification.get("reasoning", "No reasoning provided"),
        mitre_techniques=mitre_text,
        alert_details=alert_details,
    )

    # Call the LLM
    bluf_text = llm_client.generate(prompt)

    # If the LLM wrapped it in markdown code fences, strip them
    bluf_text = bluf_text.strip()
    if bluf_text.startswith("```"):
        lines = bluf_text.split("\n")
        # Remove first and last lines (code fences)
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        bluf_text = "\n".join(lines).strip()

    return bluf_text
