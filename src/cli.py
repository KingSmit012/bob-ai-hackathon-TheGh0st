"""
cli.py — Command-line interface for the Threat Intel Correlation Assistant.

This is the main entry point. It wires together all the modules:

    Alert File ─> Ingest ─> Correlate ─> Classify ─> MITRE Map ─> BLUF ─> Rank ─> Report

Usage:
    python cli.py --input data/synthetic_alerts.json
    python cli.py --input data/synthetic_alerts.json --output report.md
    python cli.py --input data/synthetic_alerts.json --format json --output report.json

If no --output is given, the report is printed to stdout.
"""

import click
import json
import os
import sys
from datetime import datetime

# Make sure we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import SYNTHETIC_ALERTS_FILE
from ingestion.ingest import load_alerts_from_json
from correlation.correlator import correlate_alerts
from classification.classifier import classify_incident
from mitre_mapping.mapper import map_to_mitre
from bluf.generator import generate_bluf
from prioritisation.ranker import rank_incidents
from llm.llm_client import get_llm_client


def _format_markdown_report(
    ranked_incidents, classifications, mitre_mappings, bluf_summaries
) -> str:
    """
    Build a full Markdown report from all the processed data.

    This is the final output that a decision-maker would read.
    """
    lines = []
    lines.append("# Threat Intelligence Correlation Report")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Total Incidents:** {len(ranked_incidents)}")

    # Count genuine threats vs false positives
    genuine = sum(
        1 for inc, _ in ranked_incidents
        if classifications.get(inc.incident_id, {}).get("classification") == "genuine_threat"
    )
    false_pos = len(ranked_incidents) - genuine
    lines.append(f"**Genuine Threats:** {genuine}")
    lines.append(f"**False Positives:** {false_pos}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    if genuine > 0:
        lines.append(f"> **{genuine} genuine threat(s) detected** requiring immediate attention. "
                     f"{false_pos} incidents classified as false positives.")
    else:
        lines.append("> No genuine threats detected. All incidents classified as false positives.")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Each incident, ranked by priority
    for rank, (incident, score) in enumerate(ranked_incidents, start=1):
        inc_id = incident.incident_id
        cls = classifications.get(inc_id, {})
        mitre = mitre_mappings.get(inc_id, [])
        bluf = bluf_summaries.get(inc_id, "No BLUF generated")

        # Header with priority badge
        classification_label = cls.get("classification", "unknown").replace("_", " ").title()
        confidence = cls.get("confidence", 0)

        if classification_label == "Genuine Threat":
            badge = "🔴 GENUINE THREAT"
        else:
            badge = "🟢 FALSE POSITIVE"

        lines.append(f"## #{rank} — {inc_id} [{badge}]")
        lines.append("")
        lines.append(f"**Priority Score:** {score:.4f} | "
                     f"**Classification:** {classification_label} | "
                     f"**Confidence:** {confidence}% | "
                     f"**Severity:** {incident.max_severity.upper()}")
        lines.append("")

        # Incident metadata
        lines.append(f"**Time Range:** {incident.time_start.strftime('%H:%M:%S')} - "
                     f"{incident.time_end.strftime('%H:%M:%S')} | "
                     f"**Alerts:** {incident.alert_count} | "
                     f"**Assets:** {', '.join(sorted(incident.involved_assets))}")
        lines.append(f"**Source IP:** {incident.primary_source_ip} | "
                     f"**Target IP:** {incident.primary_dest_ip}")
        lines.append("")

        # BLUF Summary
        lines.append("### BLUF Summary")
        lines.append("")
        lines.append(bluf)
        lines.append("")

        # MITRE ATT&CK Techniques
        if mitre:
            lines.append("### MITRE ATT&CK Mapping")
            lines.append("")
            lines.append("| Technique ID | Name | Tactic | Relevance |")
            lines.append("|---|---|---|---|")
            for t in mitre:
                lines.append(f"| {t['technique_id']} | {t['name']} | "
                            f"{t['tactic']} | {t.get('relevance', '')} |")
            lines.append("")

        # Classification reasoning
        lines.append(f"**Analyst Reasoning:** {cls.get('reasoning', 'N/A')}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _format_json_report(
    ranked_incidents, classifications, mitre_mappings, bluf_summaries
) -> str:
    """Build a JSON report from all the processed data."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_incidents": len(ranked_incidents),
        "incidents": []
    }

    for rank, (incident, score) in enumerate(ranked_incidents, start=1):
        inc_id = incident.incident_id
        cls = classifications.get(inc_id, {})
        mitre = mitre_mappings.get(inc_id, [])
        bluf = bluf_summaries.get(inc_id, "")

        report["incidents"].append({
            "rank": rank,
            "incident_id": inc_id,
            "priority_score": score,
            "classification": cls.get("classification", "unknown"),
            "confidence": cls.get("confidence", 0),
            "reasoning": cls.get("reasoning", ""),
            "max_severity": incident.max_severity,
            "alert_count": incident.alert_count,
            "time_start": incident.time_start.isoformat(),
            "time_end": incident.time_end.isoformat(),
            "primary_source_ip": incident.primary_source_ip,
            "primary_dest_ip": incident.primary_dest_ip,
            "involved_assets": sorted(list(incident.involved_assets)),
            "alert_types": sorted(list(incident.alert_types)),
            "mitre_techniques": mitre,
            "bluf_summary": bluf,
        })

    return json.dumps(report, indent=2)


@click.command()
@click.option(
    "--input", "input_file",
    default=None,
    help="Path to alert JSON file. Defaults to data/synthetic_alerts.json"
)
@click.option(
    "--output", "output_file",
    default=None,
    help="Output file path. If not given, prints to stdout."
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    help="Output format: markdown (default) or json"
)
def main(input_file, output_file, output_format):
    """
    Threat Intel Correlation & Alert Prioritisation Assistant.

    Ingests security alerts, correlates them into incidents, classifies
    each as genuine threat or false positive using an LLM, maps to
    MITRE ATT&CK, and generates ranked BLUF summaries.
    """
    print("=" * 60)
    print("  THREAT INTEL CORRELATION ASSISTANT")
    print("=" * 60)
    print()

    # ── Step 1: Ingest alerts ──
    if input_file is None:
        input_file = SYNTHETIC_ALERTS_FILE
    print(f"[1/6] Ingesting alerts from: {input_file}")
    alerts = load_alerts_from_json(input_file)
    print()

    # ── Step 2: Correlate into incidents ──
    print(f"[2/6] Correlating {len(alerts)} alerts into incidents...")
    incidents = correlate_alerts(alerts)
    print()

    # ── Step 3: Initialise LLM client ──
    print("[3/6] Initialising LLM client...")
    try:
        llm_client = get_llm_client()
    except (ValueError, ImportError) as e:
        print(f"ERROR: {e}")
        print("Set LLM_PROVIDER, and the corresponding API key in .env")
        sys.exit(1)
    print()

    # ── Step 4: Classify each incident ──
    print(f"[4/6] Classifying {len(incidents)} incidents...")
    classifications = {}
    for incident in incidents:
        result = classify_incident(incident, llm_client)
        classifications[incident.incident_id] = result
    print()

    # ── Step 5: Map to MITRE ATT&CK + Generate BLUF ──
    print(f"[5/6] MITRE mapping + BLUF generation...")
    mitre_mappings = {}
    bluf_summaries = {}
    for incident in incidents:
        cls = classifications[incident.incident_id]

        # Map to MITRE (for all incidents, not just genuine — FPs get mapped too
        # so the analyst can see what the alerts *looked like*)
        mitre = map_to_mitre(incident, llm_client)
        mitre_mappings[incident.incident_id] = mitre

        # Generate BLUF summary
        bluf = generate_bluf(incident, cls, mitre, llm_client)
        bluf_summaries[incident.incident_id] = bluf
    print()

    # ── Step 6: Rank and output ──
    print(f"[6/6] Ranking incidents by priority...")
    ranked = rank_incidents(incidents, classifications)
    print()

    # Build the report
    if output_format == "json":
        report = _format_json_report(ranked, classifications, mitre_mappings, bluf_summaries)
    else:
        report = _format_markdown_report(ranked, classifications, mitre_mappings, bluf_summaries)

    # Output
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to: {output_file}")
    else:
        print()
        print(report)

    print()
    print("=" * 60)
    print("  DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()
