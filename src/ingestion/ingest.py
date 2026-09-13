"""
ingestion/ingest.py — Load and normalise raw security alerts.

This module reads alerts from a JSON file and converts them into a
consistent internal format (Python dataclasses). It handles:

  1. Loading from JSON (or CSV in the future)
  2. Normalising fields: lowercase IPs, parse timestamps, standardise
     severity levels
  3. Returning a list of Alert objects that downstream modules can work with

DESIGN DECISION: We use Python dataclasses (not dictionaries) so that
every part of the codebase agrees on what fields an alert has. If a
field is missing from the raw data, we fill in a sensible default.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Alert:
    """
    One normalised security alert.

    Fields:
        alert_id:           Unique identifier (e.g. "ALERT-0001")
        timestamp:          When the alert fired (as a datetime object)
        source:             Which system generated it (SIEM, IDS, Firewall, etc.)
        source_ip:          Origin IP address (attacker or internal host)
        dest_ip:            Destination IP address (target)
        dest_port:          Destination port number
        alert_type:         Category of alert (e.g. "ssh_failed_login")
        severity_reported:  Severity as reported by the source (low/medium/high/critical)
        asset_name:         Name of the targeted asset (e.g. "WEB-SERVER-01")
        raw_message:        Full text of the original alert message
    """
    alert_id: str
    timestamp: datetime
    source: str
    source_ip: str
    dest_ip: str
    dest_port: int
    alert_type: str
    severity_reported: str
    asset_name: str
    raw_message: str


def _normalise_severity(severity: str) -> str:
    """
    Standardise severity strings to one of: low, medium, high, critical.

    Different alert sources might use different labels (e.g. "HIGH",
    "High", "3", "warning"). This function maps them all to our
    four-level scale.
    """
    severity_lower = severity.strip().lower()

    # Direct matches
    if severity_lower in ("low", "informational", "info", "1"):
        return "low"
    elif severity_lower in ("medium", "moderate", "warning", "2"):
        return "medium"
    elif severity_lower in ("high", "3"):
        return "high"
    elif severity_lower in ("critical", "severe", "emergency", "4"):
        return "critical"
    else:
        # If we don't recognise it, default to medium (safer than ignoring)
        return "medium"


def _parse_timestamp(ts_string: str) -> datetime:
    """
    Parse a timestamp string into a Python datetime object.

    We try several common formats since alerts come from different sources
    that might use different timestamp formats.
    """
    # Try ISO 8601 first (most common in our synthetic data)
    formats = [
        "%Y-%m-%dT%H:%M:%S",        # 2025-09-12T08:05:42
        "%Y-%m-%dT%H:%M:%S.%f",     # 2025-09-12T08:05:42.123456
        "%Y-%m-%d %H:%M:%S",        # 2025-09-12 08:05:42
        "%Y/%m/%d %H:%M:%S",        # 2025/09/12 08:05:42
        "%d/%m/%Y %H:%M:%S",        # 12/09/2025 08:05:42
    ]

    for fmt in formats:
        try:
            return datetime.strptime(ts_string, fmt)
        except ValueError:
            continue

    # Last resort: try Python's built-in parser
    try:
        return datetime.fromisoformat(ts_string)
    except (ValueError, TypeError):
        # If nothing works, use current time (shouldn't happen with our data)
        print(f"WARNING: Could not parse timestamp '{ts_string}', using current time")
        return datetime.now()


def load_alerts_from_json(filepath: str) -> List[Alert]:
    """
    Load alerts from a JSON file and return normalised Alert objects.

    Args:
        filepath: Path to the JSON file containing raw alerts.
                  Expected format: a JSON array of objects, each with
                  the fields listed in the Alert dataclass.

    Returns:
        List of Alert objects, sorted by timestamp (earliest first).
    """
    with open(filepath, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)

    alerts = []
    for raw in raw_alerts:
        alert = Alert(
            alert_id=raw.get("alert_id", "UNKNOWN"),
            timestamp=_parse_timestamp(raw.get("timestamp", "")),
            source=raw.get("source", "Unknown"),
            # Normalise IPs to lowercase (IPv6 can have mixed case)
            source_ip=raw.get("source_ip", "0.0.0.0").lower().strip(),
            dest_ip=raw.get("dest_ip", "0.0.0.0").lower().strip(),
            dest_port=int(raw.get("dest_port", 0)),
            alert_type=raw.get("alert_type", "unknown"),
            severity_reported=_normalise_severity(
                raw.get("severity_reported", "medium")
            ),
            asset_name=raw.get("asset_name", "UNKNOWN"),
            raw_message=raw.get("raw_message", ""),
        )
        alerts.append(alert)

    # Sort by timestamp so correlation can use time windows
    alerts.sort(key=lambda a: a.timestamp)

    print(f"Loaded {len(alerts)} alerts from {filepath}")
    return alerts
