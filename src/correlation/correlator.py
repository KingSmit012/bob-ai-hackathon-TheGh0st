"""
correlation/correlator.py — Group related alerts into candidate incidents.

This is the CORE correlation engine. It takes a flat list of normalised
alerts and groups them into "incidents" — clusters of alerts that are
likely about the same attack or event.

HOW IT WORKS (rule-based, no ML):

  1. Build an IP-pair index: group alerts by (source_ip, dest_ip) pair
  2. Within each IP-pair group, merge alerts that fall within a time
     window (default: 30 minutes)
  3. Then do a SECOND pass: merge any incidents that share a destination
     IP/asset within the same time window (because an attacker might use
     multiple source IPs against the same target)
  4. Finally, merge incidents that share a source IP within a time window
     (same attacker hitting multiple targets = one campaign)

The result is a list of Incident objects, each containing the alerts
that were grouped together.

WHY RULE-BASED?  For a hackathon with synthetic data, simple rules are:
  - Easy to understand and debug
  - Deterministic (same input = same output every time)
  - Fast (no training needed)
  - Good enough for the demo
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple
from collections import defaultdict

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.ingest import Alert
from config import CORRELATION_TIME_WINDOW_MINUTES


@dataclass
class Incident:
    """
    A correlated incident — a group of related alerts.

    Fields:
        incident_id:     Unique ID (e.g. "INC-001")
        alerts:          List of Alert objects in this incident
        time_start:      Timestamp of the earliest alert
        time_end:        Timestamp of the latest alert
        involved_ips:    Set of all source and dest IPs
        involved_assets: Set of all asset names
        max_severity:    Highest severity level among the alerts
        alert_count:     Number of alerts in this incident
        alert_types:     Set of distinct alert types
        primary_source_ip:  Most common source IP (likely the attacker)
        primary_dest_ip:    Most common dest IP (likely the target)
    """
    incident_id: str
    alerts: List[Alert] = field(default_factory=list)
    time_start: datetime = None
    time_end: datetime = None
    involved_ips: Set[str] = field(default_factory=set)
    involved_assets: Set[str] = field(default_factory=set)
    max_severity: str = "low"
    alert_count: int = 0
    alert_types: Set[str] = field(default_factory=set)
    primary_source_ip: str = ""
    primary_dest_ip: str = ""


# Severity ordering so we can find the "max" severity
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(sev1: str, sev2: str) -> str:
    """Return whichever severity is higher."""
    if SEVERITY_ORDER.get(sev1, 0) >= SEVERITY_ORDER.get(sev2, 0):
        return sev1
    return sev2


def _most_common(items: List[str]) -> str:
    """Return the most frequently occurring item in a list."""
    if not items:
        return ""
    counts: Dict[str, int] = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    return max(counts, key=counts.get)


def _build_incident(incident_id: str, alerts: List[Alert]) -> Incident:
    """
    Build a fully-populated Incident object from a list of alerts.
    """
    alerts_sorted = sorted(alerts, key=lambda a: a.timestamp)

    involved_ips = set()
    involved_assets = set()
    max_sev = "low"
    alert_types = set()
    source_ips = []
    dest_ips = []

    for a in alerts_sorted:
        involved_ips.add(a.source_ip)
        involved_ips.add(a.dest_ip)
        involved_assets.add(a.asset_name)
        max_sev = _max_severity(max_sev, a.severity_reported)
        alert_types.add(a.alert_type)
        source_ips.append(a.source_ip)
        dest_ips.append(a.dest_ip)

    return Incident(
        incident_id=incident_id,
        alerts=alerts_sorted,
        time_start=alerts_sorted[0].timestamp,
        time_end=alerts_sorted[-1].timestamp,
        involved_ips=involved_ips,
        involved_assets=involved_assets,
        max_severity=max_sev,
        alert_count=len(alerts_sorted),
        alert_types=alert_types,
        primary_source_ip=_most_common(source_ips),
        primary_dest_ip=_most_common(dest_ips),
    )


def _alerts_overlap_in_time(
    group_a: List[Alert], group_b: List[Alert], window_minutes: int
) -> bool:
    """
    Check whether two groups of alerts are close enough in time to merge.

    Returns True if the time gap between the latest alert in one group
    and the earliest alert in the other group is within the window.
    """
    window = timedelta(minutes=window_minutes)

    # Find time boundaries for each group
    start_a = min(a.timestamp for a in group_a)
    end_a = max(a.timestamp for a in group_a)
    start_b = min(a.timestamp for a in group_b)
    end_b = max(a.timestamp for a in group_b)

    # Groups overlap if one starts before the other ends (plus window)
    return (start_a <= end_b + window) and (start_b <= end_a + window)


def _has_high_severity(alerts: List[Alert]) -> bool:
    """Check if any alert in the group is high or critical severity."""
    return any(
        a.severity_reported in ("high", "critical")
        for a in alerts
    )


def correlate_alerts(
    alerts: List[Alert],
    time_window_minutes: int = None,
) -> List[Incident]:
    """
    Main correlation function. Takes a flat list of alerts and returns
    a list of Incident objects.

    Algorithm:
      Pass 1 — Group by (source_ip, dest_ip) pair, then split by time window
      Pass 2 — Merge groups sharing the same source_ip AND overlapping time
               (same attacker hitting multiple targets = one campaign)
      Pass 3 — Merge groups sharing dest_ip IF they also share a source_ip
               OR both have high/critical alerts (avoids scanner over-merging)

    Args:
        alerts:              List of normalised Alert objects (from ingest.py)
        time_window_minutes: Override the default time window from config

    Returns:
        List of Incident objects, sorted by time_start (earliest first)
    """
    if time_window_minutes is None:
        time_window_minutes = CORRELATION_TIME_WINDOW_MINUTES

    if not alerts:
        return []

    # ─── PASS 1: Group by (source_ip, dest_ip) pair ─────────────────────
    # This catches alerts from the same attacker to the same target.
    ip_pair_groups: Dict[Tuple[str, str], List[Alert]] = defaultdict(list)
    for alert in alerts:
        key = (alert.source_ip, alert.dest_ip)
        ip_pair_groups[key].append(alert)

    # Within each IP-pair group, split into sub-groups by time window.
    # If there's a gap > time_window between consecutive alerts in the
    # same IP-pair group, they become separate sub-groups.
    time_groups: List[List[Alert]] = []

    for (src, dst), group_alerts in ip_pair_groups.items():
        # Sort by timestamp
        sorted_alerts = sorted(group_alerts, key=lambda a: a.timestamp)
        window = timedelta(minutes=time_window_minutes)

        current_group = [sorted_alerts[0]]
        for alert in sorted_alerts[1:]:
            # If this alert is within the time window of the last alert
            # in the current group, add it to the same group
            if alert.timestamp - current_group[-1].timestamp <= window:
                current_group.append(alert)
            else:
                # Start a new group
                time_groups.append(current_group)
                current_group = [alert]
        time_groups.append(current_group)

    # ─── PASS 2: Merge groups sharing the same source_ip ────────────────
    # Same attacker hitting multiple targets = one campaign.
    # This is done BEFORE dest-IP merging to build attack chains first.
    merged = True
    while merged:
        merged = False
        new_groups = []
        used = set()

        for i in range(len(time_groups)):
            if i in used:
                continue
            current = list(time_groups[i])
            current_src_ips = {a.source_ip for a in current}

            for j in range(i + 1, len(time_groups)):
                if j in used:
                    continue
                other = time_groups[j]
                other_src_ips = {a.source_ip for a in other}

                # Merge if same source IP and overlapping time
                if (current_src_ips & other_src_ips and
                        _alerts_overlap_in_time(current, other, time_window_minutes)):
                    current.extend(other)
                    current_src_ips.update(other_src_ips)
                    used.add(j)
                    merged = True

            new_groups.append(current)
            used.add(i)

        time_groups = new_groups

    # ─── PASS 3: Merge groups sharing dest_ip (conservative) ────────────
    # Only merge if BOTH groups have at least one alert with severity
    # high or critical AND they share a dest IP. This prevents the
    # vulnerability scanner (all low-severity) from chaining groups.
    # Also merge if they share both a source IP AND a dest IP.
    merged = True
    while merged:
        merged = False
        new_groups = []
        used = set()

        for i in range(len(time_groups)):
            if i in used:
                continue
            current = list(time_groups[i])
            current_dest_ips = {a.dest_ip for a in current}
            current_src_ips = {a.source_ip for a in current}

            for j in range(i + 1, len(time_groups)):
                if j in used:
                    continue
                other = time_groups[j]
                other_dest_ips = {a.dest_ip for a in other}
                other_src_ips = {a.source_ip for a in other}

                # Must share a dest IP and be in time window
                if not (current_dest_ips & other_dest_ips and
                        _alerts_overlap_in_time(current, other, time_window_minutes)):
                    continue

                # Merge if they ALSO share a source IP (same campaign)
                shares_source = bool(current_src_ips & other_src_ips)
                # Or merge if both contain high/critical alerts on same target
                both_high = _has_high_severity(current) and _has_high_severity(other)

                if shares_source or both_high:
                    current.extend(other)
                    current_dest_ips.update(other_dest_ips)
                    current_src_ips.update(other_src_ips)
                    used.add(j)
                    merged = True

            new_groups.append(current)
            used.add(i)

        time_groups = new_groups

    # ─── Build Incident objects ──────────────────────────────────────────
    incidents = []
    for idx, group_alerts in enumerate(time_groups, start=1):
        incident = _build_incident(f"INC-{idx:03d}", group_alerts)
        incidents.append(incident)

    # Sort incidents by start time
    incidents.sort(key=lambda inc: inc.time_start)

    # Re-number after sorting
    for idx, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{idx:03d}"

    print(f"Correlated {len(alerts)} alerts into {len(incidents)} incidents")
    return incidents
