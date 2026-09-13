# Problem Statement

## Background

In defence and cybersecurity operations, Security Operations Centres (SOCs) are responsible for monitoring an organisation's digital infrastructure around the clock. Analysts receive alerts from multiple sources — SIEM systems (Splunk, QRadar), intrusion detection systems (Snort, Suricata), firewalls, email gateways, endpoint detection agents, satellite feeds, and threat intelligence platforms.

A mid-size defence organisation typically processes **thousands of security alerts per day**, each in a different format, with varying severity levels and context.

## The Problem

Defence analysts face an impossible signal-to-noise ratio: **over 90% of security alerts are false positives or low-priority noise**, but the remaining genuine threats — if missed — can result in data breaches, infrastructure compromise, or national security incidents. The consequences of a missed threat are catastrophic; the cost of chasing false positives wastes limited analyst resources.

Current workflows require analysts to:
1. Manually review alerts from 5-10 different source systems
2. Mentally correlate related alerts (e.g., "is this SSH brute force from the same attacker as that port scan?")
3. Classify each alert cluster as genuine or benign
4. Map threats to known attack frameworks (MITRE ATT&CK)
5. Write intelligence summaries for decision-makers

This manual process takes **45-90 minutes per incident** and is error-prone due to alert fatigue — analysts become desensitised after reviewing hundreds of similar-looking alerts.

## Who is Affected

- **SOC Analysts** — overwhelmed by alert volume, spending most of their time on false positives instead of investigating genuine threats.
- **Defence Decision-Makers** (commanders, CISOs) — receive intelligence summaries too slowly to act on emerging threats. Need the picture in seconds, not hours.
- **Incident Responders** — delayed by the gap between alert and triage, losing valuable time in the "golden hour" after a breach.

## Why It Matters

- **National Security Risk:** A missed alert about a credential compromise or data exfiltration on a defence network could lead to loss of classified information.
- **Resource Waste:** An estimated 67% of SOC analyst time is spent on false positives (Ponemon Institute, 2023).
- **Decision Latency:** If a BLUF summary takes 2 hours to produce instead of 2 minutes, the attacker has already moved laterally across the network.

## Why Existing Solutions Fall Short

- **Traditional SIEM correlation rules** catch known patterns but can't reason about novel attack chains or distinguish clever attacks from benign anomalies.
- **Machine learning models** require extensive labelled training data, which defence organisations rarely have (attacks are rare events).
- **Manual analyst triage** doesn't scale — you can't hire enough analysts to review every alert within minutes.
- **No existing tool** combines multi-source ingestion, intelligent correlation, LLM-based reasoning, MITRE ATT&CK mapping, and BLUF-format output in a single pipeline accessible to a junior analyst.
