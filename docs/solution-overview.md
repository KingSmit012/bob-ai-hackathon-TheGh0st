# Solution Overview

## What We Built

The **Threat Intel Correlation & Alert Prioritisation Assistant** is a Python-based pipeline that automates the SOC analyst's triage workflow. It takes thousands of raw security alerts, groups them into related incidents, uses an LLM (IBM watsonx.ai Granite model) to classify each incident as a genuine threat or false positive, maps threats to the MITRE ATT&CK framework, and generates BLUF (Bottom Line Up Front) intelligence summaries — the format defence decision-makers expect.

Instead of an analyst spending 45 minutes per incident, our tool produces a prioritised, actionable briefing in under 2 minutes.

## How It Works

1. **Ingest:** Raw alerts are loaded from a JSON file. Each alert is normalised — timestamps are parsed, severity levels are standardised (low/medium/high/critical), IPs are cleaned.

2. **Correlate:** A rule-based correlation engine groups related alerts into incidents. It uses a 3-pass algorithm: first grouping by (source IP, destination IP) pairs, then merging groups sharing the same target within a time window, then merging groups from the same attacker. No ML needed — just deterministic rules.

3. **Classify:** Each correlated incident is sent to the IBM watsonx.ai LLM (Granite model) with a structured prompt. The LLM acts as an expert SOC analyst, determining whether the incident is a genuine threat (with a confidence score 0-100) or a likely false positive, explaining its reasoning.

4. **Map to MITRE ATT&CK:** A two-stage approach: first, keyword matching against a local MITRE ATT&CK technique database; then, LLM refinement to confirm/select the most relevant techniques for each incident.

5. **Generate BLUF:** The LLM produces a military-style intelligence briefing: one-line bottom line, supporting evidence, MITRE mapping, and recommended actions.

6. **Rank:** Incidents are scored using a weighted formula (severity × 0.35 + confidence × 0.25 + asset criticality × 0.25 + alert density × 0.15). Genuine threats rank above false positives.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed diagram.

```
[Alert JSON] → [Ingest] → [Correlate] → [Classify via LLM] → [MITRE Map] → [BLUF Generate] → [Rank] → [Report]
                                              ↕                     ↕              ↕
                                        [IBM watsonx.ai Granite Model]
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Rule-based correlation (not ML) | Deterministic, debuggable, and doesn't require training data. Sufficient for our alert patterns. |
| IBM watsonx.ai as primary LLM | Hackathon requirement for IBM technology. Granite model provides strong instruction-following for structured analysis tasks. |
| Anthropic Claude as fallback | Allows development/testing without watsonx access. Same interface via abstraction layer. |
| BLUF output format | Standard military/intelligence format that decision-makers are trained to read. Gets the key message across in seconds. |
| Keyword + LLM hybrid for MITRE | Pure keyword matching is too rigid; pure LLM is too slow on full MITRE catalogue. Hybrid gives accuracy and speed. |
| Local MITRE ATT&CK subset (not full API) | Keeps the tool self-contained. 30 techniques covering common attack patterns is sufficient for the demo. |
| Dataclasses for data models | Type safety without complexity. Every module agrees on what an Alert/Incident looks like. |

## IBM Technologies Used

- **IBM watsonx.ai (Granite model):** Used as the core reasoning engine for three critical pipeline steps:
  1. **Threat Classification** — The Granite model receives structured prompts containing incident context and applies SOC analyst reasoning to classify threats vs false positives with confidence scores.
  2. **MITRE ATT&CK Mapping** — The model refines keyword-matched technique candidates, confirming relevance and explaining why each technique applies.
  3. **BLUF Generation** — The model produces military-format intelligence summaries with actionable recommendations.

  The LLM integration is the *load-bearing* component — without it, the tool can only correlate alerts but cannot classify, map, or summarise. The watsonx.ai Python SDK (`ibm-watsonx-ai`) is used to call the `ibm/granite-13b-instruct-v2` model with controlled generation parameters (low temperature for factual consistency).
