# 🛡️ Threat Intel Correlation & Alert Prioritisation Assistant

> **Bob AI Hackathon — Track: AI — Problem D2**

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | TheGh0st |
| **Track** | AI |
| **Team Lead** | Smit — [fill-in-email] |
| **Members** | Smit |

---

## 🎯 Problem Statement

> Defence analysts receive thousands of security alerts daily from SIEM systems, IDS sensors, firewalls, email gateways, and threat intelligence feeds. Over 90% are false positives, but missing a real threat is catastrophic. Manual triage takes 45-90 minutes per incident and doesn't scale.

---

## 💡 Solution

> A Python-based pipeline that ingests multi-source security alerts, correlates them into incidents using rule-based IP/time-window grouping, classifies each as genuine threat or false positive using IBM watsonx.ai (Granite model), maps threats to MITRE ATT&CK techniques, and generates ranked BLUF (Bottom Line Up Front) intelligence summaries — the format defence decision-makers expect.

---

## ✨ Key Features

- **Multi-Source Alert Ingestion:** Normalises alerts from SIEM, IDS, firewalls, email gateways, and threat intel feeds into a unified format.
- **Rule-Based Correlation Engine:** Groups related alerts into incidents using IP pair matching and configurable time windows — deterministic, debuggable, no ML training required.
- **LLM-Powered Classification:** IBM watsonx.ai Granite model acts as an expert SOC analyst to classify incidents as genuine threats or false positives with confidence scores and reasoning.
- **MITRE ATT&CK Mapping:** Hybrid keyword-match + LLM approach maps each incident to relevant ATT&CK techniques with explanations.
- **BLUF Intelligence Summaries:** Generates military-standard briefings (Bottom Line, Supporting Detail, MITRE Mapping, Recommended Actions) for decision-makers.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.10+ |
| **Frameworks** | Streamlit (dashboard), Click (CLI) |
| **IBM Technologies** | IBM watsonx.ai (Granite model via `ibm-watsonx-ai` SDK) |
| **Data** | Pandas, JSON |
| **Other** | Anthropic Claude (fallback LLM), python-dotenv |

---

## 📁 Repository Structure

```
├── src/                  # All source code
│   ├── cli.py            # CLI entry point
│   ├── config.py         # Central configuration
│   ├── data/             # Synthetic alerts, MITRE ATT&CK, asset data
│   ├── ingestion/        # Alert loading + normalisation
│   ├── correlation/      # Rule-based alert correlation
│   ├── llm/              # LLM client abstraction (watsonx + Anthropic)
│   ├── classification/   # Threat vs false-positive classification
│   ├── mitre_mapping/    # MITRE ATT&CK technique mapping
│   ├── bluf/             # BLUF summary generation
│   ├── prioritisation/   # Incident ranking
│   └── ui/               # Streamlit dashboard
├── docs/                 # Documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md   # Includes Mermaid diagram
│   └── setup-guide.md
├── demo/                 # Demo artifacts
│   ├── screenshots/
│   └── demo-video-link.txt
├── presentation/         # Slide deck
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

> **Full details in [`docs/setup-guide.md`](docs/setup-guide.md)**

```bash
# 1. Clone the repo
git clone https://github.com/your-org/bob-ai-hackathon-TheGh0st.git
cd bob-ai-hackathon-TheGh0st

# 2. Install dependencies
cd src
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your watsonx.ai API key + project ID

# 4. Generate synthetic data (if not present)
python generate_synthetic_alerts.py

# 5. Run the CLI
python cli.py --output report.md

# 6. Or launch the Streamlit dashboard
streamlit run ui/app.py
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## ⚠️ Known Limitations

- **Synthetic data only:** Uses generated alerts, not real SOC data. Real-world alerts would have more variation in format.
- **LLM latency:** Each incident requires 3 LLM API calls (classify + MITRE + BLUF). Processing 20+ incidents takes 2-5 minutes depending on API speed.
- **MITRE ATT&CK subset:** Only 30 of 600+ techniques included. Production use would need the full catalogue.
- **No persistent storage:** Results are not saved to a database; each run processes from scratch.
- **Correlation tuning:** Time window and merging heuristics work well for our synthetic data but would need tuning for real-world alert patterns.

---

## 🏅 What We're Most Proud Of

The **LLM integration is genuinely load-bearing** — it's not a wrapper around a rule engine with an LLM bolted on. The watsonx.ai Granite model performs the actual threat/false-positive reasoning, MITRE technique selection, and intelligence summary writing. The prompt engineering is visible and tunable, and the structured JSON output parsing handles real-world LLM output messiness gracefully.

---
