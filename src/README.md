# Source Code — Threat Intel Correlation Assistant

## Structure

```
src/
├── cli.py                       # CLI entry point — run the full pipeline
├── config.py                    # Central configuration (env vars + defaults)
├── generate_synthetic_alerts.py # Script to create the synthetic alert dataset
├── requirements.txt             # Python dependencies
├── .env.example                 # Template for environment variables
│
├── data/                        # Static data files
│   ├── synthetic_alerts.json    # ~150 fake security alerts (5 incidents + noise)
│   ├── mitre_attack.json        # 30 MITRE ATT&CK techniques with keywords
│   └── asset_criticality.json   # 12 network assets with criticality scores
│
├── ingestion/                   # Alert loading + normalisation
│   └── ingest.py                # Load JSON, parse timestamps, normalise severity
│
├── correlation/                 # Rule-based alert correlation
│   └── correlator.py            # 3-pass algorithm: IP pairs → source merge → dest merge
│
├── llm/                         # LLM client abstraction
│   └── llm_client.py            # WatsonxClient + AnthropicClient + factory function
│
├── classification/              # Threat classification via LLM
│   └── classifier.py            # Prompt template + JSON response parsing
│
├── mitre_mapping/               # MITRE ATT&CK mapping
│   └── mapper.py                # Keyword match + LLM refinement (2-stage)
│
├── bluf/                        # BLUF summary generation
│   └── generator.py             # Military-format intelligence briefing via LLM
│
├── prioritisation/              # Incident ranking
│   └── ranker.py                # Weighted priority scoring formula
│
└── ui/                          # Web dashboard
    └── app.py                   # Streamlit app with 3 tabs
```

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your API keys

# Run the CLI
python cli.py --input data/synthetic_alerts.json --output report.md

# Run the Streamlit dashboard
streamlit run ui/app.py
```

## Key Design Decisions

- **Dataclasses** for Alert and Incident types (type safety without ORM complexity)
- **Rule-based correlation** (deterministic, no training data needed)
- **Structured JSON prompts** to LLM (reliable parsing of responses)
- **Two-stage MITRE mapping** (fast keyword filter + smart LLM selection)
- **BLUF format** for output (standard military/intelligence briefing style)
