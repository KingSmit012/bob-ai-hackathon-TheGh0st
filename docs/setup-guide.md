# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- [x] Python 3.10+ (tested on 3.11, 3.12)
- [x] pip (Python package manager)
- [x] An IBM Cloud account with watsonx.ai access (for LLM features)
- [ ] Alternatively: an Anthropic API key (works as a fallback LLM provider)

## Environment Variables

Copy `.env.example` to `.env` and fill in the values:

```bash
cd src
cp .env.example .env
# Edit .env with your actual API keys
```

| Variable | Description | Required |
|---|---|---|
| `LLM_PROVIDER` | Which LLM to use: `watsonx` (default) or `anthropic` | Yes |
| `WATSONX_API_KEY` | Your IBM Cloud API key | Yes (if using watsonx) |
| `WATSONX_PROJECT_ID` | Your watsonx.ai project ID | Yes (if using watsonx) |
| `WATSONX_URL` | watsonx.ai endpoint URL | No (defaults to us-south) |
| `WATSONX_MODEL_ID` | Model to use on watsonx | No (defaults to granite-13b) |
| `ANTHROPIC_API_KEY` | Your Anthropic API key | Yes (if using anthropic) |
| `CORRELATION_TIME_WINDOW_MINUTES` | Time window for alert correlation | No (defaults to 30) |

### Getting Your watsonx.ai Credentials

1. Go to [IBM Cloud](https://cloud.ibm.com) and log in
2. Navigate to **watsonx.ai** → **Projects**
3. Create or open a project
4. Copy the **Project ID** from the project settings
5. Generate an **API Key** from **Manage** → **Access (IAM)** → **API keys**

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/bob-ai-hackathon-TheGh0st.git
cd bob-ai-hackathon-TheGh0st

# 2. (Recommended) Create a virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
cd src
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your actual API keys (see table above)

# 5. Generate the synthetic alert dataset (if not already present)
python generate_synthetic_alerts.py
```

## Running the Application

### Option 1: CLI (Command Line)

```bash
# Basic run — processes sample alerts, prints report to terminal
cd src
python cli.py

# Save report to a Markdown file
python cli.py --output report.md

# Specify a custom alert file
python cli.py --input data/synthetic_alerts.json --output report.md

# JSON output format
python cli.py --input data/synthetic_alerts.json --format json --output report.json
```

### Option 2: Streamlit Dashboard (Web UI)

```bash
cd src
streamlit run ui/app.py
```

The dashboard will open at: `http://localhost:8501`

**Dashboard features:**
- **Tab 1 — Alert Feed:** Browse all raw alerts with filters for source, severity, and type
- **Tab 2 — Correlated Incidents:** See how alerts were grouped into incidents
- **Tab 3 — BLUF Reports:** Enable "Run LLM Analysis" in the sidebar and click "Analyse Alerts" to generate classified, MITRE-mapped, ranked intelligence summaries

## Verifying It Works

### Quick Smoke Test (no LLM required)

```bash
cd src
python -c "
from ingestion.ingest import load_alerts_from_json
from correlation.correlator import correlate_alerts
alerts = load_alerts_from_json('data/synthetic_alerts.json')
incidents = correlate_alerts(alerts)
for inc in incidents:
    print(f'{inc.incident_id}: {inc.alert_count} alerts, severity={inc.max_severity}, assets={inc.involved_assets}')
"
```

This should print a list of correlated incidents without needing any API keys.

### Full Pipeline Test (requires LLM API key)

```bash
cd src
python cli.py --input data/synthetic_alerts.json --output report.md
```

Check `report.md` for the full BLUF intelligence report.

## Running Tests

```bash
cd src
python -m pytest tests/ -v
```

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'dotenv'` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'ibm_watsonx_ai'` | Run `pip install ibm-watsonx-ai` |
| `ValueError: WATSONX_API_KEY not set` | Copy `.env.example` to `.env` and add your API key |
| `watsonx.ai 401 Unauthorized` | Check your `WATSONX_API_KEY` is valid and not expired |
| `watsonx.ai 403 Forbidden` | Check your `WATSONX_PROJECT_ID` is correct |
| `LLM response could not be parsed` | The model may be returning unexpected format. Try a different model ID. |
| Streamlit won't start | Ensure you're running from the `src/` directory: `streamlit run ui/app.py` |
| Unicode errors on Windows | Run: `set PYTHONIOENCODING=utf-8` before running scripts |
