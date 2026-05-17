# Cyber News Daily Brief

A simple Streamlit app for reviewing high-signal cybersecurity news quickly.

The app collects trusted cyber RSS feeds, enriches CVEs with NVD and CISA KEV context, scores each item by exploitation reality and signal strength, then presents a clean daily brief backed by Supabase.

## What It Does

- Collects cyber news from BleepingComputer, Krebs, Schneier, The Hacker News, and Dark Reading.
- Detects CVEs and checks NVD metadata, CVSS score, and CISA KEV status.
- Classifies exploitation status as actively exploited, PoC available, theoretical, or unknown.
- Generates a rule-based analyst take for each item.
- Sorts newest first and filters by signal, exploitation status, source confidence, review state, and time range.
- Supports simple review actions: mark reviewed, bookmark, follow up, and read article.

## What It Does Not Do

- No knowledge graph.
- No topic pages.
- No semantic search or embeddings.
- No PWA/offline app layer.
- No SIEM exports or detection-rule generation.
- No personal expertise tracking.

The goal is a fast, calm daily brief rather than a full threat-intelligence platform.

## Project Structure

```text
Cyber-News-App/
├── app_mdr.py                 # Streamlit Daily Brief UI
├── collector_mdr.py           # RSS collector and Supabase writer
├── mdr_intelligence.py        # Event normalization and signal scoring
├── attack_mapping.py          # MITRE ATT&CK and Kill Chain mapping
├── date_utils.py              # Feed date parsing and IST display helpers
├── schema.sql                 # Supabase table schema
├── requirements.txt           # Python dependencies
├── .env.example               # Local environment template
└── .github/workflows/
    └── daily_brief.yml        # 4x daily scheduled collection
```

## Setup

1. Create a Supabase project.
2. Open the Supabase SQL editor and run `schema.sql`.
3. Create a local `.env` file:

```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your_supabase_anon_key_here
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Collect news:

```bash
python collector_mdr.py
```

6. Run the app:

```bash
streamlit run app_mdr.py
```

## GitHub Actions

The single workflow at `.github/workflows/daily_brief.yml` runs the collector four times daily:

```text
06:00, 12:00, 18:00, and 23:00 UTC
```

Add these repository secrets:

- `SUPABASE_URL`
- `SUPABASE_KEY`

## Configuration

Required:

- `SUPABASE_URL`
- `SUPABASE_KEY`

Optional:

- `MAX_ITEMS_PER_SOURCE`, default `15`
- `NVD_DELAY_SECONDS`, default `2`

## Daily Workflow

1. Run the collector automatically or manually.
2. Open the Streamlit app.
3. Review High and Medium signal items first.
4. Mark read items as reviewed.
5. Bookmark or flag follow-up items only when they need later attention.

## Design Principle

If it does not help answer "what matters in cyber news today?", it does not belong in this app.
