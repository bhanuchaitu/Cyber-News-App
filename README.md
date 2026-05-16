# Personal MDR Cyber Threat Intelligence Platform

> **Transform public cybersecurity news into analyst-ready threat intelligence with automated knowledge graph building, entity extraction, and living topic pages**  
> Optimized for speed, signal, and clarity for a single MDR analyst.

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B.svg)](https://streamlit.io/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E.svg)](https://supabase.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📸 Screenshots

### Daily Brief View
![Daily Brief View](public/Daily%20Brief%20View.jpg)

### Topic Pages
![Topic Pages](public/Topic%20Pages.jpg)

### Mobile-Responsive UI
![Mobile-Responsive UI](public/Mobile-Responsive%20UI.jpg)

---

## 🎯 What This Is

A **comprehensive three-phase Personal MDR Threat Intelligence Platform** that:

### Phase 1: Intelligent Feed Processing
- ✅ Converts noisy security news into **structured threat events**
- ✅ Prioritizes by **exploitation reality** (not just CVSS hype)
- ✅ Generates **MDR analyst takes** (1-3 sentence actionable summaries)
- ✅ Calculates **signal strength** to filter noise
- ✅ Maps to **MITRE ATT&CK** and **Cyber Kill Chain**
- ✅ Tracks CVE enrichment via **NVD API** and **CISA KEV**
- ✅ **Delta View** - "What Changed Since Yesterday?" reduces re-reading
- ✅ **Mobile-responsive UI** - Works perfectly on phones and tablets
- ✅ **PWA support** - Install as standalone app on any device
- ✅ **Newest-first sorting** - Most recent intelligence always on top

### Phase 2: Knowledge Graph & Entity Intelligence
- ✅ **Automatic entity extraction** (65+ threat actors, 60+ technologies, 25+ attack types, 20 malware families)
- ✅ **Knowledge graph** with automatic relationship building
- ✅ **IOC extraction & export** (IPs, domains, file hashes, URLs, emails) in CSV/JSON/TXT
- ✅ **SIEM integration templates** (Splunk, Sentinel, QRadar, Elastic)
- ✅ **Advanced filtering** dashboard with time-range and exploitation status

### Phase 3: Living Topic Pages
- ✅ **Dedicated pages for every entity** (threat actors, CVEs, technologies, attack types, malware)
- ✅ **Clickable entities** in Daily Brief - one click to explore any topic
- ✅ **Timeline view** - chronological article history for each entity
- ✅ **Relationship navigation** - discover connections between topics
- ✅ **Personal notes & expertise tracking** - build your knowledge base
- ✅ **Related IOCs** - all indicators associated with each topic

### What This Is NOT
- ❌ SOC/SIEM/XDR tool
- ❌ Detection rule generator
- ❌ Incident response platform
- ❌ Remediation engine
- ❌ Organization-specific security tool

**Core Principle:** If it doesn't answer "What changed in the threat landscape today?" or "What do I know about this entity?", it doesn't belong here.

---

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      RSS Feeds (5 Sources)                               │
│  BleepingComputer │ Krebs │ Schneier │ THN │ Dark Reading              │
└──────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│            Intelligence Collector (collector_mdr.py)                     │
│  • Event Normalization        • Exploitation Status Check               │
│  • CVE Enrichment (NVD)       • CISA KEV Verification                  │
│  • Signal Strength Calc       • Pattern Extraction                      │
│  • MDR Analyst Take Gen       • MITRE ATT&CK Mapping                   │
│  • Entity Extraction          • Knowledge Graph Building               │
└──────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Supabase (PostgreSQL)                               │
│                                                                          │
│  Intelligence Feed (daily_brief)  │  Knowledge Graph (7 tables)        │
│  • Threat events with metadata    │  • Topics (entities)              │
│  • Signal strength scores         │  • Topic relationships            │
│  • Exploitation timeline          │  • IOCs (indicators)              │
│  • CVE enrichment data           │  • User notes & expertise          │
│  • Pattern tags & trends         │  • Article-topic mappings         │
│                                  │  • MITRE ATT&CK techniques         │
└──────────────────────────────┬─────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                Application Layer (Streamlit)                             │
│                                                                          │
│  Daily Brief (app_mdr.py)         │  Knowledge Dashboard               │
│  • Newest-first sorting           │  • Knowledge overview              │
│  • Exploitation priority display  │  • Topic explorer & search         │
│  • Signal filtering (IST timezone)│  • IOC dashboard & export          │
│  • Analyst take display          │                                    │
│  • Clickable entity buttons      │  Topic Pages (topic_page.py)        │
│  • Review workflow               │  • Timeline view (all articles)     │
│                                  │  • Relationship graph              │
│                                  │  • Related IOCs                    │
│                                  │  • Personal notes & expertise      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Modules

#### Phase 1: Intelligence Processing

1. **`mdr_intelligence.py`** (~551 lines) - Intelligence processing engine
   - Event normalization (9 event types)
   - Exploitation status determination
   - Signal strength calculation (High/Medium/Low)
   - MDR analyst take generation
   - Pattern extraction

2. **`attack_mapping.py`** (~172 lines) - Threat framework mapping
   - MITRE ATT&CK tactics (14) & techniques (15)
   - Cyber Kill Chain phases (7)
   - Attack name identification (APT groups, ransomware, malware)

3. **`collector_mdr.py`** (~531 lines) - Intelligence collector
   - RSS feed aggregation (5 sources)
   - CVE enrichment via NVD API
   - CISA KEV verification
   - Knowledge graph processing
   - Automated article ingestion

4. **`date_utils.py`** (~205 lines) - Centralized date handling
   - UTC-to-IST timezone conversion (Indian Standard Time)
   - Feed date parsing with consistency
   - Weaponization speed calculations

#### Phase 2: Knowledge Graph  

5. **`entity_extractor.py`** (~534 lines) - Entity extraction engine
   - **65+ threat actors**: LockBit, ALPHV, APT28, APT29, Lazarus Group, BlackCat, Akira, etc.
   - **60+ technologies**: Microsoft, VMware, Fortinet, Palo Alto, AWS, Azure, Google Cloud, etc.
   - **25+ attack types**: Ransomware, phishing, supply chain, zero-day, DDoS, etc.
   - **20 malware families**: Cobalt Strike, Mimikatz, AgentTesla, RedLine, etc.
   - **CVE extraction** with pattern matching
   - **IOC extraction**: IPs, domains, file hashes, URLs, email addresses

6. **`knowledge_graph.py`** (~508 lines) - Knowledge graph manager
   - Automatic topic creation and updates
   - Relationship building (exploits, targets, affects, uses)
   - Topic search with filters
   - IOC export (CSV, JSON, TXT formats)
   - Statistics and analytics

7. **`knowledge_dashboard.py`** (~357 lines) - Knowledge UI components
   - Knowledge overview with statistics
   - Topic explorer with search
   - Topic details with relationships
   - IOC dashboard with filtering
   - SIEM integration templates (Splunk, Sentinel, QRadar, Elastic)

#### Phase 3: Topic Pages

8. **`topic_page.py`** (~463 lines) - Living topic pages
   - Individual entity pages (threat actors, CVEs, technologies, attack types, malware)
   - Timeline view (chronological article list)
   - Relationship navigation (outgoing/incoming connections)
   - Related IOCs by topic
   - Personal notes editor with expertise tracking (0-100 scale)

9. **`app_mdr.py`** (~832 lines) - Main Streamlit dashboard
   - Daily Brief view with newest-first sorting
   - Knowledge Graph view (Phase 2 dashboard)
   - Topic Page view (Phase 3 entity pages)
   - Advanced filtering (signal, exploitation status, time range, confidence)
   - Clickable entity buttons on every article
   - Review workflow (mark reviewed, bookmark, follow-up)
   - IST timezone support for all dates

---

## 🌟 Key Features

### Daily Brief Intelligence Feed

**Smart Filtering:**
- **View Mode**: All Intelligence / What Changed Since Yesterday? / Unreviewed Only
- **Signal Strength**: High / Medium / Low
- **Exploitation Status**: Actively Exploited / PoC Available / Theoretical / Unknown
- **Time Range**: Today / Last 3 Days / Last 7 Days / Last 30 Days (with proper date bounds)
- **Source Confidence**: High / Medium / Low
- **Show Reviewed**: Toggle reviewed/unreviewed items
- **Default Sort**: Newest first (by published date)

**Intelligent Cards:**
Each article card displays:
- Exploitation status badge (🔴 ACTIVELY EXPLOITED, 🟡 PoC AVAILABLE)
- Signal strength indicator
- Event type chip
- CVE badges with CVSS scores
- CISA KEV warnings
- Attack name (APT groups, ransomware)
- Windows Event Log IDs
- MDR Analyst Take (1-3 sentence summary)
- Evidence & confidence sources
- Meta information (source, target, attack vector, first observed date in IST)
- **Clickable entity buttons** (up to 10 per article)

**Review Workflow:**
- Mark items as reviewed
- Bookmark critical items
- Flag for follow-up
- Add analyst notes
- Read full article

### Knowledge Graph Dashboard (Phase 2)

**Overview Tab:**
- Total topics tracked
- Entity type distribution (threat actors, CVEs, technologies, attack types, malware)
- IOC statistics with type breakdown
- Visual charts and metrics

**Topic Explorer:**
- Search across all topics
- Filter by entity type
- View topic details with click
- See article count and date ranges

**IOC Dashboard:**
- Filter by IOC type (IP, domain, file hash, URL, email)
- Confidence threshold filtering
- Time period selection
- Export formats:
  - **CSV** - Spreadsheet for analysis
  - **JSON** - STIX-friendly format for threat intel platforms
  - **TXT** - Plain text for IOC feeds
- **SIEM Integration Templates**:
  - Splunk SPL queries
  - Microsoft Sentinel KQL queries
  - IBM QRadar AQL queries
  - Elastic Stack queries

### Topic Pages (Phase 3)

**What are Topic Pages?**
Living pages for every entity (threat actor, CVE, technology, attack type, malware) extracted from your intelligence feed.

**How to Access:**
1. Click any entity button below an article in Daily Brief
2. Search for topics in Knowledge Graph → Topic Explorer
3. Navigate between related topics via relationship links

**4 Comprehensive Tabs:**

1. **📊 Timeline Tab**
   - Chronological list of ALL articles mentioning this topic
   - Grouped by month (Feb 2026, Jan 2026, etc.)
   - Full article metadata with IST timestamps
   - Direct links to original sources

2. **🔗 Relationships Tab**
   - **Outgoing**: This topic → Related topics (e.g., CVE-2026-1234 **exploits** Microsoft Exchange)
   - **Incoming**: Related topics → This topic (e.g., LockBit **uses** Cobalt Strike)
   - Relationship types: exploits, targets, affects, uses, related_to
   - Strength scores (0.50 - 1.00)
   - One-click navigation to related topics

3. **🎯 IOCs Tab**
   - All indicators of compromise from articles about this topic
   - Grouped by type (IPs, domains, hashes, URLs, emails)
   - Confidence scores and occurrence counts
   - First seen / last seen dates in IST
   - Export-ready for SIEM ingestion

4. **📝 Notes Tab**
   - **Personal notes editor** - Free-form text for your insights
   - **Expertise tracking** - 0-100 scale with 5 levels:
     - 🌱 Beginner (0-20)
     - 📚 Learning (21-40)
     - ⚙️ Intermediate (41-60)
     - 🎓 Advanced (61-80)
     - 🏆 Expert (81-100)
   - Progress bar visualization
   - Persistent storage per topic

---

## 📋 Event Normalization

Every article is transformed into a **structured threat event**:

### Event Types
- `Vulnerability` - Security flaw disclosed
- `Active Exploit` - Confirmed exploitation in wild
- `Malware` - New malware family/variant
- `Campaign` - Coordinated threat actor activity
- `Cloud Abuse` - Cloud/SaaS platform compromise
- `Supply Chain` - Third-party/dependency attack
- `Research` - Academic/technical analysis
- `Industry News` - General security updates

### Normalized Fields
```python
{
    "event_type": "Active Exploit",
    "primary_target": "VMware vCenter",
    "attack_vector": "RCE",
    "impact_outcome": "Remote Code Execution",
    "exploitation_status": "actively_exploited",
    "signal_strength": "High",
    "mdr_analyst_take": "APT28 actively exploiting VMware vCenter RCE via phishing. CVSS 9.8 critical severity. Notable: zero-day, rapid weaponization (3 days)."
}
```

---

## 🔴 Exploitation Reality Check

### Status Levels

| Status | Meaning | Priority | Action |
|--------|---------|----------|--------|
| 🔴 **actively_exploited** | Confirmed attacks in wild | CRITICAL | Immediate review + follow-up |
| 🟡 **poc_available** | PoC exists, limited abuse | HIGH | Monitor for weaponization |
| 🟢 **theoretical** | Research-only | MEDIUM | Track for later |
| ⚪ **unknown** | Insufficient data | LOW | Awareness |

### Determination Logic
- **CISA KEV** → Automatically `actively_exploited`
- Keywords: "actively exploited", "in the wild" → `actively_exploited`
- Keywords: "PoC", "exploit code" → `poc_available`
- Has CVE → `theoretical`

---

## 🎯 Signal Strength Scoring

### Calculation Formula

**High Signal** (50+ points):
- Active exploitation: **+40 pts**
- CISA KEV listed: **+30 pts**
- Critical CVSS (≥9.0): **+15 pts**
- High-confidence source: **+15 pts**
- Technical details: **+7 pts**

**Medium Signal** (25-49 points):
- PoC available: **+20 pts**
- CVE with severity: **+5-15 pts**
- Medium-confidence source: **+8 pts**

**Low Signal** (<25 points):
- Theoretical vulnerability: **+5 pts**
- Standard reporting

### Source Confidence
- **High**: Vendor advisories, CERT, CISA, Microsoft, Google
- **Medium**: BleepingComputer, Krebs, Dark Reading
- **Low**: Unverified blogs, social media

---

## 💡 MDR Analyst Take

**1-3 sentence summary answering:** *"What should an MDR analyst remember?"*

### Generation Logic
```python
# Lead with exploitation reality
if actively_exploited:
    "APT28 actively exploiting {target}"
elif poc_available:
    "PoC available for {target} {vector}"
    
# Add impact context
if cvss_score >= 9.0:
    "using {vector} (CVSS {score}, critical severity)"
    
# Add strategic flags
if zero_day: "Notable: zero-day"
if supply_chain: "Notable: supply chain risk"
if apt: "Notable: APT-level threat"

# Speed context
if weaponization <= 3 days:
    "Rapid weaponization ({days} days)"
```

### Example Outputs
- *"VMware vCenter RCE actively exploited via phishing. CVSS 9.8 critical. Notable: zero-day, same-day weaponization."*
- *"PoC available for Microsoft Exchange privilege escalation. Notable: supply chain risk, ransomware capable."*
- *"LockBit ransomware targeting healthcare sector. Active exploitation confirmed, CISA KEV listed."*

---

## 📈 Pattern & Trend Detection

### Automatic Pattern Tags
- `oauth_abuse` - OAuth token compromise
- `rtf_exploit` - RTF document exploits
- `api_abuse` - API endpoint exploitation
- `supply_chain` - Dependency attacks
- `phishing_campaign` - Mass phishing
- `zero_day` - Unknown vulnerabilities
- `ransomware` - Encryption attacks
- `credential_theft` - Password stealing

### Trend Analysis
Dashboard sidebar shows:
- **Top recurring techniques** (last 7 days)
- **Emerging patterns** (2+ occurrences)
- **Attack vector trends** (OAuth, RCE, Phishing)

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.12** (recommended; 3.10+ supported)
- **Supabase account** (free tier works perfectly)
- **Git**

### Installation Steps

#### 1. Clone Repository
```bash
git clone <your-repo-url>
cd Cyber-News-App
```

#### 2. Create Virtual Environment
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

**Core dependencies (7 packages):**
- `streamlit==1.40.2` - Dashboard UI
- `supabase==2.10.0` - Database client
- `feedparser==6.0.11` - RSS feed parsing
- `requests==2.32.3` - HTTP requests
- `python-dateutil==2.9.0` - Date parsing
- `python-dotenv==1.0.0` - Environment configuration
- `google-generativeai==0.8.3` - AI capabilities

#### 4. Configure Environment
```bash
cp .env.example .env
```

Edit `.env` with your Supabase credentials:
```ini
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-or-service-role-key
```

**Get Supabase credentials:**
1. Create a free account at https://supabase.com
2. Create new project
3. Go to Project Settings → API
4. Copy URL and anon/public key

#### 5. Deploy Database Schema
1. Open Supabase SQL Editor (dashboard → SQL Editor)
2. Copy contents of `knowledge_schema.sql`
3. Execute the SQL script
4. Verify 7 tables created: `topics`, `topic_relationships`, `iocs`, `user_knowledge`, `attck_techniques`, `article_topics`, `article_attck`

**Note:** The `daily_brief` table will be created automatically by the collector if it doesn't exist.

#### 6. Run Intelligence Collector (First Time)
```bash
python collector_mdr.py
```

**What it does:**
- Fetches from 5 RSS feeds
- Enriches with CVE data (NVD)
- Checks CISA KEV catalog (with 1-hour caching)
- Extracts entities (threat actors, technologies, attack types)
- Builds knowledge graph
- Stores in Supabase

**First run takes:** ~2-3 minutes (fetches historical items)
**Subsequent runs:** ~30-60 seconds

#### 7. Launch Dashboard
```bash
streamlit run app_mdr.py
```

Dashboard opens at: `http://localhost:8501`

**Mobile-Friendly:**
- Works on all devices (phone, tablet, desktop)
- Responsive design adapts to screen size
- Touch-friendly buttons

---

## 🚀 Deploy to Streamlit Cloud (Recommended)

**Benefits:**
- ✅ Access from anywhere (no local server needed)
- ✅ HTTPS enables PWA installation (install as app)
- ✅ Free hosting on Streamlit Community Cloud
- ✅ Automatic updates from GitHub

**Deployment Steps:**

1. **Push to GitHub** (if not already done)
   ```bash
   git init
   git add .
   git commit -m "Deploy MDR Intelligence Platform"
   git remote add origin <your-repo-url>
   git push -u origin main
   ```

2. **Deploy on Streamlit Cloud**
   - Visit: https://streamlit.io/cloud
   - Sign in with GitHub account
   - Click "New app"
   - Select your repository: `Cyber-News-App`
   - **Main file path: `app_mdr.py`**
   - **Python version: 3.12**
   - Click "Deploy"
   - Wait 2-3 minutes for initial deployment

3. **Configure Secrets**
   - In app dashboard → ⚙️ Settings → Secrets
   - Add your environment variables:
     ```toml
     SUPABASE_URL = "https://your-project.supabase.co"
     SUPABASE_KEY = "your-anon-or-service-key"
     ```
   - Click "Save"
   - App will automatically restart

4. **Access Your App**
   - Your live URL: `https://your-app-name.streamlit.app`
   - Share URL with any device
   - Works on mobile browsers

5. **Install as PWA** (Optional)
   - **Android:** Chrome menu (⋮) → "Install app"
   - **iOS:** Safari Share → "Add to Home Screen"
   - **Desktop:** Install icon in browser address bar
   - App appears on home screen/applications menu

**Automatic Updates:**
- Push code changes to GitHub
- Streamlit Cloud auto-deploys within 1-2 minutes
- No manual redeployment needed

> **Note:** Semantic search (pgvector + sentence-transformers) is **not available** on Streamlit Cloud due to torch dependency size constraints. All other features work fully. Semantic search can be used in local deployments by installing `sentence-transformers` separately.

---

## 📖 Usage Guide

### Daily Workflow (5-10 minutes)

#### Morning Intelligence Review

1. **Run Collector** (automated 4x daily via GitHub Actions, or manual)
   ```bash
   python collector_mdr.py
   ```

2. **Open Dashboard**
   ```bash
   streamlit run app_mdr.py
   ```

3. **Filter Intelligence**
   - Set Time Range: "Today" or "Last 3 Days"
   - Signal Strength: High + Medium
   - Exploitation Status: Actively Exploited + PoC Available
   - Uncheck "Show Reviewed Items"

4. **Scan High-Priority Items**
   - Results are sorted newest-first by default
   - Focus on 🔴 **ACTIVELY EXPLOITED** first
   - Read **MDR Analyst Takes** (1-3 sentences)
   - Check CISA KEV warnings
   - Note exploitation velocity indicators

5. **Explore Topics**
   - Click entity buttons below articles
   - Examples: "LockBit", "CVE-2026-1234", "Microsoft Exchange"
   - Navigate to topic pages to see:
     - Full timeline of all articles
     - Related topics and connections
     - All IOCs associated with this entity
     - Add personal notes and track expertise

6. **Mark & Review**
   - ✅ Mark reviewed items
   - ⭐ Bookmark critical threats
   - 📌 Flag for follow-up
   - 📝 Add analyst notes

### Topic Page Workflows

#### Workflow 1: Threat Actor Research

1. **Discovery** - Click entity button in Daily Brief (e.g., "DarkVault")
2. **Timeline Analysis** (Tab 1) - Review all articles mentioning this actor chronologically
3. **Relationship Mapping** (Tab 2) - Discover uses/targets/exploits connections
4. **IOC Collection** (Tab 3) - View and export C2 IPs, file hashes, domains
5. **Documentation** (Tab 4) - Add personal notes and track expertise level

#### Workflow 2: CVE Tracking

1. **Initial Alert** - Click CVE button → Topic page opens
2. **Impact Assessment** - Timeline + relationships reveal affected products and threat actors
3. **IOC Monitoring** - All associated attack indicators
4. **Ongoing Tracking** - Check back as timeline grows with new articles

#### Workflow 3: Knowledge Graph Exploration

1. **Switch View Mode** - Sidebar → "Knowledge Graph"
2. **Overview Tab** - Total topics, entity breakdown, IOC statistics
3. **Topic Explorer** - Search and filter by entity type
4. **IOC Dashboard** - Filter by type/confidence, export in CSV/JSON/TXT, use SIEM templates

---

## 🎨 Dashboard Features

### Intelligence Cards

```
┌─────────────────────────────────────────────────┐
│ 🔴 ACTIVELY EXPLOITED    🎯 High Signal         │
│                                                  │
│ APT28 Weaponizes Microsoft Office Bug...        │
│                                                  │
│ [Active Exploit] [⚡ New PoC Released]          │
│ [🔍 CVE-2025-1234] [⚠️ CISA KEV] [🎯 APT28]   │
│                                                  │
│ 💡 Analyst Take:                                │
│ APT28 actively exploiting Microsoft Office      │
│ via phishing. CVSS 9.8. Notable: zero-day,     │
│ 3-day weaponization.                            │
│                                                  │
│ 📡 BleepingComputer | 🎯 Microsoft Office       │
│ 📍 Phishing | 📅 First: 2026-02-06             │
│ ⚡ 3 day weaponization | 📊 High Confidence     │
│                                                  │
│ 📖 View Full Details ▼                          │
└─────────────────────────────────────────────────┘
```

### Sidebar Filters
- **Signal Strength**: High / Medium / Low
- **Exploitation Status**: Active / PoC / Theoretical / Unknown
- **Event Type**: Vulnerability, Malware, Campaign, etc.
- **Time Range**: Today / 3 Days / 7 Days / 30 Days
- **Source Confidence**: High / Medium / Low

### Review Workflow
- ✅ **Mark Reviewed** - Track processed intelligence
- ⭐ **Bookmark** - Flag for deep analysis
- 🔖 **Follow Up** - Require action items
- 📝 **Add Notes** - Document decisions

---

## 🗄️ Database Schema

### Phase 1: Intelligence Feed Table

**`daily_brief`** - Core intelligence events

```sql
CREATE TABLE daily_brief (
    -- Core fields
    id                      BIGSERIAL PRIMARY KEY,
    source                  TEXT,
    title                   TEXT,
    url                     TEXT UNIQUE,
    summary                 TEXT,
    published_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),
    
    -- Event Normalization
    event_type              TEXT,
    primary_target          TEXT,
    attack_vector           TEXT,
    impact_outcome          TEXT,
    
    -- Exploitation Reality
    first_observed_date     DATE,
    exploitation_status     TEXT,
    weaponization_speed     INT,
    previous_exploitation_status TEXT,
    exploitation_escalated_at TIMESTAMPTZ,
    
    -- Intelligence
    mdr_analyst_take        TEXT,
    technical_method        TEXT,
    delta_reason            TEXT,
    
    -- Signal & Source
    signal_strength         TEXT,
    signal_strength_reason  TEXT,
    signal_upgraded_at      TIMESTAMPTZ,
    previous_signal_strength TEXT,
    source_confidence       TEXT,
    evidence_sources        TEXT[],
    evidence_count          INT,
    
    -- Pattern & Trends
    pattern_tags            TEXT[],
    campaign_id             TEXT,
    story_hash              TEXT,
    threat_velocity         TEXT,
    
    -- CVE Data
    cve_id                  TEXT,
    cvss_score              FLOAT,
    cvss_vector             TEXT,
    cve_published_date      DATE,
    cisa_exploited          BOOLEAN,
    
    -- Attack Frameworks
    attack_name             TEXT,
    mitre_tactics           TEXT[],
    mitre_techniques        TEXT[],
    kill_chain_phases       TEXT[],
    windows_event_id        TEXT,
    windows_event_description TEXT,
    
    -- Analyst Workflow
    reviewed_at             TIMESTAMP,
    analyst_notes           TEXT,
    bookmarked              BOOLEAN DEFAULT FALSE,
    follow_up_required      BOOLEAN DEFAULT FALSE
);
```

### Phase 2 & 3: Knowledge Graph Tables

**7-table knowledge graph schema** — see `knowledge_schema.sql` for full definitions:

1. **`topics`** - Entity master table (threat actors, CVEs, technologies, attack types, malware)
2. **`topic_relationships`** - Entity connections (exploits, targets, affects, uses, related_to)
3. **`iocs`** - Indicators of compromise (IPv4, domain, file hash, URL, email)
4. **`user_knowledge`** - Personal notes and expertise per topic
5. **`article_topics`** - Article-to-topic mappings
6. **`attck_techniques`** - MITRE ATT&CK technique mappings
7. **`article_attck`** - Article-to-ATT&CK mappings

### Performance Indexes

```sql
CREATE INDEX idx_exploitation_status ON daily_brief(exploitation_status) 
WHERE exploitation_status = 'actively_exploited';
CREATE INDEX idx_signal_strength ON daily_brief(signal_strength) 
WHERE signal_strength = 'High';
CREATE INDEX idx_published_at ON daily_brief(published_at DESC);
CREATE INDEX idx_reviewed ON daily_brief(reviewed_at) WHERE reviewed_at IS NULL;
CREATE INDEX idx_pattern_tags ON daily_brief USING GIN(pattern_tags);
CREATE INDEX idx_topics_slug ON topics(slug);
CREATE INDEX idx_topics_type ON topics(type);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_article_topics_article ON article_topics(article_id);
CREATE INDEX idx_article_topics_topic ON article_topics(topic_id);
```

---

## 🛠️ Customization

### Adjust Signal Thresholds

Edit `mdr_intelligence.py`:
```python
# calculate_signal_strength()
if score >= 50:      # Change threshold
    strength = 'High'
elif score >= 25:    # Change threshold
    strength = 'Medium'
```

### Add Custom Pattern Tags

Edit `mdr_intelligence.py`:
```python
# extract_pattern_tags()
patterns = {
    'your_pattern': ['keyword1', 'keyword2'],
    'custom_tag': ['indicator1', 'indicator2'],
}
```

### Add RSS Feeds

Edit `collector_mdr.py`:
```python
# RSS_FEEDS
RSS_FEEDS = {
    'Your Source': 'https://example.com/feed.xml',
}
```

### Customize Entity Extraction

Edit `entity_extractor.py`:
```python
THREAT_ACTORS = {
    'Your New Actor': ['alias1', 'alias2'],
}
TECHNOLOGIES = {
    'Your Technology': ['keyword1', 'keyword2'],
}
```

---

## 🔄 Automation & Scheduling

### GitHub Actions (Automated Collection)

The project includes **two GitHub Actions workflows**:

#### 1. `collect-news.yml` — Primary collector (4x daily)
- **Schedule**: `0 6,12,18,23 * * *` (6 AM, 12 PM, 6 PM, 11 PM UTC)
- Covers EU morning, US morning, US afternoon, and end-of-day disclosures
- Manual dispatch available

#### 2. `.github/workflows/daily_brief.yml` — Legacy daily run
- **Schedule**: `0 1 * * *` (1 AM UTC)
- Runs `collector_mdr.py` with dependencies from `requirements.txt`

**Setup:**
1. Go to your GitHub repository → Settings → Secrets and Variables → Actions
2. Add repository secrets:
   - `SUPABASE_URL` - Your Supabase project URL
   - `SUPABASE_KEY` - Your Supabase anon/public key
3. Commit workflow files to repository
4. Workflow runs automatically (check Actions tab)

### Windows Task Scheduler

```batch
@echo off
cd C:\path\to\Cyber-News-App
call .venv\Scripts\activate.bat
python collector_mdr.py >> collector.log 2>&1
deactivate
```

### Linux Cron Job

```bash
# Runs 4x daily matching GitHub Actions schedule
0 6,12,18,23 * * * cd /home/user/Cyber-News-App && source .venv/bin/activate && python collector_mdr.py >> collector.log 2>&1
```

### Docker Deployment (Optional)

**Dockerfile:**
```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "collector_mdr.py"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  collector:
    build: .
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_KEY=${SUPABASE_KEY}
    restart: always
    command: python collector_mdr.py

  dashboard:
    build: .
    command: streamlit run app_mdr.py --server.port=8501 --server.address=0.0.0.0
    ports:
      - "8501:8501"
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_KEY=${SUPABASE_KEY}
    restart: always
```

---

## 📦 Project Structure

```
Cyber-News-App/
├── .env                         # Environment variables (git-ignored)
├── .env.example                 # Environment template
├── .gitignore                   # Git ignore rules
├── .github/
│   └── workflows/
│       └── daily_brief.yml      # GitHub Actions: daily collector
├── .streamlit/                  # Streamlit configuration
│
├── requirements.txt             # Python dependencies (7 packages)
├── README.md                    # This guide
├── collect-news.yml             # GitHub Actions: 4x daily collector
├── knowledge_schema.sql         # Complete database schema (7 tables)
│
├── mdr_intelligence.py          # Phase 1: Intelligence processing (~551 lines)
├── attack_mapping.py            # Phase 1: MITRE ATT&CK mapping (~172 lines)
├── date_utils.py                # Phase 1: UTC/IST date handling (~205 lines)
├── collector_mdr.py             # Phase 1+2: Main collector (~531 lines)
│
├── entity_extractor.py          # Phase 2: Entity extraction (~534 lines)
├── knowledge_graph.py           # Phase 2: Graph manager (~508 lines)
├── knowledge_dashboard.py       # Phase 2: Knowledge UI (~357 lines)
│
├── topic_page.py                # Phase 3: Topic pages (~463 lines)
├── app_mdr.py                   # Main dashboard (~832 lines)
│
├── generate_pwa_icons.py        # PWA icon generator utility
├── run_migration.py             # Database migration runner
├── migrations/                  # SQL migration scripts
│   └── 001_add_escalation_velocity_fields.sql
├── public/                      # Screenshots & images
│   ├── Daily Brief View.jpg     # Daily Brief screenshot
│   ├── Topic Pages.jpg          # Topic Pages screenshot
│   └── Mobile-Responsive UI.jpg # Mobile UI screenshot
├── static/                      # Static assets
│   ├── manifest.json            # PWA manifest
│   └── service-worker.js        # PWA service worker
│
└── __pycache__/                 # Python cache (git-ignored)
```

### File Descriptions

| File | Purpose | Phase | Lines |
|------|---------|-------|-------|
| `mdr_intelligence.py` | Event normalization, signal scoring, analyst take generation | 1 | ~551 |
| `attack_mapping.py` | MITRE ATT&CK tactics/techniques, Kill Chain, attack names | 1 | ~172 |
| `date_utils.py` | Centralized date parsing, UTC-to-IST conversion | 1 | ~205 |
| `collector_mdr.py` | RSS aggregation, CVE enrichment, knowledge graph processing | 1+2 | ~531 |
| `entity_extractor.py` | Extract threat actors, CVEs, technologies, malware, IOCs | 2 | ~534 |
| `knowledge_graph.py` | Topic management, relationships, IOC export, search | 2 | ~508 |
| `knowledge_dashboard.py` | Knowledge UI: overview, explorer, IOCs, SIEM templates | 2 | ~357 |
| `topic_page.py` | Living pages: timeline, relationships, IOCs, notes | 3 | ~463 |
| `app_mdr.py` | Main Streamlit dashboard with all views | 1+2+3 | ~832 |
| `knowledge_schema.sql` | Complete database schema (7 knowledge tables) | 2+3 | ~150 |

### Total Project Statistics

- **Total Lines of Code**: ~4,150+ lines
- **Python Modules**: 9 core modules
- **Database Tables**: 8 tables (1 intelligence + 7 knowledge graph)
- **Entity Types Tracked**: 5 types (threat actors, CVEs, technologies, attack types, malware)
- **Entities in Dictionary**: 170+ entities
- **IOC Types**: 5 types (IPv4, domain, file hash, URL, email)
- **Export Formats**: 3 formats (CSV, JSON, TXT)
- **SIEM Integrations**: 4 platforms (Splunk, Sentinel, QRadar, Elastic)
- **View Modes**: 3 modes (Daily Brief, Knowledge Graph, Topic Pages)

---

## 🧪 Testing & Validation

### Test Intelligence Collector
```bash
python collector_mdr.py
```

**Verification Checklist:**
- ✅ RSS feeds accessible (all 5 sources)
- ✅ NVD API responding (2-second rate limit enforced)
- ✅ CISA KEV API responding
- ✅ Event normalization working
- ✅ Signal strength calculations correct
- ✅ MDR analyst takes generated
- ✅ Entity extraction working (threat actors, CVEs, technologies found)
- ✅ Knowledge graph updated (topics, relationships, IOCs)
- ✅ Database inserts successful

### Test Dashboard
```bash
streamlit run app_mdr.py
```

**Daily Brief (Phase 1):**
- ✅ Filters working (signal, exploitation, time range, confidence)
- ✅ Time range properly bounded
- ✅ Sorted newest-first by published date
- ✅ Analyst takes displaying prominently
- ✅ Entity buttons appearing below cards
- ✅ IST timezone showing correctly
- ✅ Review workflow (mark reviewed, bookmark, notes)

**Knowledge Graph (Phase 2):**
- ✅ Overview tab showing statistics
- ✅ Topic explorer search working
- ✅ IOC dashboard filters functioning
- ✅ Export formats working (CSV, JSON, TXT)
- ✅ SIEM templates displaying correctly

**Topic Pages (Phase 3):**
- ✅ Clicking entity button opens topic page
- ✅ Timeline tab shows all articles chronologically
- ✅ Relationships tab displays connections
- ✅ IOCs tab shows related indicators
- ✅ Notes tab saves successfully
- ✅ Navigation between related topics works

### Test Entity Extraction
```bash
python -c "from entity_extractor import EntityExtractor; e = EntityExtractor(); entities = e.extract_all('LockBit ransomware exploits CVE-2024-1234 in Microsoft Exchange'); print(entities)"
```

---

## 🚨 Troubleshooting

### Collector Issues

**No items collected:**
- Test RSS feed accessibility: `curl https://www.bleepingcomputer.com/feed/`
- Test database connection with a simple Supabase query
- Check `.env` file has correct credentials

**NVD API errors:**
- Rate limit enforced automatically (2-second delay per CVE lookup)
- Connection timeout: increase in `enrich_cve_from_nvd()` function
- Newly disclosed CVEs may not be in NVD database yet

**Knowledge graph not building:**
- Verify `knowledge_schema.sql` was executed (7 tables should exist)
- Check entity_extractor.py is imported correctly in collector_mdr.py

### Dashboard Issues

**Dashboard won't load:**
- Verify Supabase credentials in `.env` (or `st.secrets` on Streamlit Cloud)
- Check `SUPABASE_URL` and `SUPABASE_KEY` are correct
- Restart Streamlit: `Ctrl+C` then `streamlit run app_mdr.py`
- Check Python version: `python --version` (requires 3.10+, 3.12 recommended)

**Filters not working:**
- Clear browser cache: Ctrl+F5
- Check Supabase table has required fields
- Check browser console (F12) for errors

**Entity buttons not appearing:**
- Check article has title and summary (extraction requires text content)
- Ensure EntityExtractor is imported in app_mdr.py
- Run collector to process articles

**Topic pages show "Topic not found":**
- Topic may not exist yet (needs at least 1 article mention)
- Run collector to process articles and create topics
- Check `topics` table in Supabase

**IST timezone not showing:**
- Verify `date_utils.py` is imported in app_mdr.py
- Dates should show format: "11 Feb 2026 15:30 IST"

### Performance Issues

**Slow dashboard loading (>5 seconds):**
- Filter data to smaller time ranges
- Add indexes to database (see Database Schema section)
- Limit results in `fetch_intelligence()` if needed

**Collector taking too long (>10 minutes):**
- NVD API rate limit (2 seconds per CVE) is intentional
- Reduce number of RSS feeds to test
- Skip CVE enrichment temporarily

---

## ⚠️ Known Limitations

### Semantic Search (Disabled on Streamlit Cloud)

**Status:** Available for local development only

Semantic search using pgvector and sentence-transformers is **not included** in the deployed Streamlit Cloud app. The `sentence-transformers` and `torch` packages were removed from `requirements.txt` to keep the deployment lightweight and avoid build failures on cloud platforms.

**If you want semantic search locally:**
```bash
pip install sentence-transformers
```
The app will auto-detect availability and show the semantic search UI when the package is installed.

### Date Handling (Critical)
All feed dates use a centralized UTC parser (`date_utils.py`). This is essential for:
- Delta detection consistency
- Weaponization speed calculations
- Trend analysis accuracy

**Rule:** ONE date parser function. No exceptions.

### ID Collision Risk
Current schema uses `BIGSERIAL PRIMARY KEY`. A UUID migration script is available at `migrations/` if needed for production scale.

### "Unknown" Exploitation Status
Single `unknown` status doesn't capture *why* it's unknown. Future improvement: distinguish `unknown_no_data` vs `unknown_conflicting_sources` vs `unknown_early_report`.

---

## ✅ Implemented Features

### "What Changed Since Yesterday?" View
- Sidebar → View Mode → "What Changed Since Yesterday?"
- Shows only new/changed items since your last review
- Tracks new articles, exploitation escalations (🟡 → 🔴), signal upgrades

### Exploitation Status Escalation Tracking
- Tracks `exploitation_escalated_at` and `signal_upgraded_at` timestamps
- Delta View automatically filters escalations

### Mobile-Responsive UI
- Works on phones (≤480px), tablets (481-768px), desktop (>768px)
- Touch-friendly buttons (44px minimum tap targets)
- No horizontal scrolling

### PWA (Progressive Web App) Support
- Install as standalone app on mobile/desktop (requires HTTPS — use Streamlit Cloud)
- Offline caching via service worker
- Native app icons and splash screen

### Newest-First Sorting
- Intelligence feed sorted by `published_at` descending by default
- Most recent threat intelligence always appears at the top

### 4x Daily Collection
- GitHub Actions runs collector at 6 AM, 12 PM, 6 PM, and 11 PM UTC
- Covers global business hours for timely threat intelligence

---

## 🟡 Recommendations for Future Enhancement

1. **Automated Expertise Calculation** - Auto-increment expertise when reading articles, adding notes
2. **Topic Watchlists** - Subscribe to topics for email/webhook notifications
3. **Visual Relationship Graph** - Interactive network graph (D3.js/Cytoscape.js)
4. **Threat Velocity Display** - Surface weaponization speed visually (🔴 FAST / 🟡 MODERATE / 🟢 SLOW)
5. **Weekly Technique Heatmap** - Bar chart of top recurring attack techniques
6. **Historical Recall** - "Show similar events (last 90 days)" button

---

## 🚫 What NOT to Add

**Intentional design boundaries:**

❌ **Detection rules** - Not your job, reduces trust  
❌ **Predictive analytics** - Adds noise, reduces clarity  
❌ **AI-generated summaries** - Unreliable; we use rule-based analyst takes instead  
❌ **Real-time alerting** - Wrong workflow for daily intelligence review  
❌ **Org-specific risk scoring** - Personal platform, not org tool  

**Philosophy:** This platform is valuable BECAUSE it is calm, focused, and disciplined.

---

## 🛡️ Hardening Checklist

**Before trusting this system in production:**

### Data & Logic
- [ ] UUID primary keys (migration at `migrations/`)
- [ ] Mandatory signal_strength_reason (always explain scoring)
- [ ] Internal reason for unknown exploitation status

### UX Improvements
- [ ] Visual badge for status escalation (🟡 → 🔴 transitions)
- [ ] Collapse Low-signal items by default

### Operations
- [ ] Idempotent collector runs (safe to run multiple times)
- [ ] Weekly database backup (automated via Supabase)
- [ ] Log exploitation status escalations (audit trail)

---

## 📈 Success Metrics

### Platform Working When:
- ✅ Daily review takes **5-10 minutes** (down from 30-60 minutes)
- ✅ Catch exploits **faster than colleagues**
- ✅ Pattern recognition **improves week-over-week**
- ✅ Meeting briefings become **effortless** (just share topic pages)
- ✅ Signal-to-noise ratio feels **manageable**
- ✅ **Topic pages become your go-to reference** for any entity
- ✅ **Knowledge compounds** - notes from 6 months ago still valuable

---

## 🤝 Contributing

This is a personal MDR platform designed for individual analysts. Contributions are welcome if they align with the core philosophy.

### Core Principles:
1. **Speed over completeness** - Daily review should take 5-10 minutes
2. **Signal over volume** - Filter noise aggressively
3. **Clarity over features** - Simple, focused tools
4. **Knowledge over alerts** - Build understanding, not panic
5. **Calm intelligence** - Deliberate, methodical analysis

### What We Accept:
✅ Bug fixes  
✅ Performance improvements  
✅ Additional entity dictionaries  
✅ New RSS feed sources (reliable, high-signal)  
✅ Documentation improvements  
✅ IOC extraction enhancements  
✅ SIEM template additions  

### What We Don't Accept:
❌ Detection rules or signatures  
❌ Predictive analytics or ML models  
❌ Real-time alerting systems  
❌ Organization-specific features  
❌ Complexity that slows down daily workflow  

---

## 📚 Additional Resources

### External References
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Tactics, techniques, and procedures
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Attack lifecycle model
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - KEV catalog
- [NVD CVE Database](https://nvd.nist.gov/) - National Vulnerability Database
- [Streamlit Documentation](https://docs.streamlit.io/) - Dashboard framework
- [Supabase Documentation](https://supabase.com/docs) - PostgreSQL backend

---

## 📝 License

MIT License - Use freely for personal MDR work.

---

## 🙏 Acknowledgments

Built for speed. Optimized for signal. Designed for one analyst who needs to stay ahead.

**Special Thanks To:**
- **Open source threat intelligence community** - For sharing knowledge freely
- **RSS feed providers** - BleepingComputer, Krebs on Security, Schneier on Security, The Hacker News, Dark Reading
- **MITRE Corporation** - For ATT&CK framework
- **CISA** - For Known Exploited Vulnerabilities catalog
- **NVD/NIST** - For CVE enrichment data
- **Supabase** - For free PostgreSQL hosting
- **Streamlit** - For rapid dashboard development

**Core Philosophy:**  
*"If it doesn't help answer 'What changed in the threat landscape today?', it doesn't belong here."*

---

*Last updated: February 13, 2026*  
*Platform version: 3.1*  
*Total implementation: ~4,150+ lines of Python across 9 modules*  
*Database: 8 tables (1 intelligence feed + 7 knowledge graph)*  
*Dependencies: 7 packages (lightweight, no torch/ML on cloud)*  
*Deployment: Streamlit Cloud (Python 3.12) + GitHub Actions (4x daily collection)*  
*Timezone: IST (UTC+5:30) throughout*

---

**🎯 Built for analysts. By analysts. For staying ahead of threats.**
