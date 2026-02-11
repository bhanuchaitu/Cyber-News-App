# Personal MDR Cyber Threat Intelligence Platform

> **Transform public cybersecurity news into analyst-ready threat intelligence with automated knowledge graph building, entity extraction, and living topic pages**  
> Optimized for speed, signal, and clarity for a single MDR analyst.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40-FF4B4B.svg)](https://streamlit.io/)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E.svg)](https://supabase.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

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

### Phase 2: Knowledge Graph & Entity Intelligence
- ✅ **Automatic entity extraction** (65+ threat actors, 60+ technologies, 25+ attack types, 20 malware families)
- ✅ **Knowledge graph** with automatic relationship building
- ✅ **IOC extraction & export** (IPs, domains, file hashes, URLs, emails) in CSV/JSON/TXT
- ✅ **SIEM integration templates** (Splunk, Sentinel, QRadar, Elastic)
- ✅ **Semantic search** across topics using pgvector
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
│               Supabase (PostgreSQL + pgvector)                           │
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
│  • Exploitation priority sort     │  • Knowledge overview              │
│  • Signal filtering (IST timezone)│  • Topic explorer & search         │
│  • Analyst take display          │  • IOC dashboard & export          │
│  • Clickable entity buttons      │                                    │
│  • Review workflow               │  Topic Pages (topic_page.py)        │
│                                  │  • Timeline view (all articles)     │
│                                  │  • Relationship graph              │
│                                  │  • Related IOCs                    │
│                                  │  • Personal notes & expertise      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Modules

### Core Modules

#### Phase 1: Intelligence Processing

1. **`mdr_intelligence.py`** (560 lines) - Intelligence processing engine
   - Event normalization (9 event types)
   - Exploitation status determination
   - Signal strength calculation (High/Medium/Low)
   - MDR analyst take generation
   - Pattern extraction

2. **`attack_mapping.py`** (185 lines) - Threat framework mapping
   - MITRE ATT&CK tactics (14) & techniques (15)
   - Cyber Kill Chain phases (7)
   - Attack name identification (APT groups, ransomware, malware)

3. **`collector_mdr.py`** (390 lines) - Intelligence collector
   - RSS feed aggregation (5 sources)
   - CVE enrichment via NVD API
   - CISA KEV verification
   - Knowledge graph processing
   - Automated article ingestion

4. **`date_utils.py`** (220 lines) - Centralized date handling
   - UTC-to-IST timezone conversion (Indian Standard Time)
   - Feed date parsing with consistency
   - Weaponization speed calculations

#### Phase 2: Knowledge Graph  

5. **`entity_extractor.py`** (527 lines) - Entity extraction engine
   - **65+ threat actors**: LockBit, ALPHV, APT28, APT29, Lazarus Group, BlackCat, Akira, etc.
   - **60+ technologies**: Microsoft, VMware, Fortinet, Palo Alto, AWS, Azure, Google Cloud, etc.
   - **25+ attack types**: Ransomware, phishing, supply chain, zero-day, DDoS, etc.
   - **20 malware families**: Cobalt Strike, Mimikatz, AgentTesla, RedLine, etc.
   - **CVE extraction** with pattern matching
   - **IOC extraction**: IPs, domains, file hashes, URLs, email addresses

6. **`knowledge_graph.py`** (480 lines) - Knowledge graph manager
   - Automatic topic creation and updates
   - Relationship building (exploits, targets, affects, uses)
   - Topic search with filters
   - IOC export (CSV, JSON, TXT formats)
   - Statistics and analytics

7. **`knowledge_dashboard.py`** (400 lines) - Knowledge UI components
   - Knowledge overview with statistics
   - Topic explorer with search
   - Topic details with relationships
   - IOC dashboard with filtering
   - SIEM integration templates (Splunk, Sentinel, QRadar, Elastic)

#### Phase 3: Topic Pages

8. **`topic_page.py`** (468 lines) - Living topic pages
   - Individual entity pages (threat actors, CVEs, technologies, attack types, malware)
   - Timeline view (chronological article list)
   - Relationship navigation (outgoing/incoming connections)
   - Related IOCs by topic
   - Personal notes editor with expertise tracking (0-100 scale)

9. **`app_mdr.py`** (603 lines) - Main Streamlit dashboard
   - Daily Brief view with exploitation priority sorting
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
- **Signal Strength**: High / Medium / Low
- **Exploitation Status**: Actively Exploited / PoC Available / Theoretical / Unknown
- **Time Range**: Today / Last 3 Days / Last 7 Days / Last 30 Days (with proper date bounds)
- **Source Confidence**: High / Medium / Low
- **Show Reviewed**: Toggle reviewed/unreviewed items

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
   - Perfect for tracking threat evolution

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
- **Python 3.10+**
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

**Core dependencies:**
- `streamlit==1.40.2` - Dashboard UI
- `supabase==2.11.0` - Database client
- `feedparser==6.0.11` - RSS feed parsing
- `python-dotenv==1.0.1` - Environment configuration
- `requests==2.32.3` - HTTP requests
- `pandas==2.2.3` - Data manipulation

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

**Expected output:**
```
🎯 PERSONAL MDR CYBER THREAT INTELLIGENCE COLLECTOR
================================================================

📡 Collecting from RSS feeds...

  📰 Processing BleepingComputer...
    🔴 Active Exploit: APT28 Weaponizes Office Bug... [High signal]
    🟡 Vulnerability: VMware vCenter RCE discovered... [Medium signal]
    🟢 Research: New memory protection bypass technique... [Low signal]
    ✅ Collected 15 items from BleepingComputer

  📰 Processing Krebs on Security...
    ✅ Collected 8 items from Krebs on Security

  [... processing other feeds ...]

🧠 Processing knowledge graph...
  ✓ Extracted 47 entities (threat actors, CVEs, technologies, etc.)
  ✓ Built 23 relationships between topics
  ✓ Extracted 127 IOCs (IPs, domains, hashes)

📊 INTELLIGENCE SUMMARY
================================================================
📰 Total Articles: 42
🔴 Active Exploits: 3
🟡 PoC Available: 8
🎯 High Signal: 11
⚠️  CISA KEV: 2
📍 CVEs Found: 15

🧠 KNOWLEDGE GRAPH
================================================================
📌 Topics Created: 47
🔗 Relationships: 23
🎯 IOCs Extracted: 127

⏱️  Collection completed in 68.4 seconds
================================================================
```

#### 7. Launch Dashboard
```bash
streamlit run app_mdr.py
```

Dashboard opens at: `http://localhost:8501`

**First login view:**
- Daily Brief with filtered intelligence cards
- Sidebar with filters (signal, exploitation, time range)
- Entity buttons on each article (clickable!)
- Knowledge Graph view mode option

---

## 📖 Usage Guide

### Daily Workflow (5-10 minutes)

#### Morning Intelligence Review

1. **Run Collector** (automated daily or manual)
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
   - Focus on 🔴 **ACTIVELY EXPLOITED** first
   - Read **MDR Analyst Takes** (1-3 sentences)
   - Check CISA KEV warnings
   - Note exploitation velocity indicators

5. **Explore Topics** (NEW in Phase 3)
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

**Scenario:** New ransomware gang mentioned in feed

1. **Discovery**
   - Article in Daily Brief: "New ransomware gang 'DarkVault' hits healthcare"
   - Click **"DarkVault"** entity button below card

2. **Timeline Analysis** (Tab 1)
   - Review all 4 articles mentioning DarkVault
   - First appearance: Jan 15, 2026
   - Track campaign evolution chronologically

3. **Relationship Mapping** (Tab 2)
   - Discover DarkVault **uses** Cobalt Strike
   - Discover DarkVault **targets** Healthcare sector
   - Discover DarkVault **exploits** CVE-2024-5678
   - Click related topics to explore further

4. **IOC Collection** (Tab 3)
   - View 12 C2 IPs, 8 file hashes extracted
   - Export as CSV/JSON/TXT
   - Import to SIEM for blocking

5. **Documentation** (Tab 4)
   - Add notes: "Active since Jan 2026, cryptocurrency demands, weak VPN targeting"
   - Track expertise: 35/100 (Learning 📚)

#### Workflow 2: CVE Tracking

**Scenario:** Critical vulnerability in your infrastructure

1. **Initial Alert**
   - CVE-2026-1234 appears in Daily Brief
   - Click CVE button → Topic page opens

2. **Impact Assessment**
   - Timeline: 8 articles tracked
   - Relationships reveal:
     - **Affects**: VMware ESXi, vCenter
     - **Exploited by**: LockBit, ALPHV
     - CVSS 9.8 (Critical)
     - PoC public since Feb 5

3. **IOC Monitoring**
   - 23 attack indicators
   - Add to watchlist

4. **Ongoing Tracking**
   - Check back weekly
   - Timeline grows to 15 articles
   - Update notes with patch status

#### Workflow 3: Knowledge Graph Exploration

1. **Switch View Mode**: Sidebar → "Knowledge Graph"

2. **Overview Tab**
   - See total topics: 347 entities
   - Entity breakdown: 85 threat actors, 142 CVEs, 67 technologies, etc.
   - IOC statistics: 1,247 indicators extracted

3. **Topic Explorer**
   - Search: "ransomware"
   - Filter by type: "Threat Actor"
   - Results: LockBit, ALPHV, BlackCat, Akira, etc.
   - Click "View Details" → Opens topic page

4. **IOC Dashboard**
   - Filter: IOC Type = "Domain", Confidence ≥ 0.7
   - Time period: Last 30 days
   - Export as JSON for STIX ingestion
   - Use SIEM templates (Splunk, Sentinel, QRadar, Elastic)

---

## 🎨 Dashboard Features

### Stats Overview
- **Total Intelligence** - All collected items
- **🔴 Active Exploits** - Confirmed in-the-wild exploitation
- **High Signal** - High-confidence intelligence
- **⚠️ CISA KEV** - Known Exploited Vulnerabilities
- **CVEs Found** - Total CVE identifications

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
    event_type              TEXT,  -- Vulnerability, Active Exploit, etc.
    primary_target          TEXT,  -- VMware, Microsoft, etc.
    attack_vector           TEXT,  -- Phishing, RCE, OAuth, etc.
    impact_outcome          TEXT,  -- RCE, Data Exfiltration, etc.
    
    -- Exploitation Reality
    first_observed_date     DATE,
    exploitation_status     TEXT,  -- actively_exploited, poc_available, theoretical, unknown
    weaponization_speed     INT,   -- Days from disclosure to exploit
    previous_exploitation_status TEXT,
    exploitation_escalated_at TIMESTAMPTZ,
    
    -- Intelligence
    mdr_analyst_take        TEXT,  -- 1-3 sentence summary
    technical_method        TEXT,  -- How attack works
    delta_reason            TEXT,  -- Why news today
    
    -- Signal & Source
    signal_strength         TEXT,  -- High, Medium, Low
    signal_strength_reason  TEXT,
    signal_upgraded_at      TIMESTAMPTZ,
    previous_signal_strength TEXT,
    source_confidence       TEXT,  -- High, Medium, Low
    evidence_sources        TEXT[],
    evidence_count          INT,
    
    -- Pattern & Trends
    pattern_tags            TEXT[],
    campaign_id             TEXT,
    story_hash              TEXT,
    threat_velocity         TEXT,  -- FAST, MODERATE, SLOW
    
    -- CVE Data
    cve_id                  TEXT,
    cvss_score              FLOAT,
    cvss_vector             TEXT,
    cve_published_date      DATE,
    cisa_exploited          BOOLEAN,
    
    -- Attack Frameworks
    attack_name             TEXT,  -- APT28, LockBit, etc.
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

**7-table knowledge graph schema for entity tracking and relationships**

**1. `topics`** - Entity master table

```sql
CREATE TABLE topics (
    id SERIAL PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,           -- URL-friendly identifier (e.g., 'lockbit', 'cve_2026_1234')
    name TEXT NOT NULL,                   -- Display name
    description TEXT,                     -- Entity description
    type TEXT NOT NULL,                   -- threat_actor, cve, technology, attack_type, malware, campaign
    article_count INT DEFAULT 0,          -- Number of articles mentioning this entity
    first_seen TIMESTAMPTZ,              -- First appearance in intelligence
    last_seen TIMESTAMPTZ,               -- Most recent appearance
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB                        -- Flexible additional data (CVSS scores, aliases, etc.)
);
```

**2. `topic_relationships`** - Entity connections

```sql
CREATE TABLE topic_relationships (
    id SERIAL PRIMARY KEY,
    source_topic_id INT REFERENCES topics(id) ON DELETE CASCADE,
    target_topic_id INT REFERENCES topics(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,     -- exploits, targets, affects, uses, related_to
    strength FLOAT DEFAULT 0.5,          -- 0.0 - 1.0 confidence score
    evidence_count INT DEFAULT 1,        -- Number of articles supporting this relationship
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_topic_id, target_topic_id, relationship_type)
);
```

**3. `iocs`** - Indicators of compromise

```sql
CREATE TABLE iocs (
    id SERIAL PRIMARY KEY,
    article_id INT,                      -- Can link to daily_brief if needed
    ioc_type TEXT NOT NULL,              -- ioc_ipv4, ioc_domain, ioc_file_hash, ioc_url, ioc_email
    value TEXT NOT NULL,                 -- The actual indicator
    confidence FLOAT DEFAULT 0.5,        -- 0.0 - 1.0 extraction confidence
    context TEXT,                        -- Surrounding text for verification
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INT DEFAULT 1,      -- Times seen across articles
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ioc_type, value)
);
```

**4. `user_knowledge`** - Personal notes and expertise

```sql
CREATE TABLE user_knowledge (
    id SERIAL PRIMARY KEY,
    topic_id INT REFERENCES topics(id) ON DELETE CASCADE,
    notes TEXT,                          -- Free-form personal notes
    expertise_level INT DEFAULT 0,       -- 0-100 score
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(topic_id)
);
```

**5. `article_topics`** - Article-to-topic mappings

```sql
CREATE TABLE article_topics (
    id SERIAL PRIMARY KEY,
    article_id INT,                      -- Reference to intelligence article
    topic_id INT REFERENCES topics(id) ON DELETE CASCADE,
    relevance_score FLOAT DEFAULT 1.0,   -- How relevant this topic is to the article
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(article_id, topic_id)
);
```

**6. `attck_techniques`** - MITRE ATT&CK mappings

```sql
CREATE TABLE attck_techniques (
    id SERIAL PRIMARY KEY,
    technique_id TEXT NOT NULL,          -- T1566, T1059, etc.
    technique_name TEXT,
    tactic TEXT,
    article_id INT,
    topic_id INT REFERENCES topics(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**7. `article_attck`** - Article-to-ATT&CK mappings

```sql
CREATE TABLE article_attck (
    id SERIAL PRIMARY KEY,
    article_id INT,
    technique_id TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(article_id, technique_id)
);
```

### Performance Indexes

```sql
-- Phase 1 Intelligence Feed
CREATE INDEX idx_exploitation_status ON daily_brief(exploitation_status) 
WHERE exploitation_status = 'actively_exploited';

CREATE INDEX idx_signal_strength ON daily_brief(signal_strength) 
WHERE signal_strength = 'High';

CREATE INDEX idx_published_at ON daily_brief(published_at DESC);

CREATE INDEX idx_reviewed ON daily_brief(reviewed_at) 
WHERE reviewed_at IS NULL;

CREATE INDEX idx_pattern_tags ON daily_brief USING GIN(pattern_tags);

-- Phase 2 Knowledge Graph
CREATE INDEX idx_topics_slug ON topics(slug);
CREATE INDEX idx_topics_type ON topics(type);
CREATE INDEX idx_topic_relationships_source ON topic_relationships(source_topic_id);
CREATE INDEX idx_topic_relationships_target ON topic_relationships(target_topic_id);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_article_topics_article ON article_topics(article_id);
CREATE INDEX idx_article_topics_topic ON article_topics(topic_id);

-- pgvector extension (optional for semantic search)
CREATE EXTENSION IF NOT EXISTS vector;
```

---

## �️ Customization

### Adjust Signal Thresholds

Edit [mdr_intelligence.py](mdr_intelligence.py):
```python
# Line ~360: calculate_signal_strength()
if score >= 50:      # Change threshold
    strength = 'High'
elif score >= 25:    # Change threshold
    strength = 'Medium'
```

### Add Custom Pattern Tags

Edit [mdr_intelligence.py](mdr_intelligence.py):
```python
# Line ~425: extract_pattern_tags()
patterns = {
    'your_pattern': ['keyword1', 'keyword2'],
    'custom_tag': ['indicator1', 'indicator2'],
}
```

### Modify Event Types

Edit [mdr_intelligence.py](mdr_intelligence.py):
```python
# Line ~14: EVENT_TYPE_PATTERNS
EVENT_TYPE_PATTERNS = {
    'Your Custom Type': [r'pattern1', r'pattern2'],
}
```

### Add RSS Feeds

Edit [collector_mdr.py](collector_mdr.py):
```python
# Line ~40: RSS_FEEDS
RSS_FEEDS = {
    'Your Source': 'https://example.com/feed.xml',
}
```

### Customize Entity Extraction

Edit [entity_extractor.py](entity_extractor.py):
```python
# Add more threat actors, technologies, attack types, or malware
THREAT_ACTORS = {
    'Your New Actor': ['alias1', 'alias2'],
}

TECHNOLOGIES = {
    'Your Technology': ['keyword1', 'keyword2'],
}
```

### Modify Topic Page Display Limits

Edit [app_mdr.py](app_mdr.py):
```python
# Line ~514: Entity extraction limits
MAX_CVES = 3           # CVEs to show per article
MAX_ACTORS = 2          # Threat actors to show
MAX_TECHNOLOGIES = 2    # Technologies to show
MAX_ATTACK_TYPES = 2    # Attack types to show
MAX_MALWARE = 2         # Malware families to show
```

---

## 🧪 Testing & Validation

### Test Intelligence Collector
```bash
python collector_mdr.py
```

**Expected Output:**
```
Starting MDR Intelligence Collection...
Fetching from BleepingComputer...
Processing 18 items from BleepingComputer
...
Entity extraction: Found 12 threat actors, 8 CVEs, 15 technologies
Knowledge graph: Created 35 topics, 42 relationships
IOCs extracted: 23 IPv4s, 15 domains, 5 file hashes
✅ Collection complete: 67 items processed
```

**Verification Checklist:**
- ✅ RSS feeds accessible (all 5 sources)
- ✅ NVD API responding (2-second rate limit enforced)
- ✅ CISA KEV API responding
- ✅ Event normalization working (event types assigned)
- ✅ Signal strength calculations correct (High/Medium/Low)
- ✅ MDR analyst takes generated (1-3 sentences per article)
- ✅ Pattern tags extracted
- ✅ Entity extraction working (threat actors, CVEs, technologies found)
- ✅ Knowledge graph updated (topics, relationships, IOCs)
- ✅ Database inserts successful (check Supabase dashboard)

### Test Dashboard
```bash
streamlit run app_mdr.py
```

**Verification Checklist:**

**Daily Brief (Phase 1):**
- ✅ Filters working (signal, exploitation, time range, confidence)
- ✅ Time range properly bounded (Today excludes past/future dates)
- ✅ Sorting by exploitation priority (🔴 Actively Exploited first)
- ✅ Analyst takes displaying prominently (1-3 sentences)
- ✅ Entity buttons appearing below cards (up to 10 per card)
- ✅ IST timezone showing correctly ("DD MMM YYYY HH:MM IST" format)
- ✅ Review workflow (mark reviewed, bookmark, notes)
- ✅ Statistics showing in sidebar (total, active exploits, high signal)

**Knowledge Graph (Phase 2):**
- ✅ Overview tab showing statistics (topics, relationships, IOCs)
- ✅ Topic explorer search working
- ✅ IOC dashboard filters functioning (type, confidence, time period)
- ✅ Export formats working (CSV, JSON, TXT)
- ✅ SIEM templates displaying correctly (Splunk, Sentinel, QRadar, Elastic)
- ✅ Topic type filtering working (Threat Actor, CVE, Technology, etc.)

**Topic Pages (Phase 3):**
- ✅ Clicking entity button opens topic page
- ✅ Header shows topic name, type, article count
- ✅ Timeline tab shows all articles chronologically (grouped by month)
- ✅ Relationships tab displays incoming/outgoing connections
- ✅ IOCs tab shows related indicators (grouped by type)
- ✅ Notes tab allows editing and saves successfully
- ✅ Expertise slider updates and saves (0-100 scale)
- ✅ Navigation between related topics works (click relationship → opens topic)
- ✅ Back button returns to Daily Brief

### Test Entity Extraction
```bash
python -c "from entity_extractor import EntityExtractor; \
e = EntityExtractor(); \
text = 'LockBit ransomware exploits CVE-2024-1234 in Microsoft Exchange targeting healthcare'; \
entities = e.extract_all(text); \
print(f'Threat Actors: {entities[\"threat_actors\"]}'); \
print(f'CVEs: {entities[\"cves\"]}'); \
print(f'Technologies: {entities[\"technologies\"]}'); \
print(f'Attack Types: {entities[\"attack_types\"]}')"
```

**Expected Output:**
```
Threat Actors: ['LockBit']
CVEs: ['CVE-2024-1234']
Technologies: ['Microsoft Exchange']
Attack Types: ['ransomware']
```

### Test IOC Extraction
```bash
python -c "from entity_extractor import EntityExtractor; \
e = EntityExtractor(); \
text = 'C2 server at 192.168.1.100 and malicious domain evil.com used hash a1b2c3d4'; \
iocs = e.extract_iocs(text); \
print(f'IPv4: {iocs.get(\"ioc_ipv4\", [])}'); \
print(f'Domains: {iocs.get(\"ioc_domain\", [])}'); \
print(f'Hashes: {iocs.get(\"ioc_file_hash\", [])}')"
```

**Expected Output:**
```
IPv4: ['192.168.1.100']
Domains: ['evil.com']
Hashes: ['a1b2c3d4']
```

---

## 🚨 Troubleshooting

### Collector Issues

**Problem: No items collected**
```bash
# Test RSS feed accessibility
curl https://www.bleepingcomputer.com/feed/

# Test database connection
python -c "from supabase import create_client; \
import os; from dotenv import load_dotenv; \
load_dotenv(); \
url = os.getenv('SUPABASE_URL'); \
key = os.getenv('SUPABASE_KEY'); \
client = create_client(url, key); \
result = client.table('daily_brief').select('id').limit(1).execute(); \
print('✅ Database connected successfully!')"
```

**Problem: NVD API errors**
- **Rate limit exceeded**: Collector automatically enforces 2-second delay between CVE lookups
- **Connection timeout**: Increase timeout in `enrich_cve_from_nvd()` function (line ~280 in collector_mdr.py)
- **No CVE data found**: CVE may not be in NVD database yet (newly disclosed vulnerabilities)
- **API key issues**: NVD API works without key but with strict rate limits

**Problem: Knowledge graph not building**
- Check `entity_extractor.py` is imported correctly in collector_mdr.py
- Verify `knowledge_schema.sql` was executed (7 tables should exist)
- Check tables exist: `topics`, `topic_relationships`, `iocs`, `user_knowledge`, `attck_techniques`, `article_topics`, `article_attck`
- Run `SELECT COUNT(*) FROM topics;` in Supabase SQL Editor

**Problem: Entity extraction not finding entities**
- Verify entity dictionaries in `entity_extractor.py` (lines 10-80)
- Check article text quality (summary field should have content)
- Test extraction manually (see "Test Entity Extraction" above)

### Dashboard Issues

**Problem: Dashboard won't load**
- Verify Supabase credentials in `.env` file
- Check `SUPABASE_URL` and `SUPABASE_KEY` are correct
- Ensure no extra spaces/quotes in .env values
- Restart Streamlit: `Ctrl+C` then `streamlit run app_mdr.py`
- Check Python version: `python --version` (requires 3.10+)

**Problem: Filters not working**
- Ensure running latest version of `app_mdr.py`
- Check Supabase table has required fields (`signal_strength`, `exploitation_status`, `published_at`)
- Clear browser cache: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac)
- Check browser console (F12) for JavaScript errors
- Verify filter logic in `fetch_intelligence()` function (lines 296-370 in app_mdr.py)

**Problem: Entity buttons not appearing**
- Check article has title and summary (extraction requires text content)
- View browser console (F12) for JavaScript errors
- Verify entity extraction is running in collector (check logs)
- Ensure EntityExtractor is imported in app_mdr.py (line 10)
- Check entity dictionary size: `len(THREAT_ACTORS)` should return > 0

**Problem: Topic pages show "Topic not found"**
- Topic may not exist in knowledge graph yet (needs at least 1 article mention)
- Run collector to process articles and create topics
- Check `topics` table in Supabase: `SELECT COUNT(*) FROM topics;`
- Verify topic slug format: spaces become underscores, lowercase (e.g., "Lock Bit" → "lockbit")

**Problem: IST timezone not showing**
- Verify `date_utils.py` is imported in both `app_mdr.py` and `knowledge_dashboard.py`
- Check `format_ist_datetime()` function exists (lines 200-215 in date_utils.py)
- Dates should show format: "11 Feb 2026 15:30 IST"
- If showing UTC, check `convert_utc_to_ist()` is being called (line 170-197 in date_utils.py)

**Problem: "No module named 'supabase'" error**
- Activate virtual environment: `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Linux/Mac)
- Reinstall dependencies: `pip install -r requirements.txt`
- Check pip list: `pip list | grep supabase`

### Performance Issues

**Problem: Slow dashboard loading (>5 seconds)**
- Filter data to smaller time ranges (Today, Last 3 Days instead of Last 30 Days)
- Increase Supabase plan if needed (free tier: 500MB, 2GB bandwidth/month)
- Add indexes to database (see Database Schema section)
- Check Supabase project status (dashboard.supabase.com)
- Limit results: Modify fetch_intelligence() to use `.limit(100)`

**Problem: Collector taking too long (>10 minutes)**
- NVD API rate limit (2 seconds per CVE) is intentional to avoid blocking
- Reduce number of RSS feeds in `collector_mdr.py` (comment out sources)
- Run collector less frequently (weekly instead of daily) if data volume is low
- Skip CVE enrichment for testing: comment out `enrich_cve_from_nvd()` calls

**Problem: Topic page slow to load**
- Large topic with 100+ articles (expected behavior)
- Add pagination to timeline tab (modify `render_topic_timeline()`)
- Limit relationships shown (modify `render_topic_relationships()`)
- Check IOC count: Large IOC lists (500+) may slow rendering

### Knowledge Graph Issues

**Problem: Relationships not appearing**
- Check `topic_relationships` table has data: `SELECT COUNT(*) FROM topic_relationships;`
- Verify relationship types in entity_extractor.py (exploits, targets, affects, uses)
- Relationships only created when both entities exist in same article
- Run collector multiple times to build relationship graph

**Problem: IOC export not working**
- Check IOCs exist: `SELECT COUNT(*) FROM iocs;`
- Verify export format selection (CSV/JSON/TXT)
- Check browser download settings (may be blocked)
- Test manual export: `knowledge_graph.export_iocs()` in Python console

**Problem: Notes not saving**
- Check `user_knowledge` table exists
- Verify topic_id is valid: `SELECT * FROM topics WHERE slug = 'your_topic';`
- Clear browser cache and retry
- Check database permissions (Supabase RLS policies)

---

## 🔄 Automation & Scheduling

### GitHub Actions (Automated Collection)

**File:** `.github/workflows/collect-news.yml`

Automatically runs collector daily:
- **Schedule**: Every day at 07:00 UTC (12:30 PM IST)
- **Triggers**: Manual dispatch also available
- **Environment**: Uses GitHub Secrets for Supabase credentials

**Setup:**
1. Go to your GitHub repository → Settings → Secrets and Variables → Actions
2. Add repository secrets:
   - `SUPABASE_URL` - Your Supabase project URL
   - `SUPABASE_KEY` - Your Supabase anon/public key
3. Commit `.github/workflows/collect-news.yml` to repository
4. Workflow runs automatically daily (check Actions tab)

### Windows Task Scheduler

**Step 1: Create `run_collector.bat`:**
```batch
@echo off
cd C:\Users\bhanu\OneDrive\Desktop\Cyber-News-App\Cyber-News-App
call .venv\Scripts\activate.bat
python collector_mdr.py >> collector.log 2>&1
deactivate
```

**Step 2: Schedule daily at 8:00 AM:**
```powershell
$action = New-ScheduledTaskAction -Execute "C:\Users\bhanu\OneDrive\Desktop\Cyber-News-App\Cyber-News-App\run_collector.bat"
$trigger = New-ScheduledTaskTrigger -Daily -At 8am
Register-ScheduledTask -TaskName "MDR Intelligence Collector" `
  -Action $action -Trigger $trigger -Description "Daily threat intelligence collection"
```

**Or use GUI:**
1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task → Name: "MDR Intelligence Collector"
3. Trigger: Daily at 8:00 AM
4. Action: Start a program → Browse to `run_collector.bat`
5. Finish

### Linux Cron Job

**Add to crontab:**
```bash
# Edit crontab
crontab -e

# Add line (runs daily at 8 AM)
0 8 * * * cd /home/user/Cyber-News-App && source .venv/bin/activate && python collector_mdr.py >> collector.log 2>&1
```

**Verify cron job:**
```bash
crontab -l   # List all cron jobs
```

### Docker Deployment (Optional)

**Dockerfile:**
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Default command (collector)
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

**Run with Docker:**
```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 🎓 Three-Phase Implementation

This platform was built in three strategic phases:

### Phase 1: Intelligent Feed Processing ✅
**Goal:** Transform RSS chaos into analyst-ready intelligence

**What was built:**
- Event normalization with 9 event types
- Exploitation status detection (actively exploited, PoC, theoretical)
- Signal strength scoring (High/Medium/Low)
- MDR analyst take generation
- CVE enrichment via NVD API
- CISA KEV verification
- MITRE ATT&CK mapping
- Centralized UTC date handling
- Daily Brief dashboard

**Value delivered:** Intelligence review reduced from 60 mins to 15 mins

### Phase 2: Knowledge Graph & Entity Intelligence ✅
**Goal:** Build automated knowledge graph from intelligence feed

**What was built:**
- Entity extraction engine (65+ threat actors, 60+ technologies, 25+ attack types, 20 malware families)
- Knowledge graph with 7 tables
- Automatic relationship building (exploits, targets, affects, uses)
- IOC extraction (IPs, domains, hashes, URLs, emails)
- IOC export (CSV, JSON, TXT)
- SIEM integration templates
- Knowledge dashboard with overview, topic explorer, IOC dashboard
- Advanced filtering and search

**Value delivered:** Automatic entity tracking, IOC collection, and SIEM integration

### Phase 3: Living Topic Pages ✅
**Goal:** Create explorable knowledge base with personal insights

**What was built:**
- Individual topic pages for every entity
- 4-tab comprehensive views (Timeline, Relationships, IOCs, Notes)
- Clickable entity buttons in Daily Brief
- Seamless navigation between related topics
- Personal notes editor per topic
- Expertise tracking (0-100 scale, 5 levels)
- IST timezone support throughout

**Value delivered:** Institutional knowledge building, meeting prep automation, expertise tracking

---

## ⚠️ Known Limitations & Recommendations

### Current Implementation Notes

#### IST Timezone Support ✅
**Status:** Fully implemented

All dates throughout the platform now display in **Indian Standard Time (UTC+5:30)**:
- Daily Brief article dates
- Topic page timelines
- IOC first/last seen dates
- Knowledge graph timestamps

#### Working Filters ✅
**Status:** Fully functional

All dashboard filters now work correctly:
- **Signal Strength**: Filters by High/Medium/Low
- **Exploitation Status**: Filters by actively_exploited, poc_available, theoretical, unknown
- **Time Range**: Proper date bounds (Today excludes future/past dates)
- **Source Confidence**: Filters by confidence level
- **Show Reviewed**: Toggles reviewed/unreviewed items

Filter logic uses Supabase query operators for database-level filtering (better performance).

#### Phase Completion Status

| Phase | Status | Core Features | Documentation |
|-------|--------|---------------|---------------|
| Phase 1 | ✅ Complete | Intelligence processing, signal scoring | README.md |
| Phase 2 | ✅ Complete | Knowledge graph, entity extraction, IOCs | PHASE2_GUIDE.md |
| Phase 3 | ✅ Complete | Topic pages, notes, expertise tracking | PHASE3_GUIDE.md |

### Recommendations for Future Enhancement

#### 1. ID Collision Risk
**Current schema uses `INT PRIMARY KEY`**

**Recommended fix:**
```sql
-- Better for production scale
id BIGSERIAL PRIMARY KEY

-- Best for deduplication
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

**When to apply:** Before production scale (easy one-line migration)

#### 2. Automated Expertise Calculation
**Current:** Expertise is manually tracked in topic notes

**Enhancement:** Auto-increment expertise when:
- Reading articles about topic (+1 per article)
- Adding notes (+5 per note)
- Viewing relationships (+2)
- Tracking IOCs (+3)

#### 3. Topic Watchlists
**Potential feature:** Subscribe to specific topics for alerts

Would enable:
- Email notifications when new articles mention watched topics
- Webhook integration for Slack/Teams
- Priority highlighting in Daily Brief

#### 4. Visual Relationship Graph
**Current:** Relationships shown as tables

**Enhancement:** Interactive network graph visualization
- D3.js or Cytoscape.js integration
- Click nodes to navigate
- Filter by relationship type
- Strength indicated by edge thickness

### Intentional Design Decisions

**These are NOT limitations - they are deliberate choices:**

✅ **No detection rules** - Out of scope, reduces trust  
✅ **No predictive analytics** - Adds noise, reduces clarity  
✅ **No AI-generated summaries** - Unreliable, we generate analyst takes instead  
✅ **No real-time alerting** - Wrong workflow for daily intelligence review  
✅ **No org-specific risk scoring** - Personal platform, not org tool  

**Philosophy:** This platform is valuable BECAUSE it is calm, focused, and disciplined.

---

## 📦 Project Structure

```
Cyber-News-App/
├── .env                         # Environment variables (git-ignored)
├── .env.example                 # Environment template
├── .gitignore                   # Git ignore rules
├── .github/                     # GitHub workflows
│   └── workflows/
│       └── collect-news.yml     # Automated collector schedule
├── .streamlit/                  # Streamlit configuration
│
├── requirements.txt             # Python dependencies
│
├── README.md                    # This comprehensive guide
├── PHASE2_GUIDE.md              # Phase 2 implementation docs
├── PHASE3_GUIDE.md              # Phase 3 topic pages docs
├── cyber-knowledge-architecture.html  # Architecture visualization
│
├── knowledge_schema.sql         # Complete database schema (7 tables)
│
├── mdr_intelligence.py          # Phase 1: Intelligence processing engine (560 lines)
├── attack_mapping.py            # Phase 1: MITRE ATT&CK mapping (185 lines)
├── date_utils.py                # Phase 1: UTC/IST date handling (220 lines)
├── collector_mdr.py             # Phase 1+2: Main collector (390 lines)
│
├── entity_extractor.py          # Phase 2: Entity extraction (527 lines)
├── knowledge_graph.py           # Phase 2: Graph manager (480 lines)
├── knowledge_dashboard.py       # Phase 2: Knowledge UI (400 lines)
│
├── topic_page.py                # Phase 3: Topic pages (468 lines)
├── app_mdr.py                   # Main dashboard (603 lines)
│
└── __pycache__/                 # Python cache (git-ignored)
```

### File Descriptions

| File | Purpose | Phase | Lines | Status |
|------|---------|-------|-------|--------|
| `mdr_intelligence.py` | Event normalization, signal scoring, analyst take generation | 1 | 560 | ✅ Core |
| `attack_mapping.py` | MITRE ATT&CK tactics/techniques, Kill Chain, attack names | 1 | 185 | ✅ Core |
| `date_utils.py` | Centralized date parsing, UTC-to-IST conversion | 1 | 220 | ✅ Core |
| `collector_mdr.py` | RSS aggregation, CVE enrichment, intelligence processing | 1+2 | 390 | ✅ Core |
| `entity_extractor.py` | Extract threat actors, CVEs, technologies, malware, IOCs | 2 | 527 | ✅ Core |
| `knowledge_graph.py` | Topic management, relationships, IOC export, search | 2 | 480 | ✅ Core |
| `knowledge_dashboard.py` | Knowledge UI: overview, explorer, IOCs, SIEM templates | 2 | 400 | ✅ Core |
| `topic_page.py` | Living pages: timeline, relationships, IOCs, notes | 3 | 468 | ✅ Core |
| `app_mdr.py` | Main Streamlit dashboard with all views | 1+2+3 | 603 | ✅ Core |
| `knowledge_schema.sql` | Complete database schema (7 knowledge tables) | 2+3 | 150 | ✅ Core |

### Total Project Statistics

- **Total Lines of Code**: ~4,500 lines
- **Python Modules**: 9 core modules
- **Database Tables**: 8 tables (1 intelligence + 7 knowledge graph)
- **Entity Types Tracked**: 5 types (threat actors, CVEs, technologies, attack types, malware)
- **Entities in Dictionary**: 170+ entities
- **IOC Types**: 5 types (IPv4, domain, file hash, URL, email)
- **Export Formats**: 3 formats (CSV, JSON, TXT)
- **SIEM Integrations**: 4 platforms (Splunk, Sentinel, QRadar, Elastic)
- **View Modes**: 3 modes (Daily Brief, Knowledge Graph, Topic Pages)

---

## 🧪 Testing

### Test Collector
```bash
python collector_mdr.py
```

**Verify:**
- ✅ RSS feeds accessible
- ✅ NVD API responding (2-second rate limit)
- ✅ CISA KEV API responding
- ✅ Signal strength calculations
- ✅ MDR analyst takes generated
- ✅ Pattern tags extracted
- ✅ Database inserts successful

### Test Dashboard
```bash
streamlit run app_mdr.py
```

**Verify:**
- ✅ Filters working (signal, exploitation, event type)
- ✅ Sorting by exploitation priority
- ✅ Analyst takes displaying prominently
- ✅ Pattern trends in sidebar
- ✅ Review workflow (mark, bookmark, notes)

---

## 📈 Success Metrics

### Platform Working When:
- ✅ Daily review takes **5-10 minutes** (down from 30-60 minutes)
- ✅ Catch exploits **faster than colleagues**
- ✅ Pattern recognition **improves week-over-week**
- ✅ Meeting briefings become **effortless** (just share topic pages)
- ✅ Signal-to-noise ratio feels **manageable**
- ✅ Trust the High/Medium/Low scoring
- ✅ **Topic pages become your go-to reference** for any entity
- ✅ **Knowledge compounds** - notes from 6 months ago still valuable

### Key Performance Indicators

**Intelligence Processing:**
- **5-10 high-signal items/day** (filtered from 50-70 total)
- **<30 seconds** per item review time
- **95%+ accuracy** in signal strength classification
- **0 missed active exploits** (CISA KEV coverage)
- **3-5 seconds** to access any entity's full history via topic pages

**Knowledge Graph Metrics:**
- **350+ topics** tracked within 3 months
- **500+ relationships** discovered automatically
- **1,000+ IOCs** extracted and categorized
- **10-15 new entities** added daily
- **100% coverage** of mentioned threat actors, CVEs, and technologies

**Topic Page Usage:**
- **5-10 topic pages** visited per review session
- **2-3 clicks** average to find related information
- **Notes on 20-30 critical topics** within first month
- **Expertise tracking** on key technologies/threats
- **Meeting prep time** reduced from 20 mins to 5 mins

---

## 📚 Additional Resources

### Official Documentation
- **Phase 2 Guide**: [PHASE2_GUIDE.md](PHASE2_GUIDE.md) - Knowledge graph implementation details, entity extraction, IOC export
- **Phase 3 Guide**: [PHASE3_GUIDE.md](PHASE3_GUIDE.md) - Topic pages usage workflows, expertise tracking, meeting prep automation
- **Architecture Visualization**: [cyber-knowledge-architecture.html](cyber-knowledge-architecture.html) - Interactive system diagram

### External References

**Threat Intelligence:**
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Tactics, techniques, and procedures (TTPs)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) - Attack lifecycle model
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - KEV catalog
- [NVD CVE Database](https://nvd.nist.gov/) - National Vulnerability Database
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/) - Threat intelligence sharing standards

**MDR Best Practices:**
- [SANS MDR Guide](https://www.sans.org/white-papers/) - Managed Detection & Response framework
- [Gartner MDR Market Guide](https://www.gartner.com/) - Industry analysis and vendor landscape
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Security controls and maturity model

**Technologies:**
- [Streamlit Documentation](https://docs.streamlit.io/) - Dashboard framework
- [Supabase Documentation](https://supabase.com/docs) - PostgreSQL backend
- [pgvector Extension](https://github.com/pgvector/pgvector) - Vector similarity search
- [Python Feedparser](https://feedparser.readthedocs.io/) - RSS/Atom parsing

---

## 🤝 Contributing

This is a personal MDR platform designed for individual analysts. Contributions are welcome if they align with the core philosophy:

### Core Principles:
1. **Speed over completeness** - Daily review should take 5-10 minutes, not hours
2. **Signal over volume** - Filter noise aggressively, surface high-confidence intelligence
3. **Clarity over features** - Simple, focused tools beat complex, bloated dashboards
4. **Knowledge over alerts** - Build understanding and context, not panic and noise
5. **Calm intelligence** - Deliberate, methodical analysis - not real-time chaos

### How to Contribute:
1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Test thoroughly**: Run collector + dashboard + knowledge graph + topic pages
4. **Commit with clear messages**: Explain why, not just what
5. **Push to branch**: `git push origin feature/amazing-feature`
6. **Open Pull Request**: Detailed description of changes, screenshots if UI

### What We Accept:
✅ Bug fixes (especially filter logic, timezone issues, type errors)  
✅ Performance improvements (query optimization, caching)  
✅ Additional entity dictionaries (threat actors, technologies, attack types, malware)  
✅ New RSS feed sources (must be reliable, high-signal)  
✅ Documentation improvements (usage examples, troubleshooting)  
✅ IOC extraction enhancements (new patterns, better accuracy)  
✅ SIEM template additions (new platforms)  

### What We Don't Accept:
❌ Detection rules or signatures (out of scope)  
❌ Predictive analytics or ML models (adds noise)  
❌ Real-time alerting systems (wrong workflow)  
❌ Organization-specific features (personal tool)  
❌ Complexity that slows down daily workflow  
❌ AI-generated content (unreliable)  
❌ Features that contradict "calm intelligence" philosophy  

### Development Setup:
```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/Cyber-News-App.git
cd Cyber-News-App

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your Supabase credentials

# Test changes
python collector_mdr.py
streamlit run app_mdr.py
```

---



---

## 🙏 Acknowledgments

Built for speed. Optimized for signal. Designed for one analyst who needs to stay ahead.

**Special Thanks To:**
- **Open source threat intelligence community** - For sharing knowledge freely
- **RSS feed providers** - BleepingComputer, Krebs on Security, Schneier on Security, The Hacker News, Dark Reading
- **MITRE Corporation** - For ATT&CK framework and threat intelligence taxonomy
- **CISA** - For Known Exploited Vulnerabilities catalog
- **NVD/NIST** - For CVE enrichment data and CVSS scoring
- **Supabase** - For free PostgreSQL + pgvector hosting
- **Streamlit** - For rapid dashboard development framework
- **Python community** - For excellent libraries (feedparser, requests, beautifulsoup4)

**Core Philosophy:**  
*"If it doesn't help answer 'What changed in the threat landscape today?', it doesn't belong here."*

---


**Remember:** This is a personal tool for one MDR analyst. Customize it to match your workflow, threat landscape focus, and learning style.

---

## 🎯 Final Notes

### You've Built Something Valuable

You now have a **comprehensive three-phase threat intelligence platform** that:

1. **Processes** 50-70 articles daily into structured, analyst-ready intelligence (Phase 1)
2. **Extracts** 350+ entities and builds a knowledge graph automatically (Phase 2)
3. **Enables** one-click exploration of any threat actor, CVE, or technology (Phase 3)

### What Success Looks Like

- **Week 1**: Daily review drops from 60 minutes to 15 minutes
- **Week 2**: You start clicking entity buttons and exploring topic pages naturally
- **Month 1**: You have personal notes on 20+ critical topics
- **Month 3**: 350+ topics tracked, meeting prep takes 5 minutes instead of 20
- **Month 6**: You're the go-to person for threat intelligence in your team
- **Year 1**: Institutional knowledge that would take months to rebuild

### Your Workflow Now

**Every Morning (5-10 minutes):**
1. Run collector (automated via cron/Task Scheduler)
2. Open Daily Brief → Filter to High signal + Active exploits
3. Read 5-10 analyst takes (1-3 sentences each)
4. Click entity buttons to explore context (2-3 clicks to full history)
5. Add notes to critical topics
6. Mark reviewed and move on

**Meeting Prep (5 minutes):**
1. Search for relevant topic (e.g., "LockBit")
2. Open topic page → Timeline shows all 15 articles automatically
3. Review relationships → "LockBit exploits CVE-2024-1234 in VMware ESXi"
4. Check your notes from 2 months ago → Still relevant context
5. Export IOCs if needed → Ready for SIEM ingestion

### Stop When...

You're tempted to add features. **Seriously, stop.**

This platform is valuable BECAUSE it's focused. Resist the urge to add:
- ❌ Detection rules (not your job)
- ❌ Predictive analytics (adds noise)
- ❌ Real-time alerts (wrong workflow)
- ❌ AI-generated anything (unreliable)
- ❌ Organization-specific features (scope creep)

**The power is in the discipline.**

If you find yourself spending more than 15 minutes per day reviewing intelligence, you're doing it wrong. Go back to the filters, increase signal threshold, reduce time range.

**The goal is not completeness. The goal is staying ahead of threats with minimal overhead.**

---

**🎯 Built for analysts. By analysts. For staying ahead of threats.**

---

*Last updated: February 11, 2026*  
*Platform version: 3.0 (All Three Phases Complete)*  
*Total implementation: ~4,500 lines of Python across 9 modules*  
*Database: 8 tables (1 intelligence feed + 7 knowledge graph)*  
*Tracked entities: 170+ (65 threat actors, 60 technologies, 25 attack types, 20 malware families)*  
*Timezone: IST (UTC+5:30) throughout*  
*Export formats: CSV, JSON, TXT*  
*SIEM integrations: Splunk, Sentinel, QRadar, Elastic*

---

## ⚠️ Known Limitations

### pgvector on Supabase Free Tier
**Status:** Available but limited performance

**Current Reality:**
- pgvector extension is installed
- Embeddings are generated and stored
- **Semantic search is NOT core to the workflow**
- Free tier has performance constraints

**Recommendation:**
- Treat embeddings as **future-flagged feature**
- Current workflow uses exploitation status + signal strength filtering
- Semantic search can be added later when/if needed

### Date Handling (Critical)
**All feed dates MUST use centralized UTC parser**

Why this matters:
- Delta detection relies on consistent timestamps
- Weaponization speed calculations fail with mixed timezones
- Trend analysis drifts with inconsistent parsing

**Rule:** ONE date parser function. No exceptions.

### ID Collision Risk
**Current schema uses `INT PRIMARY KEY`**

**Risk:** RSS ingestion + retries + deduplication can cause collisions

**Recommended fix:**
```sql
-- Option 1: Auto-incrementing big integer
id BIGSERIAL PRIMARY KEY

-- Option 2: UUID (better for story evolution)
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

**When to apply:** Before production scale (easy one-line fix)

### "Unknown" Exploitation Status
**Current:** Single `unknown` status

**Limitation:** Doesn't capture *why* it's unknown

**Internal improvement** (no UI change needed):
- `unknown_no_data` - Insufficient information
- `unknown_conflicting_sources` - Reports contradict
- `unknown_early_report` - Too recent to confirm

**Why it matters:** Prevents subconsciously ignoring emerging threats

---

## 🚨 Troubleshooting

### No Items Collected
```bash
# Check RSS feeds
curl https://www.bleepingcomputer.com/feed/

# Check database connection
python -c "from supabase import create_client; import os; from dotenv import load_dotenv; load_dotenv(); print('OK')"
```

### NVD API Errors
- **Rate limit**: 2-second delay between requests (automatic)
- **Timeout**: Increase timeout in `enrich_cve_from_nvd()`
- **No data**: CVE may not be in NVD yet

### Signal Strength Always Low
- Check `signal_strength_reason` field
- Verify CISA KEV API access
- Review source confidence mapping

### Dashboard Not Loading
- Verify Supabase credentials in `.env`
- Check for old data without MDR fields (handled gracefully)
- Restart Streamlit: `Ctrl+C` then `streamlit run app_mdr.py`

---

## �️ Hardening Checklist

**Before trusting this system in production, complete these:**

### Data & Logic
- [ ] **Centralized feed date parser** (UTC only, single function)
- [ ] **UUID primary keys** (prevents ID collisions)
- [ ] **Mandatory signal_strength_reason** (always explain scoring)
- [ ] **Internal reason for unknown status** (track why classification failed)

### UX Improvements
- [ ] **"Changed since yesterday" toggle** (delta-driven view)
- [ ] **Visual badge for status escalation** (🟡 → 🔴 transitions)
- [ ] **Collapse Low-signal by default** (reduce noise)

### Operations
- [ ] **Idempotent collector runs** (safe to run multiple times)
- [ ] **Weekly database backup** (automated via Supabase)
- [ ] **Log exploitation status escalations** (audit trail)

**After completing this checklist, stop. You're done for a long time.**

---

## 🎯 Must-Have Features (High ROI, Low Risk)

### 1️⃣ "What Changed Since Yesterday?" View ⭐ **TOP PRIORITY**

**Why it's mandatory:**
- MDR work is delta-driven, not volume-driven
- Prevents re-reading the same story
- Matches analyst handover workflows

**What it shows:**
- New items
- Exploitation status escalations (🟡 → 🔴)
- Signal strength upgrades
- Newly added patterns or CVEs

**Implementation:**
```python
# Compare updated_at / changelog
flag is_update = TRUE
filter by last_seen < today
```

**If you add only ONE feature, add this.**

---

### 2️⃣ Exploitation Status Escalation Indicator 🔥

**You already track status — now surface transitions.**

**Example:**
```
🟡 PoC Available → 🔴 Actively Exploited (2 days later)
```

**Why it matters:**
- This is when analysts actually care
- Prevents missing silent escalations

**Minimal UI:**
- Arrow badge: `↑ ESCALATED`
- Color pulse animation
- "Escalated since last review" flag

---

### 3️⃣ Threat Velocity (Disclosure → Exploitation)

**You already compute weaponization_speed — make it visible.**

**Display:**
```
Velocity: 🔴 FAST (3 days)
Velocity: 🟡 MODERATE (10 days)
Velocity: 🟢 SLOW (30+ days)
```

**Why it's must-have:**
- Builds analyst intuition
- Helps separate "panic now" from "monitor"
- Pure MDR value

---

### 4️⃣ Confidence / Evidence Banner (Trust Feature)

**Surface why something is High signal.**

**Example:**
```
Evidence:
✔ CISA KEV listed
✔ Vendor advisory (Microsoft)
✔ Multiple independent reports (3)
✔ Technical PoC published
```

**Why it's mandatory:**
- Prevents blind trust in automation
- Lets you explain decisions in meetings
- You already store the data — just surface it

---

### 5️⃣ "Reviewed Since Last Run" Memory

**You already track reviewed_at.**

**Add:**
- "Unreviewed since last collector run" filter
- "Escalated after review" flag (critical!)

**Why it matters:**
- Prevents false sense of coverage
- Supports daily discipline
- Catches items that changed *after* you reviewed them

---

## 🟡 Strongly Recommended (But Optional)

### 6️⃣ Weekly Technique Heatmap

**Simple bar chart:**
- OAuth abuse (18 items)
- RTF exploits (12 items)
- API abuse (9 items)
- Ransomware (7 items)

**Why:** Strategic awareness, no prediction, no noise.

---

### 7️⃣ Historical Recall ("Have we seen this before?")

**Button:** "Show similar events (last 90 days)"

**Why:**
- Great for briefings
- Helps spot recycled tradecraft
- Uses existing embeddings

---

## 🚫 What NOT to Add (Critical Boundaries)

**You are at the most dangerous point of a good project.**

**Do NOT add these features** (even if tempting):

❌ **Detection rules** - Not your job  
❌ **"Recommended actions"** - Reduces trust  
❌ **Org-specific risk scoring** - Out of scope  
❌ **Predictive analytics** - Adds noise  
❌ **AI-hallucinated summaries** - Unreliable  
❌ **Real-time alerting** - Wrong workflow  

**Why these are dangerous:**
- Reduce trust in the system
- Slow down scanning
- Add maintenance burden
- Drift from core value: *"What changed in the threat landscape today?"*

**Your system is valuable BECAUSE it is calm and disciplined.**

**Stop after the Must-Have features. Seriously.**

---

## �📚 Additional Resources

### Threat Intelligence
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE Database](https://nvd.nist.gov/)

### MDR Best Practices
- [SANS MDR Guide](https://www.sans.org/white-papers/)
- [Gartner MDR Market Guide](https://www.gartner.com/)

---

## 📝 License

MIT License - Use freely for personal MDR work.

---

## 🙏 Acknowledgments

Built for speed. Optimized for signal. Designed for one analyst who needs to stay ahead.

**Core Philosophy:**  
If it doesn't help answer "What changed in the threat landscape today?", it doesn't belong here.

---

## 📧 Support

For issues, questions, or contributions, please open an issue in the repository.

**Remember:** This is a personal tool for one MDR analyst. Customize it to match your workflow and threat landscape focus.

---

**🎯 Built for analysts. By analysts. For staying ahead of threats.**
