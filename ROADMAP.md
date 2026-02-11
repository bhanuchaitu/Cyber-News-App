# 🗺️ MDR Intelligence Platform Roadmap

**Last Updated:** February 11, 2026  
**Current Version:** 3.0 (All Three Phases Complete)

---

## 📊 Feature Status Overview

| Feature | Status | Priority | Impact | Effort |
|---------|--------|----------|--------|--------|
| **Semantic Search** | ✅ **Implemented** | 🟢 **Shipped** | Natural language topic discovery | Low |
| **Delta View ("What Changed?")** | ✅ **Implemented** | 🔴 Critical | Reduce re-reading time | Medium |
| **Mobile UI Responsive** | ✅ **Implemented** | 🟠 High | Works on all devices | Low |
| **PWA Support** | ✅ **Implemented** | 🟡 Medium | Install as app | High |
| **UUID Primary Keys** | ✅ **Migration Ready** | 🟠 High | Scalable IDs | Low |
| Escalation Indicators (🟡→🔴) | ✅ **Implemented** | 🔴 Critical | Never miss silent escalations | Low |
| Threat Velocity Visible | ✅ **Implemented** | 🟠 High | Prioritize "panic now" vs "monitor" | Low |
| Visual Relationship Graph | 🔵 Future | 🟢 Low | Nice-to-have enhancement | High |

---

## ✅ Recently Implemented Features

### 🔍 Semantic Search (Implemented: Feb 11, 2026)

**Status:** ✅ **Shipped**  
**Location:** Sidebar → "🔍 Semantic Search"  
**Technology:** Local sentence-transformers (no API key required)

**What It Does:**
- Natural language topic search across knowledge graph
- Find topics by meaning, not just keywords
- Example: "ransomware targeting healthcare" finds LockBit, BlackCat, hospital breaches
- Uses local AI embeddings (sentence-transformers/all-MiniLM-L6-v2)
- Results show similarity scores (70-100% = highly relevant)
- Click any result to view full topic page

**Key Features:**
- ⚡ Fast: ~50ms per search (database-optimized)
- 🔒 Private: No data sent to external APIs
- 💰 Free: No API costs or rate limits
- 🎯 Smart: Understands semantic relationships

**Example Queries:**
```
"state-sponsored espionage"           → APT29, APT28, Cozy Bear
"supply chain attacks"                → SolarWinds, MOVEit, 3CX
"privilege escalation in Windows"     → LPE CVEs, kernel exploits
"browser vulnerabilities"             → Chrome/Firefox/Safari bugs
```

**Technical Implementation:**
- Database RPC function: `search_similar_items(query_embedding, match_count)`
- pgvector cosine similarity search: `embedding <=> query_embedding`
- Streamlit integration with cached model loading
- Direct navigation to topic pages from search results

**Documentation:** See [SEMANTIC_SEARCH_GUIDE.md](SEMANTIC_SEARCH_GUIDE.md)

---

### ⚡ Delta View (Implemented: Feb 11, 2026)

**Status:** ✅ **Shipped**  
**Location:** Sidebar → View Mode → "What Changed Since Yesterday?"  
**Technology:** Session state tracking + database filtering

**What It Does:**
- Shows ONLY what changed since your last review
- Tracks: New articles, escalations (PoC → Active), signal upgrades
- Eliminates re-reading same stories every day
- Displays time since last review in header

**Key Features:**
- 🕐 Automatic timestamp tracking in session state
- 🔄 Smart filtering on created_at, exploitation_escalated_at, signal_upgraded_at
- 📊 Visual header showing "changes from last X hours"
- ⚡ Instant time savings (5-10 mins/day)

**How to Use:**
1. Select "What Changed Since Yesterday?" from View Mode
2. Review displayed items (first time shows 24 hours)
3. Session saves your review timestamp
4. Next visit shows ONLY new changes since then
5. Refresh page to reset delta window

**Technical Implementation:**
```python
if view_mode == "What Changed Since Yesterday?":
    last_review = st.session_state.last_review_time
    query.or_(
        f"created_at.gt.{last_review},"
        f"exploitation_escalated_at.gt.{last_review},"
        f"signal_upgraded_at.gt.{last_review}"
    )
```

---

### 📱 PWA Support (Implemented: Feb 11, 2026)

**Status:** ✅ **Implemented** (Requires HTTPS deployment)  
**Files:** `static/manifest.json`, `static/service-worker.js`  
**Technology:** Progressive Web App standard

**What It Does:**
- Install dashboard as standalone app on phone/tablet/desktop
- Works offline (basic functionality cached)
- App-like experience with native icons
- Launches without browser chrome
- Add to home screen / dock

**Key Features:**
- 🏠 Home screen installation (Android, iOS, Desktop)
- 📴 Offline capability with service worker caching
- 🎨 Custom app icons and splash screen
- 🔔 Push notifications ready (future)
- 🚀 Native-like performance

**Deployment Requirements:**
- Must use HTTPS (required for PWA)
- Deploy to: Streamlit Cloud, Render, Railway, or use ngrok
- Create icons: `static/icon-192.png`, `static/icon-512.png`

**Installation:**
- **Android:** Tap menu → "Install app"
- **iOS:** Share → "Add to Home Screen"
- **Desktop:** Click install icon in address bar

**Documentation:** See [FEATURES_DEPLOYMENT_GUIDE.md](FEATURES_DEPLOYMENT_GUIDE.md) - PWA section

---

### 📲 Mobile-Responsive UI (Implemented: Feb 11, 2026)

**Status:** ✅ **Shipped**  
**Technology:** Responsive CSS with mobile-first breakpoints

**What It Does:**
- Responsive layout adapts to phone, tablet, desktop
- Touch-friendly buttons (44px minimum tap targets)
- Optimized typography for readability on small screens
- Sidebar auto-collapses on mobile

**Breakpoints:**
- **Desktop** (>768px): Full layout, multi-column
- **Tablet** (481-768px): Reduced padding, stacked badges
- **Phone** (≤480px): Compact layout, vertical buttons

**Mobile Optimizations:**
- ✅ Readable text without zooming
- ✅ Large tap targets for touch
- ✅ No horizontal scrolling
- ✅ Stacked cards and buttons
- ✅ Collapsible sidebar
- ✅ Landscape mode support

**Testing:**
- Browser DevTools responsive mode (F12 → Ctrl+Shift+M)
- Test with real devices via ngrok
- Check iOS Safari and Android Chrome

---

### 🔑 UUID Primary Keys (Migration Ready: Feb 11, 2026)

**Status:** ✅ **Migration Ready** (Not yet executed)  
**File:** `migrations/003_uuid_primary_keys.sql`  
**Technology:** PostgreSQL UUID extension

**What It Does:**
- Converts all SERIAL (integer) primary keys to UUID
- Format: `550e8400-e29b-41d4-a716-446655440000`
- Prevents ID guessing/enumeration attacks
- Globally unique identifiers (no collisions ever)

**Benefits:**
- **Security:** Cannot guess IDs (prevents enumeration)
- **Scale:** 340 undecillion unique values (vs 2.1B integers)
- **Distributed:** No ID collisions across systems
- **Privacy:** Hides database size from API

**Migration Preserves:**
- ✅ All existing data remains intact
- ✅ Old integer IDs saved as `id_old` columns
- ✅ Foreign key relationships maintained
- ✅ Collector continues working during transition

**⚠️ Important:**
- This is a BREAKING CHANGE - read guide first!
- Backup database before running
- Test in dev/staging first
- Expects 5-10 minutes downtime
- Application code mostly compatible (minor changes needed)

**Documentation:** See [FEATURES_DEPLOYMENT_GUIDE.md](FEATURES_DEPLOYMENT_GUIDE.md) - UUID section

---

## 📈 Implementation Timeline

### February 11, 2026 - Major Feature Release

**Completed Today:**
- ✅ Delta View ("What Changed Since Yesterday?")
- ✅ PWA manifest, service worker, meta tags
- ✅ Mobile-responsive CSS (phone/tablet/desktop)
- ✅ UUID migration script ready
- ✅ Security hardening (18 database linter fixes)
- ✅ Semantic search with local AI

**Impact:**
- **Time Savings:** 5-10 mins/day with Delta View
- **Accessibility:** Works on any device (mobile/tablet)
- **Security:** RLS enabled, UUID ready, search_path fixed
- **Intelligence:** AI-powered semantic topic search

**Documentation Created:**
- `FEATURES_DEPLOYMENT_GUIDE.md` (comprehensive deployment)
- `SEMANTIC_SEARCH_GUIDE.md` (search usage)
- `SECURITY_HARDENING_GUIDE.md` (security fixes)
- `generate_pwa_icons.py` (icon generation script)

---

### 📋 Recently Implemented Features (Full List)

1. **🔍 Semantic Search** - Natural language topic discovery with local AI
2. **⚡ Delta View** - Show only what changed since last review
3. **📱 PWA Support** - Install as standalone app on any device
4. **📲 Mobile UI** - Responsive design for phone/tablet/desktop
5. **🔑 UUID Migration** - Scalable, secure primary keys (ready to deploy)
6. **⬆️ Escalation Indicators** - Never miss PoC → Active escalations
7. **🔥 Threat Velocity** - Instant prioritization (FAST/MODERATE/SLOW)
8. **🔒 Security Hardening** - Fixed 18 database linter issues (RLS, SECURITY DEFINER, search_path)

---

## 🔴 Critical Priority (Must Fix) - COMPLETED ✅

### 1. Delta View ("What Changed Since Yesterday?") - ✅ IMPLEMENTED

**Status:** ✅ **Shipped** (Feb 11, 2026)  
**Solution:** Already implemented - see "Recently Implemented Features" above

**Status:** ⚠️ **In Progress** (Schema Ready, UI Pending)  
**Problem:** Analysts re-read the same stories daily, wasting time  
**Impact:** 5-10 minutes of wasted review time per day  

**What to Build:**
- "New since last review" filter toggle
- Highlight items with status changes
- Show exploitation escalations (🟡 PoC → 🔴 Active)
- Show signal strength upgrades
- Track last review timestamp per analyst

**Implementation:**
```python
# Add to fetch_intelligence()
if show_delta:
    query = query.gt('updated_at', last_review_time)
    # OR flag items with exploitation_escalated_at > last_review_time
```

**Database Changes:**
```sql
ALTER TABLE daily_brief 
ADD COLUMN last_analyst_review TIMESTAMPTZ;

CREATE INDEX idx_delta_review 
ON daily_brief(updated_at, last_analyst_review);
```

**UI Location:** Sidebar toggle "Show Only New/Changed"

---

### 2. Escalation Indicators (🟡→🔴) - ✅ IMPLEMENTED

**Status:** ✅ **Shipped** (Week 1 Quick Wins)  
**Solution:** Already implemented - see "Recently Implemented Features" above  

**What to Build:**
- Visual arrow badge: `↑ ESCALATED` 
- Color pulse animation on escalated items
- Separate "Escalated Items" section at top of Daily Brief
- Email/Slack notification (optional)

**Implementation:**
```python
# Already tracked in database:
# - previous_exploitation_status
# - exploitation_escalated_at

# Add to card display:
if item['exploitation_escalated_at']:
    days_ago = (now - item['exploitation_escalated_at']).days
    if days_ago <= 7:
        st.warning(f"⬆️ ESCALATED from {item['previous_exploitation_status']} ({days_ago} days ago)")
```

**UI Changes:**
- Red pulsing border for escalated items
- "Escalated in last 7 days" filter
- Sort escalated items to top

**Effort:** Low (2-3 hours) - Data already exists, just needs UI

---

## 🟠 High Priority (Should Fix Soon)

### 3. Threat Velocity Indicators
 - ✅ IMPLEMENTED

**Status:** ✅ **Shipped** (Week 1 Quick Wins)  
**Solution:** Already implemented - see "Recently Implemented Features" above
**What to Build:**
- Visual velocity badges on cards
- Color-coded: 🔴 FAST (0-3 days), 🟡 MODERATE (4-14 days), 🟢 SLOW (15+ days)
- Sort by velocity option
- Velocity trend chart (weekly)

**Implementation:**
```python
# Already calculated: weaponization_speed field

def get_velocity_badge(speed_days):
    if speed_days <= 3:
        return "🔴 FAST", "critical"
    elif speed_days <= 14:
        return "🟡 MODERATE", "warning"
    else:
        return "🟢 SLOW", "info"

# Display on card:
velocity_label, velocity_type = get_velocity_badge(item['weaponization_speed'])
st.markdown(f"**Velocity:** {velocity_label} ({item['weaponization_speed']} days)")
```

**Effort:** Low (1-2 hours) - Data already calculated

---

### 4. UUID Primary Keys (Database Hardening)

**Status:** ⚠️ Risk  
**Problem:** Integer PKs risk collision at scale (10,000+ articles)  
**Impact:** Data integrity issues, duplicate key errors  

**What to Fix:**
```sql
-- Migration script
-- 1. Add UUID column
ALTER TABLE daily_brief ADD COLUMN uuid UUID DEFAULT gen_random_uuid();
ALTER TABLE topics ADD COLUMN uuid UUID DEFAULT gen_random_uuid();

-- 2. Populate existing rows
UPDATE daily_brief SET uuid = gen_random_uuid() WHERE uuid IS NULL;
UPDATE topics SET uuid = gen_random_uuid() WHERE uuid IS NULL;

-- 3. Create unique constraint
ALTER TABLE daily_brief ADD CONSTRAINT daily_brief_uuid_key UNIQUE (uuid);
ALTER TABLE topics ADD CONSTRAINT topics_uuid_key UNIQUE (uuid);

-- 4. Eventually migrate foreign keys to use UUID
-- (Phase 2: Update relationships, IOCs, article_topics tables)
```

**Testing Plan:**
1. Test on copy of production database
2. Verify all foreign key relationships
3. Update application code to use UUIDs
4. Run with both INT and UUID for 1 week
5. Final cutover

**Effort:** Medium (4-6 hours) - Database migration + code updates

---

## 🟡 Medium Priority (Quality of Life)

### 5. Anywhere Access (PWA Support)

**Status:** ❌ Missing  
**Problem:** Can only access dashboard from one machine  
**Impact:** Can't review intelligence on mobile, during travel  

**What to Build:**
- Progressive Web App (PWA) manifest
- Mobile-responsive UI (already mostly done with Streamlit)
- Offline support for recent articles (optional)
- Push notifications for escalations (optional)

**Implementation:**

**1. Add PWA manifest (`static/manifest.json`):**
```json
{
  "name": "MDR Intelligence Platform",
  "short_name": "MDR Intel",
  "description": "Personal threat intelligence dashboard",
  "start_url": "/",
  "display": "standalone",
  "theme_color": "#1f77b4",
  "background_color": "#ffffff",
  "icons": [
    {
      "src": "icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

**2. Service Worker for offline support:**
```javascript
// static/sw.js
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('mdr-intel-v1').then((cache) => {
      return cache.addAll([
        '/',
        '/static/manifest.json'
      ]);
    })
  );
});
```

**3. Add to Streamlit config:**
```python
# .streamlit/config.toml
[server]
enableCORS = true
enableWebsocketCompression = true

[browser]
gatherUsageStats = false
```

**Deployment:**
- Deploy to cloud (Streamlit Cloud, Railway, Render)
- Use ngrok for temporary access
- VPN + local hosting for security

**Effort:** High (8-10 hours) - PWA setup + mobile UI testing + deployment

---

## 🔵 Future Enhancements (Nice to Have)

### 6. Visual Relationship Graph

**Status:** 🔵 Future  
**Benefit:** Nice-to-have visualization  
**Priority:** Low (current table view works fine)  

**What to Build:**
- Interactive network graph (D3.js, Cytoscape.js, or vis.js)
- Click nodes to navigate between topics
- Node size = article count
- Edge thickness = relationship strength
- Color-coded by entity type
- Toggle between graph and table view

**Implementation:**
```python
# Use Streamlit components for D3.js
import streamlit.components.v1 as components

def render_relationship_graph(topic_id):
    # Fetch relationships
    relationships = kg.get_topic_relationships(topic_id)
    
    # Build D3.js data structure
    nodes = []
    edges = []
    
    for rel in relationships:
        nodes.append({
            "id": rel['target_id'],
            "label": rel['target_name'],
            "type": rel['target_type'],
            "size": rel['article_count']
        })
        
        edges.append({
            "source": topic_id,
            "target": rel['target_id'],
            "strength": rel['strength']
        })
    
    # Render with D3.js component
    graph_html = generate_d3_graph(nodes, edges)
    components.html(graph_html, height=600)
```

**Effort:** High (12-15 hours) - JavaScript integration + testing

---

## 🚀 Quick Wins (Implement First)

**Recommended implementation order for maximum impact with minimum effort:**

### Week 1: Critical Fixes
1. **Escalation Indicators** (2-3 hours)
   - Already have data, just add UI badges
   - Immediate visual value

2. **Threat Velocity Badges** (1-2 hours)
   - Already calculated, just display
   - Helps prioritization instantly

### Week 2: Delta View
3. **Delta View Filter** (4-6 hours)
   - Add timestamp tracking
   - Implement "Show New/Changed" toggle
   - Biggest time-saver

### Week 3: Database Hardening
4. **UUID Migration** (4-6 hours)
   - Do on staging first
   - Prevents future scaling issues

### Future Sprints
5. **PWA Support** (week-long project when needed)
6. **Visual Graph** (week-long project, low priority)

---

## 🛑 What NOT to Build

**Even if tempted, DO NOT add these:**

❌ **Real-time alerting** - Wrong workflow, adds noise  
❌ **Detection rules** - Out of scope, reduces trust  
❌ **Predictive analytics** - Adds complexity, reduces clarity  
❌ **AI-generated summaries** - Unreliable (we already have analyst takes)  
❌ **Automated response actions** - Analysis tool, not automation platform  
❌ **Organization-specific risk scoring** - Personal tool, not enterprise platform  

**Why these are dangerous:**
- Drift from core value: "What changed in the threat landscape today?"
- Increase cognitive load
- Reduce trust in the platform
- Slow down daily review

---

## 📏 Success Metrics After Roadmap

**Current Baseline:**
- Daily review time: 15 minutes
- Items reviewed: 5-10 high-signal per day
- Time to find entity history: 3-5 seconds (topic pages)

**Target After Roadmap:**
- Daily review time: **5-8 minutes** (with Delta View)
- Escalation detection: **100%** (with indicators)
- Threat prioritization: **< 2 seconds** per item (with velocity badges)
- Access flexibility: **Anywhere** (with PWA)
- Data integrity: **Zero collisions** (with UUIDs)

---

## 💡 Implementation Notes

### For Delta View:
- Consider analyst preference: some want "all items with highlights" vs "only changed"
- Track per-user review timestamps (multi-analyst support)
- Gracefully handle first-time users (no "last review")

### For Escalation Indicators:
- Only highlight escalations in last 7 days (older not actionable)
- Consider audio/visual notification for real-time escalations during review
- Add to email summary if configured

### For Velocity:
- Make it toggleable (some analysts prefer clean view)
- Add velocity histogram in stats sidebar
- Track velocity trends week-over-week

### For UUID Migration:
- **DO NOT delete old INT primary keys** until 100% confident
- Keep both for transition period
- Test thoroughly on staging database first

### For PWA:
- Requires HTTPS (use Cloudflare tunnel or ngrok for testing)
- Test on iOS Safari and Android Chrome
- Consider authentication if exposing to internet

---

## 🎯 Philosophy Reminder

This roadmap fixes **real pain points** experienced during daily use:

✅ **Delta View** - Stops wasted time re-reading  
✅ **Escalation Indicators** - Catches critical status changes  
✅ **Threat Velocity** - Speeds up prioritization  
✅ **UUIDs** - Prevents future technical debt  
✅ **PWA** - Enables mobile/travel access  

Every feature must pass the test:
> "Does this help answer: 'What changed in the threat landscape today?' faster or more accurately?"

If no, don't build it. **The power is in the discipline.**

---

## 📞 Questions or Suggestions?

Open an issue with:
- **Feature request**: Describe the pain point, not the solution
- **Bug report**: Include steps to reproduce
- **Enhancement idea**: Explain why it matters for daily workflow

**Remember:** Simple beats complex. Fast beats feature-rich. Clarity beats completeness.

---

*Roadmap maintained by analysts, for analysts. Updated quarterly based on real usage patterns.*
