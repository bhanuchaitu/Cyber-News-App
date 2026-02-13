"""
Personal MDR Cyber Threat Intelligence Dashboard
Optimized for 20-30 second scanning and rapid decision-making
FIXED: Resolves blank screen issues when changing filters
"""

import streamlit as st
from datetime import datetime, timedelta, timezone
from supabase import create_client
import os
from dotenv import load_dotenv
import html
from knowledge_graph import KnowledgeGraphManager
from knowledge_dashboard import render_knowledge_dashboard
from date_utils import format_ist_datetime
from topic_page import render_topic_page
from entity_extractor import EntityExtractor

# Try to import sentence transformers - if it fails, semantic search will be disabled
try:
    from sentence_transformers import SentenceTransformer
    SEMANTIC_SEARCH_AVAILABLE = True
except Exception as e:
    SentenceTransformer = None
    SEMANTIC_SEARCH_AVAILABLE = False
    print(f"⚠️ Semantic search disabled: {str(e)}")

load_dotenv()

# =========================================================
# PAGE CONFIG - Must be first Streamlit command
# =========================================================

st.set_page_config(
    page_title="MDR Threat Intelligence",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>
:root {
    --mdr-red: #ff4444;
    --mdr-orange: #ff8800;
    --mdr-green: #00cc88;
    --mdr-blue: #0088ff;
    --mdr-purple: #8844ff;
    --bg-dark: #0e1117;
    --bg-card: #1a1d24;
    --border: #2d3139;
}

/* Exploitation badges */
.exploit-active {
    background: linear-gradient(135deg, #ff4444, #cc0000);
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 14px;
    display: inline-block;
    margin-right: 8px;
    box-shadow: 0 0 20px rgba(255,68,68,0.4);
}

.exploit-poc {
    background: linear-gradient(135deg, #ff8800, #cc6600);
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 14px;
    display: inline-block;
    margin-right: 8px;
}

.exploit-theoretical {
    background: linear-gradient(135deg, #00cc88, #00aa66);
    color: white;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 14px;
    display: inline-block;
    margin-right: 8px;
}

/* Signal strength */
.signal-high {
    background: linear-gradient(135deg, #ff4444, #ff6666);
    color: white;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}

.signal-medium {
    background: linear-gradient(135deg, #ff8800, #ffaa00);
    color: white;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}

.signal-low {
    background: #444;
    color: #aaa;
    padding: 6px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}

/* Intelligence card */
.intel-card {
    background: var(--bg-card);
    border: 2px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    transition: all 0.2s;
}

.intel-card:hover {
    border-color: var(--mdr-blue);
    transform: translateY(-2px);
}

.intel-card-critical {
    border-left: 6px solid var(--mdr-red);
    box-shadow: 0 0 30px rgba(255,68,68,0.2);
}

.intel-card-warning {
    border-left: 6px solid var(--mdr-orange);
}

/* Analyst take */
.mdr-take {
    background: linear-gradient(
        135deg,
        rgba(0,136,255,0.15),
        rgba(136,68,255,0.15)
    );
    border-left: 4px solid var(--mdr-blue);
    padding: 16px;
    margin: 16px 0;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 500;
    line-height: 1.6;
    color: #e0e0e0;
}

.delta-badge {
    background: linear-gradient(135deg, #8844ff, #6633cc);
    color: white;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    display: inline-block;
    margin-right: 6px;
}

.event-chip {
    background: rgba(255,255,255,0.1);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    display: inline-block;
    margin-right: 8px;
    border: 1px solid rgba(255,255,255,0.2);
}

.meta-info {
    display: flex;
    gap: 16px;
    margin-top: 12px;
    font-size: 13px;
    color: #888;
    flex-wrap: wrap;
}

.meta-item {
    display: inline-flex;
    align-items: center;
    gap: 4px;
}

.stat-card {
    background: var(--bg-card);
    border: 2px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}

.stat-value {
    font-size: 36px;
    font-weight: 700;
    margin: 8px 0;
}

.stat-label {
    font-size: 13px;
    color: #888;
    text-transform: uppercase;
    font-weight: 600;
}

/* ========================================= */
/* MOBILE RESPONSIVE DESIGN                 */
/* ========================================= */

/* Tablets and below (768px) */
@media (max-width: 768px) {
    .intel-card {
        padding: 15px;
        margin-bottom: 15px;
    }
    
    .exploit-active, .exploit-poc, .exploit-theoretical {
        padding: 6px 12px;
        font-size: 12px;
        display: block;
        margin: 5px 0;
        text-align: center;
    }
    
    .signal-high, .signal-medium, .signal-low {
        padding: 4px 8px;
        font-size: 10px;
        display: inline-block;
    }
    
    .stat-value {
        font-size: 24px;
    }
    
    .stat-label {
        font-size: 11px;
    }
    
    /* Stack entity buttons vertically on mobile */
    .stButton button {
        width: 100%;
        margin: 4px 0 !important;
    }
    
    /* Adjust card title */
    h3 {
        font-size: 18px !important;
    }
    
    /* Sidebar adjustments - auto-collapse on mobile */
    [data-testid="stSidebar"] {
        min-width: 280px;
    }
}

/* Mobile phones (480px) */
@media (max-width: 480px) {
    .intel-card {
        padding: 12px;
        border-radius: 8px;
    }
    
    .exploit-active, .exploit-poc, .exploit-theoretical {
        font-size: 11px;
        padding: 5px 10px;
    }
    
    .signal-high, .signal-medium, .signal-low {
        font-size: 9px;
        padding: 3px 6px;
    }
    
    .stat-value {
        font-size: 20px;
    }
    
    h1 {
        font-size: 24px !important;
    }
    
    h2 {
        font-size: 20px !important;
    }
    
    h3 {
        font-size: 16px !important;
    }
    
    /* Reduce padding on small screens */
    .main .block-container {
        padding: 1rem !important;
    }
}

/* Touch-friendly buttons */
@media (hover: none) and (pointer: coarse) {
    .stButton button {
        min-height: 44px;
        font-size: 14px;
    }
    
    /* Larger tap targets */
    a, button {
        min-height: 44px;
        min-width: 44px;
    }
}

/* Dark mode support (native) */
@media (prefers-color-scheme: dark) {
    :root {
        --bg-dark: #000000;
        --bg-card: #111111;
    }
}
</style>
""", unsafe_allow_html=True)

# =========================================================
# DATABASE CONNECTION
# =========================================================

@st.cache_resource
def init_supabase():
    """Initialize Supabase client (cached, loads once per session)"""
    try:
        # Try Streamlit Cloud secrets first
        url = st.secrets.get("SUPABASE_URL")
        key = st.secrets.get("SUPABASE_KEY")
    except Exception:
        # Fall back to .env
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        st.error("⚠️ Missing Supabase credentials!")
        st.info("""
        **For Streamlit Cloud:**
        1. Go to App Settings → Secrets
        2. Add:
        ```toml
        SUPABASE_URL = "https://your-project.supabase.co"
        SUPABASE_KEY = "your-anon-key"
        ```
        
        **For Local Development:**
        Create a `.env` file with:
        ```
        SUPABASE_URL=https://your-project.supabase.co
        SUPABASE_KEY=your-anon-key
        ```
        """)
        st.stop()
        
    return create_client(url, key)

@st.cache_resource
def init_embedding_model():
    """Initialize sentence-transformers model (cached, loads once)"""
    if not SEMANTIC_SEARCH_AVAILABLE or SentenceTransformer is None:
        return None
    try:
        return SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    except Exception as e:
        print(f"Failed to load embedding model: {str(e)}")
        return None

# Initialize connections
supabase = init_supabase()

# Initialize session state
if 'embed_model' not in st.session_state:
    st.session_state.embed_model = None
if 'last_review_time' not in st.session_state:
    st.session_state.last_review_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

# =========================================================
# HEADER
# =========================================================

st.markdown("# 🎯 MDR Threat Intelligence")
st.markdown(
    "**Personal cyber threat intelligence for MDR analysts** — "
    "Optimized for 20-30 second scanning"
)

# =========================================================
# SIDEBAR FILTERS
# =========================================================

st.sidebar.markdown("### ⚙️ Intelligence Filters")

view_mode = st.sidebar.radio(
    "🌟 View Mode",
    ["All Intelligence", "What Changed Since Yesterday?", "Unreviewed Only", "Knowledge Graph"],
    index=0,
    key="view_mode_selector"
)

signal_filter = st.sidebar.multiselect(
    "Signal Strength",
    ["High", "Medium", "Low"],
    default=["High", "Medium"],
    key="signal_filter_selector"
)

exploit_filter = st.sidebar.multiselect(
    "Exploitation Status",
    ["actively_exploited", "poc_available", "theoretical", "unknown"],
    default=["actively_exploited", "poc_available"],
    key="exploit_filter_selector"
)

time_range = st.sidebar.selectbox(
    "Time Range",
    ["Today", "Last 3 Days", "Last 7 Days", "Last 30 Days"],
    index=2,
    key="time_range_selector"
)

show_reviewed = st.sidebar.checkbox("Show Reviewed Items", value=False, key="show_reviewed_checkbox")

source_confidence_filter = st.sidebar.multiselect(
    "Source Confidence",
    ["High", "Medium", "Low"],
    default=["High", "Medium"],
    key="confidence_filter_selector"
)

st.sidebar.markdown("---")

# =========================================================
# SEMANTIC SEARCH (Phase 2)
# =========================================================

if SEMANTIC_SEARCH_AVAILABLE:
    st.sidebar.markdown("### 🔍 Semantic Search")
    st.sidebar.markdown("*Find topics by meaning, not just keywords*")

    search_query = st.sidebar.text_input(
        "Search topics",
        placeholder="e.g., ransomware targeting healthcare",
        help="Uses local AI embeddings — no API key needed!",
        key="search_query_input"
    )
    
    if search_query:
        with st.sidebar:
            with st.spinner("🧠 Searching..."):
                try:
                    # Initialize embedding model only when needed
                    if st.session_state.embed_model is None:
                        st.session_state.embed_model = init_embedding_model()
                    
                    if st.session_state.embed_model is not None:
                        # Generate embedding and convert to list
                        embedding_result = st.session_state.embed_model.encode(search_query)
                        query_embedding: list = embedding_result.tolist() if hasattr(embedding_result, 'tolist') else list(embedding_result)  # type: ignore[union-attr]
                        
                        # Search
                        search_results = supabase.rpc(
                            'search_similar_items',
                            {
                                'query_embedding': query_embedding,
                                'match_count': 5
                            }
                        ).execute()
                        
                        # Type checking for search results
                        results_data: list = search_results.data if isinstance(search_results.data, list) else []
                        if len(results_data) > 0:
                            st.markdown("**🎯 Top Matches:**")
                            for raw_result in results_data:
                                result: dict = dict(raw_result) if not isinstance(raw_result, dict) else raw_result
                                similarity_pct = int(float(result.get('similarity', 0)) * 100)
                                
                                if similarity_pct >= 70:
                                    color = '🟢'
                                elif similarity_pct >= 50:
                                    color = '🟡'
                                else:
                                    color = '🔵'
                                
                                if st.button(
                                    f"{color} {result.get('name', 'Unknown')} ({similarity_pct}%)",
                                    key=f"search_{result.get('id', 0)}",
                                    help=f"Type: {result.get('type', 'Unknown')}\nSimilarity: {similarity_pct}%"
                                ):
                                    st.session_state.viewing_topic = result.get('id')
                                    st.rerun()
                        else:
                            st.info("No similar topics found.")
                except Exception as e:
                    st.error(f"Search error: {str(e)[:100]}")

st.sidebar.markdown("---")

# =========================================================
# KNOWLEDGE GRAPH VIEW (Phase 2)
# =========================================================

if view_mode == "Knowledge Graph":
    kg_manager = KnowledgeGraphManager(supabase)
    render_knowledge_dashboard(kg_manager)
    st.stop()

# =========================================================
# TOPIC PAGE VIEW (Phase 3)
# =========================================================

if 'viewing_topic' in st.session_state and st.session_state.viewing_topic:
    kg_manager = KnowledgeGraphManager(supabase)
    render_topic_page(kg_manager, str(st.session_state.viewing_topic))
    st.stop()

# =========================================================
# FETCH DATA WITH LOADING STATE
# =========================================================

def fetch_intelligence(
    signal_filter=None,
    exploit_filter=None,
    time_range="Last 7 Days",
    show_reviewed=False,
    source_confidence_filter=None,
    view_mode="All Intelligence"
):
    """Fetch intelligence items with applied filters"""
    try:
        query = supabase.table("daily_brief").select("*")
        
        # Apply filters only if not empty
        if signal_filter and len(signal_filter) > 0:
            query = query.in_("signal_strength", signal_filter)
        
        if exploit_filter and len(exploit_filter) > 0:
            query = query.in_("exploitation_status", exploit_filter)
        
        if source_confidence_filter and len(source_confidence_filter) > 0:
            query = query.in_("source_confidence", source_confidence_filter)
        
        if not show_reviewed:
            query = query.is_("reviewed_at", "null")
        
        # Time range
        now = datetime.now(timezone.utc)
        
        if view_mode == "What Changed Since Yesterday?":
            last_review = st.session_state.last_review_time
            query = query.or_(
                f"created_at.gt.{last_review},"
                f"exploitation_escalated_at.gt.{last_review},"
                f"signal_upgraded_at.gt.{last_review}"
            )
        elif view_mode == "Unreviewed Only":
            query = query.is_("reviewed_at", "null")
        
        if time_range == "Today":
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = now.replace(hour=23, minute=59, second=59, microsecond=999999)
            query = query.gte("published_at", start_date.isoformat()).lte("published_at", end_date.isoformat())
        elif time_range == "Last 3 Days":
            start_date = now - timedelta(days=3)
            query = query.gte("published_at", start_date.isoformat())
        elif time_range == "Last 7 Days":
            start_date = now - timedelta(days=7)
            query = query.gte("published_at", start_date.isoformat())
        elif time_range == "Last 30 Days":
            start_date = now - timedelta(days=30)
            query = query.gte("published_at", start_date.isoformat())
        
        # Sort by newest first
        query = query.order("published_at", desc=True)
        
        result = query.execute()
        return result.data if result.data else []
        
    except Exception as e:
        st.error(f"⚠️ Database query error: {str(e)}")
        return []

# Show loading spinner
with st.spinner("🔄 Loading intelligence..."):
    items = fetch_intelligence(
        signal_filter=signal_filter,
        exploit_filter=exploit_filter,
        time_range=time_range,
        show_reviewed=show_reviewed,
        source_confidence_filter=source_confidence_filter,
        view_mode=view_mode
    )

# Update last review time
if view_mode == "What Changed Since Yesterday?" and items:
    st.session_state.last_review_time = datetime.now(timezone.utc).isoformat()

# =========================================================
# DISPLAY INTELLIGENCE CARDS
# =========================================================

# View mode headers
if view_mode == "What Changed Since Yesterday?":
    st.markdown("### ⚡ What Changed Since Your Last Review")
    if 'last_review_time' in st.session_state:
        from dateutil import parser
        last_review = parser.parse(st.session_state.last_review_time)
        time_diff = datetime.now(timezone.utc) - last_review
        hours = int(time_diff.total_seconds() / 3600)
        st.caption(f"📅 Showing changes from the last {hours} hours")
    st.markdown("---")
elif view_mode == "Unreviewed Only":
    st.markdown("### 📋 Unreviewed Intelligence")
    st.caption("Items you haven't analyzed yet")
    st.markdown("---")

# No results message
if not items or len(items) == 0:
    st.warning("⚠️ No intelligence items match current filters.")
    st.info("💡 Try adjusting your filters or run the collector to gather new intelligence.")
    st.markdown("**Current filters:**")
    st.write(f"- Signal Strength: {signal_filter if signal_filter else 'None selected'}")
    st.write(f"- Exploitation Status: {exploit_filter if exploit_filter else 'None selected'}")
    st.write(f"- Time Range: {time_range}")
    st.write(f"- Source Confidence: {source_confidence_filter if source_confidence_filter else 'None selected'}")
    st.stop()

# Render cards (with per-card error handling)
for idx, item in enumerate(items):
    try:
        # Type check
        if not isinstance(item, dict):
            continue
        
        # Determine exploitation badge
        exploit_status = str(item.get('exploitation_status') or 'unknown')
        exploit_html = ""
        card_class = "intel-card"
        
        if exploit_status == 'actively_exploited':
            exploit_html = '<span class="exploit-active">🔴 ACTIVELY EXPLOITED</span>'
            card_class = "intel-card intel-card-critical"
        elif exploit_status == 'poc_available':
            exploit_html = '<span class="exploit-poc">🟡 PoC AVAILABLE</span>'
            card_class = "intel-card intel-card-warning"
        elif exploit_status == 'theoretical':
            exploit_html = '<span class="exploit-theoretical">🟢 THEORETICAL</span>'
        
        # Signal strength badge
        signal = str(item.get('signal_strength') or 'Low')
        signal_html = f'<span class="signal-{signal.lower()}">{signal} Signal</span>'
        
        # Event type chip
        event_type = str(item.get('event_type') or 'Unknown')
        event_html = f'<span class="event-chip">{event_type}</span>'
        
        # Delta badge
        delta = item.get('delta_reason')
        delta_html = f'<span class="delta-badge">⚡ {delta}</span>' if delta else ''
        
        # Escalation indicator
        escalation_html = ''
        if item.get('exploitation_escalated_at'):
            prev_status = str(item.get('previous_exploitation_status') or 'unknown')
            escalation_html = f'<span style="background: linear-gradient(135deg, #ff4444, #ff0000); color: white; padding: 6px 12px; border-radius: 4px; font-weight: 700; display: inline-block; margin-right: 8px;">↑ ESCALATED from {prev_status.replace("_", " ").title()}</span>'
        elif item.get('signal_upgraded_at'):
            prev_signal = str(item.get('previous_signal_strength') or 'Low')
            escalation_html = f'<span style="background: linear-gradient(135deg, #ff8800, #ffaa00); color: white; padding: 6px 12px; border-radius: 4px; font-weight: 600; display: inline-block; margin-right: 8px;">↑ Signal Upgraded from {prev_signal}</span>'
        
        # Threat velocity
        velocity_html = ''
        if item.get('threat_velocity') and item['threat_velocity'] != 'UNKNOWN':
            velocity = str(item['threat_velocity'])
            velocity_colors = {
                'FAST': 'var(--mdr-red)',
                'MODERATE': 'var(--mdr-orange)',
                'SLOW': 'var(--mdr-green)'
            }
            velocity_color = velocity_colors.get(velocity, '#888')
            velocity_icons = {'FAST': '🔥', 'MODERATE': '⚡', 'SLOW': '📊'}
            velocity_icon = velocity_icons.get(velocity, '⏱️')
            velocity_html = f'<span style="color: {velocity_color}; font-weight: 600; margin-left: 8px;">{velocity_icon} Velocity: {velocity}</span>'
        
        # Build card
        card_html = f'<div class="{card_class}">'
        card_html += '<div style="margin-bottom: 12px;">'
        card_html += exploit_html + ' ' + signal_html + ' ' + escalation_html + ' ' + velocity_html
        card_html += '</div>'
        card_html += f'<h3>{html.escape(str(item.get("title") or "Untitled"))}</h3>'
        card_html += '<div style="margin: 8px 0;">'
        card_html += event_html + ' ' + delta_html
        
        # CVE badge
        if item.get('cve_id'):
            cve_badge = f'<span class="event-chip" style="border-color: var(--mdr-orange)">🔍 {html.escape(str(item["cve_id"]))}'
            if item.get('cvss_score'):
                cve_badge += f' (CVSS {html.escape(str(item["cvss_score"]))})'  
            cve_badge += '</span>'
            card_html += cve_badge
        
        # CISA KEV
        if item.get('cisa_exploited'):
            card_html += '<span class="event-chip" style="border-color: var(--mdr-red); color: var(--mdr-red)">⚠️ CISA KEV</span>'
        
        # Attack name
        if item.get('attack_name'):
            card_html += f'<span class="event-chip" style="border-color: var(--mdr-purple); color: var(--mdr-purple)">🎯 {html.escape(str(item["attack_name"]))}</span>'
        
        # Windows Event ID
        if item.get('windows_event_id'):
            card_html += f'<span class="event-chip" style="border-color: #00aaff; color: #00aaff">🪟 Event ID: {html.escape(str(item["windows_event_id"]))}</span>'
        
        card_html += '</div>'
        
        # MDR ANALYST TAKE
        if item.get('mdr_analyst_take'):
            card_html += f'<div class="mdr-take">💡 <strong>Analyst Take:</strong> {html.escape(str(item["mdr_analyst_take"]))}</div>'
        
        # EVIDENCE/CONFIDENCE
        evidence_sources = item.get('evidence_sources')
        if evidence_sources and isinstance(evidence_sources, list) and len(evidence_sources) > 0:
            evidence_html = '<div style="background: rgba(0,200,136,0.1); border: 1px solid rgba(0,200,136,0.3); padding: 10px; border-radius: 6px; margin: 12px 0;">'
            evidence_html += '<strong>🔍 Evidence & Confidence:</strong><br/>'
            for evidence in evidence_sources[:5]:  # Limit to 5
                evidence_html += f'<span style="color: #00cc88; margin-right: 12px;">✔ {html.escape(str(evidence))}</span><br/>'
            evidence_html += f'<span style="color: #888; font-size: 12px;">{item.get("evidence_count", 0)} sources — {item.get("source_confidence", "Unknown")} confidence</span>'
            evidence_html += '</div>'
            card_html += evidence_html
        
        # Meta info
        meta_html = '<div class="meta-info">'
        meta_html += f'<span class="meta-item">📡 <strong>{item.get("source", "Unknown")}</strong></span>'
        
        if item.get('primary_target') and item['primary_target'] != 'Unspecified':
            meta_html += f'<span class="meta-item">🎯 {html.escape(str(item["primary_target"]))}</span>'
        
        if item.get('attack_vector') and item['attack_vector'] != 'Unknown':
            meta_html += f'<span class="meta-item">📍 {html.escape(str(item["attack_vector"]))}</span>'
        
        if item.get('first_observed_date'):
            formatted_date = format_ist_datetime(item['first_observed_date'], "%d %b %Y %H:%M IST")
            meta_html += f'<span class="meta-item">📅 First: {formatted_date}</span>'
        
        if item.get('weaponization_speed'):
            days = item['weaponization_speed']
            if isinstance(days, (int, float)) and days <= 3:
                meta_html += f'<span class="meta-item" style="color: var(--mdr-red)">⚡ {days} day weaponization</span>'
        
        if item.get('source_confidence'):
            conf_colors = {'High': 'var(--mdr-green)', 'Medium': 'var(--mdr-orange)', 'Low': '#666'}
            conf_color = conf_colors.get(item['source_confidence'], '#888')
            meta_html += f'<span class="meta-item" style="color: {conf_color}">📊 {html.escape(str(item["source_confidence"]))} Confidence</span>'
        
        meta_html += '</div>'
        card_html += meta_html + '</div>'
        
        st.markdown(card_html, unsafe_allow_html=True)
        
        # Extract entities
        content_for_extraction = f"{item.get('title', '')} {item.get('summary', '')}"
        all_entities = []
        
        if content_for_extraction.strip():
            try:
                extractor = EntityExtractor()
                entities = extractor.extract_all(content_for_extraction)
                
                for cve in entities.get('cves', [])[:3]:
                    cve_value = cve.value if hasattr(cve, 'value') else str(cve)
                    all_entities.append(('CVE', cve_value, cve_value.lower().replace('-', '_')))
                
                for actor in entities.get('threat_actors', [])[:2]:
                    actor_value = actor.value if hasattr(actor, 'value') else str(actor)
                    slug = actor_value.lower().replace(' ', '_').replace('-', '_')
                    all_entities.append(('Threat Actor', actor_value, slug))
                
                for tech in entities.get('technologies', [])[:2]:
                    tech_value = tech.value if hasattr(tech, 'value') else str(tech)
                    slug = tech_value.lower().replace(' ', '_').replace('-', '_')
                    all_entities.append(('Technology', tech_value, slug))
                
                for attack in entities.get('attack_types', [])[:2]:
                    attack_value = attack.value if hasattr(attack, 'value') else str(attack)
                    slug = attack_value.lower().replace(' ', '_').replace('-', '_')
                    all_entities.append(('Attack', attack_value, slug))
                
                for malware in entities.get('malware', [])[:2]:
                    malware_value = malware.value if hasattr(malware, 'value') else str(malware)
                    slug = malware_value.lower().replace(' ', '_').replace('-', '_')
                    all_entities.append(('Malware', malware_value, slug))
            except Exception:
                pass  # Silently skip entity extraction errors
            
            # Display entity buttons
            if all_entities:
                st.markdown("**🏷️ Extracted Topics:**")
                cols = st.columns(min(len(all_entities), 5))
                
                for idx_entity, (entity_type, entity_name, slug) in enumerate(all_entities[:5]):
                    with cols[idx_entity]:
                        if st.button(
                            f"{entity_name}",
                            key=f"entity_{item['id']}_{slug}_{idx}",
                            help=f"View {entity_type} page",
                            use_container_width=True
                        ):
                            st.session_state.viewing_topic = slug
                            st.rerun()
        
        # Expandable details
        with st.expander("📖 Full Intelligence Report"):
            if item.get('summary'):
                st.markdown(f"**📄 Summary:**\n\n{item['summary']}")
            
            if item.get('technical_method'):
                st.markdown(f"**⚙️ Technical Method:**\n\n{item['technical_method']}")
            
            if item.get('impact_outcome') and item['impact_outcome'] != 'Unknown':
                st.markdown(f"**💥 Impact:** {item['impact_outcome']}")
            
            st.markdown("---")
            
            # MITRE ATT&CK
            if item.get('mitre_tactics') or item.get('mitre_techniques'):
                st.markdown("**⚔️ MITRE ATT&CK:**")
                if item.get('mitre_tactics'):
                    tactics = ' '.join([f'`{t}`' for t in item['mitre_tactics']])
                    st.markdown(f"- **Tactics:** {tactics}")
                if item.get('mitre_techniques'):
                    techniques = ' '.join([f'`{t}`' for t in item['mitre_techniques']])
                    st.markdown(f"- **Techniques:** {techniques}")
            
            # Kill Chain
            if item.get('kill_chain_phases'):
                phases = ' '.join([f'`{p}`' for p in item['kill_chain_phases']])
                st.markdown(f"**🔗 Kill Chain:** {phases}")
            
            # Pattern tags
            if item.get('pattern_tags'):
                tags = ' '.join([f'`#{t}`' for t in item['pattern_tags']])
                st.markdown(f"**🏷️ Patterns:** {tags}")
            
            st.markdown("---")
            
            # Actions
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button("✅ Mark Reviewed", key=f"review_{item['id']}_{idx}", use_container_width=True):
                    supabase.table('daily_brief').update({
                        'reviewed_at': datetime.now().isoformat()
                    }).eq('id', item['id']).execute()
                    st.success("Marked as reviewed")
                    st.rerun()
            
            with col2:
                if st.button("⭐ Bookmark", key=f"book_{item['id']}_{idx}", use_container_width=True):
                    supabase.table('daily_brief').update({
                        'bookmarked': True
                    }).eq('id', item['id']).execute()
                    st.success("Bookmarked")
            
            with col3:
                if st.button("📌 Follow Up", key=f"follow_{item['id']}_{idx}", use_container_width=True):
                    supabase.table('daily_brief').update({
                        'follow_up_required': True
                    }).eq('id', item['id']).execute()
                    st.success("Marked for follow-up")
            
            with col4:
                article_url = str(item.get('url') or '#')
                st.link_button("🔗 Read Article", article_url, use_container_width=True)
    
    except Exception as e:
        # Per-card error handling - don't crash entire app
        st.error(f"⚠️ Error rendering card #{idx+1}: {str(e)[:100]}")
        continue

st.markdown("---")
st.markdown("🎯 **Personal MDR Threat Intelligence Platform** — Optimized for analyst efficiency")