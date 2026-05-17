"""
Lean Cyber News Daily Brief

Streamlit dashboard focused on fast review of high-signal cyber news.
"""

from __future__ import annotations

import html
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import streamlit as st
from dotenv import load_dotenv
from supabase import create_client

from date_utils import format_ist_datetime


load_dotenv()

st.set_page_config(
    page_title="Cyber News Daily Brief",
    page_icon=":newspaper:",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
<style>
:root {
    --bg-card: #151922;
    --border: #2b3240;
    --text-muted: #9aa4b2;
    --red: #ef4444;
    --amber: #f59e0b;
    --green: #10b981;
    --blue: #3b82f6;
}
.brief-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-left: 5px solid var(--border);
    border-radius: 8px;
    padding: 18px;
    margin: 0 0 16px 0;
}
.brief-card.high {
    border-left-color: var(--red);
}
.brief-card.medium {
    border-left-color: var(--amber);
}
.badge {
    display: inline-block;
    border-radius: 999px;
    padding: 4px 10px;
    margin: 0 6px 6px 0;
    font-size: 12px;
    font-weight: 700;
    line-height: 1.2;
    border: 1px solid rgba(255,255,255,0.18);
}
.badge.red { background: rgba(239,68,68,0.18); color: #fecaca; border-color: rgba(239,68,68,0.45); }
.badge.amber { background: rgba(245,158,11,0.18); color: #fde68a; border-color: rgba(245,158,11,0.45); }
.badge.green { background: rgba(16,185,129,0.16); color: #bbf7d0; border-color: rgba(16,185,129,0.4); }
.badge.blue { background: rgba(59,130,246,0.16); color: #bfdbfe; border-color: rgba(59,130,246,0.4); }
.badge.gray { background: rgba(148,163,184,0.12); color: #cbd5e1; border-color: rgba(148,163,184,0.3); }
.card-title {
    font-size: 21px;
    line-height: 1.3;
    margin: 4px 0 10px 0;
    font-weight: 750;
}
.summary {
    color: #d5dae3;
    line-height: 1.55;
    margin: 10px 0 12px 0;
}
.analyst-take {
    background: rgba(59,130,246,0.12);
    border-left: 3px solid var(--blue);
    border-radius: 6px;
    padding: 12px;
    margin-top: 12px;
    line-height: 1.5;
}
.meta {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 12px;
}
@media (max-width: 640px) {
    .brief-card { padding: 14px; }
    .card-title { font-size: 18px; }
}
</style>
""",
    unsafe_allow_html=True,
)


def safe_text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return html.escape(str(value))


@st.cache_resource
def init_supabase():
    try:
        url = st.secrets.get("SUPABASE_URL")
        key = st.secrets.get("SUPABASE_KEY")
    except Exception:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")

    if not url or not key:
        st.error("Missing Supabase credentials.")
        st.info("Set SUPABASE_URL and SUPABASE_KEY in Streamlit secrets or a local .env file.")
        st.stop()

    return create_client(url, key)


supabase = init_supabase()


st.title("Cyber News Daily Brief")
st.caption("A focused feed for quickly spotting what matters in the threat landscape.")


st.sidebar.header("Filters")

signal_filter = st.sidebar.multiselect(
    "Signal strength",
    ["High", "Medium", "Low"],
    default=["High", "Medium"],
)

exploit_filter = st.sidebar.multiselect(
    "Exploitation status",
    ["actively_exploited", "poc_available", "theoretical", "unknown"],
    default=["actively_exploited", "poc_available"],
)

time_range = st.sidebar.selectbox(
    "Time range",
    ["Today", "Last 3 Days", "Last 7 Days", "Last 30 Days"],
    index=2,
)

show_reviewed = st.sidebar.checkbox("Show reviewed items", value=False)

source_confidence_filter = st.sidebar.multiselect(
    "Source confidence",
    ["High", "Medium", "Low"],
    default=["High", "Medium"],
)


def range_start(selected_range: str) -> datetime:
    now = datetime.now(timezone.utc)
    if selected_range == "Today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if selected_range == "Last 3 Days":
        return now - timedelta(days=3)
    if selected_range == "Last 30 Days":
        return now - timedelta(days=30)
    return now - timedelta(days=7)


def fetch_items() -> list[dict[str, Any]]:
    query = supabase.table("daily_brief").select("*")

    if signal_filter:
        query = query.in_("signal_strength", signal_filter)
    if exploit_filter:
        query = query.in_("exploitation_status", exploit_filter)
    if source_confidence_filter:
        query = query.in_("source_confidence", source_confidence_filter)
    if not show_reviewed:
        query = query.is_("reviewed_at", "null")

    query = query.gte("published_at", range_start(time_range).isoformat())
    query = query.order("published_at", desc=True)

    result = query.execute()
    return result.data if isinstance(result.data, list) else []


def badge(text: str, color: str = "gray") -> str:
    return f'<span class="badge {color}">{html.escape(text)}</span>'


def exploitation_badge(status: str) -> str:
    labels = {
        "actively_exploited": ("Actively exploited", "red"),
        "poc_available": ("PoC available", "amber"),
        "theoretical": ("Theoretical", "green"),
        "unknown": ("Unknown", "gray"),
    }
    label, color = labels.get(status, ("Unknown", "gray"))
    return badge(label, color)


def signal_badge(signal: str) -> str:
    colors = {"High": "red", "Medium": "amber", "Low": "gray"}
    return badge(f"{signal} signal", colors.get(signal, "gray"))


def render_card(item: dict[str, Any], index: int) -> None:
    signal = str(item.get("signal_strength") or "Low")
    status = str(item.get("exploitation_status") or "unknown")
    card_weight = "high" if signal == "High" else "medium" if signal == "Medium" else ""

    chips = [
        exploitation_badge(status),
        signal_badge(signal),
        badge(str(item.get("event_type") or "News"), "blue"),
    ]

    if item.get("cve_id"):
        cve_text = str(item["cve_id"])
        if item.get("cvss_score"):
            cve_text = f"{cve_text} / CVSS {item['cvss_score']}"
        chips.append(badge(cve_text, "amber"))

    if item.get("cisa_exploited"):
        chips.append(badge("CISA KEV", "red"))

    if item.get("attack_name"):
        chips.append(badge(str(item["attack_name"]), "gray"))

    summary = safe_text(item.get("summary"), "No summary available.")
    analyst_take = safe_text(item.get("mdr_analyst_take"))
    source = safe_text(item.get("source"), "Unknown source")
    published = format_ist_datetime(item.get("published_at"), "%d %b %Y %H:%M IST")
    confidence = safe_text(item.get("source_confidence"), "Unknown")
    target = safe_text(item.get("primary_target"), "Unspecified")

    report_html = ""
    if analyst_take:
        report_html = f'<div class="analyst-take"><strong>Analyst take:</strong> {analyst_take}</div>'

    st.markdown(
        f"""
<article class="brief-card {card_weight}">
    <div>{''.join(chips)}</div>
    <div class="card-title">{safe_text(item.get("title"), "Untitled")}</div>
    <div class="summary">{summary}</div>
    {report_html}
    <div class="meta">
        <span>{source}</span>
        <span>{published}</span>
        <span>{confidence} confidence</span>
        <span>Target: {target}</span>
    </div>
</article>
""",
        unsafe_allow_html=True,
    )

    with st.expander("Details and actions"):
        if item.get("signal_strength_reason"):
            st.markdown(f"**Why this signal:** {item['signal_strength_reason']}")
        if item.get("technical_method"):
            st.markdown(f"**Technical method:** {item['technical_method']}")
        if item.get("impact_outcome") and item.get("impact_outcome") != "Unknown":
            st.markdown(f"**Impact:** {item['impact_outcome']}")
        if item.get("mitre_tactics") or item.get("mitre_techniques"):
            st.markdown("**MITRE ATT&CK:**")
            if item.get("mitre_tactics"):
                st.write(", ".join(item["mitre_tactics"]))
            if item.get("mitre_techniques"):
                st.write(", ".join(item["mitre_techniques"]))
        if item.get("kill_chain_phases"):
            st.markdown(f"**Kill chain:** {', '.join(item['kill_chain_phases'])}")

        col1, col2, col3, col4 = st.columns(4)
        article_id = item.get("id")

        with col1:
            if st.button("Mark reviewed", key=f"review_{article_id}_{index}", use_container_width=True):
                supabase.table("daily_brief").update(
                    {"reviewed_at": datetime.now(timezone.utc).isoformat()}
                ).eq("id", article_id).execute()
                st.rerun()

        with col2:
            if st.button("Bookmark", key=f"bookmark_{article_id}_{index}", use_container_width=True):
                supabase.table("daily_brief").update({"bookmarked": True}).eq("id", article_id).execute()
                st.toast("Bookmarked")

        with col3:
            if st.button("Follow up", key=f"follow_{article_id}_{index}", use_container_width=True):
                supabase.table("daily_brief").update({"follow_up_required": True}).eq("id", article_id).execute()
                st.toast("Marked for follow-up")

        with col4:
            st.link_button("Read article", str(item.get("url") or "#"), use_container_width=True)


with st.spinner("Loading brief..."):
    try:
        items = fetch_items()
    except Exception as exc:
        st.error(f"Database query failed: {exc}")
        st.stop()


if not items:
    st.warning("No articles match the current filters.")
    st.info("Try widening the filters or run `python collector_mdr.py` to collect fresh news.")
    st.stop()


high_count = sum(1 for item in items if item.get("signal_strength") == "High")
active_count = sum(1 for item in items if item.get("exploitation_status") == "actively_exploited")

col1, col2, col3 = st.columns(3)
col1.metric("Items", len(items))
col2.metric("High signal", high_count)
col3.metric("Actively exploited", active_count)

st.divider()

for idx, item in enumerate(items):
    if isinstance(item, dict):
        render_card(item, idx)
