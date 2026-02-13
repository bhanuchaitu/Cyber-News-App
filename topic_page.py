"""
Topic Page UI - Phase 3
Living pages for every entity (threat actor, CVE, technology, attack type, malware)
Shows timeline, relationships, IOCs, notes, expertise
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from typing import Dict, List
from knowledge_graph import KnowledgeGraphManager
from date_utils import format_ist_datetime


def render_topic_page(kg_manager: KnowledgeGraphManager, topic_slug: str):
    """
    Render a comprehensive topic page for a specific entity
    
    Args:
        kg_manager: Knowledge graph manager instance
        topic_slug: Unique slug for the topic (e.g., 'lockbit', 'cve-2026-1234')
    """
    # Fetch topic with related articles
    topic_data = kg_manager.get_topic_with_articles(topic_slug)
    
    if not topic_data:
        st.error(f"❌ Topic '{topic_slug}' not found in knowledge graph")
        if st.button("← Back to Knowledge Graph"):
            st.session_state.pop('viewing_topic', None)
            st.rerun()
        return
    
    topic = topic_data.get('topic', {})
    articles = topic_data.get('articles', [])
    
    # =========================================================
    # TOPIC HEADER
    # =========================================================
    
    st.markdown("### 🧠 Topic Page")
    
    # Topic name with type badge
    topic_type = topic.get('type', 'unknown').replace('_', ' ').title()
    type_icons = {
        'Threat Actor': '👾',
        'Cve': '🔒',
        'Technology': '💻',
        'Attack Type': '⚔️',
        'Malware': '🦠',
        'Campaign': '🎯'
    }
    type_icon = type_icons.get(topic_type, '📌')
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.markdown(f"# {type_icon} {topic.get('name', 'Unknown Topic')}")
        
        if topic.get('description'):
            st.markdown(f"*{topic['description']}*")
    
    with col2:
        st.metric("Type", topic_type)
        if st.button("← Back", use_container_width=True):
            st.session_state.pop('viewing_topic', None)
            st.rerun()
    
    st.markdown("---")
    
    # =========================================================
    # STATISTICS ROW
    # =========================================================
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        article_count = topic.get('article_count', len(articles))
        st.metric("📰 Articles", article_count)
    
    with col2:
        first_seen = topic.get('first_seen') or topic.get('created_at')
        if first_seen:
            formatted_date = format_ist_datetime(first_seen, "%d %b %Y")
            st.metric("👁️ First Seen", formatted_date)
        else:
            st.metric("👁️ First Seen", "N/A")
    
    with col3:
        last_seen = topic.get('last_seen') or topic.get('updated_at')
        if last_seen:
            formatted_date = format_ist_datetime(last_seen, "%d %b %Y")
            st.metric("🕐 Last Seen", formatted_date)
        else:
            st.metric("🕐 Last Seen", "N/A")
    
    with col4:
        # Get related topics count
        relationships = kg_manager.get_topic_relationships(topic.get('id'))
        related_count = len(relationships.get('outgoing', [])) + len(relationships.get('incoming', []))
        st.metric("🔗 Related Topics", related_count)
    
    st.markdown("---")
    
    # =========================================================
    # TABS: TIMELINE | RELATIONSHIPS | IOCs | NOTES
    # =========================================================
    
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Timeline", "🔗 Relationships", "🎯 IOCs", "📝 Notes"])
    
    # TAB 1: TIMELINE OF ARTICLES
    with tab1:
        render_topic_timeline(articles, topic.get('name', 'Unknown'))
    
    # TAB 2: RELATED TOPICS (RELATIONSHIPS)
    with tab2:
        render_topic_relationships(relationships, topic.get('name', 'Unknown'))
    
    # TAB 3: RELATED IOCs
    with tab3:
        render_topic_iocs(kg_manager, topic.get('id'), topic.get('name', 'Unknown'))
    
    # TAB 4: USER NOTES & EXPERTISE
    with tab4:
        render_topic_notes(kg_manager, topic.get('id'), topic.get('slug'), topic.get('name', 'Unknown'))


def render_topic_timeline(articles: List[Dict], topic_name: str):
    """Render chronological timeline of articles mentioning this topic"""
    
    st.markdown(f"### 📰 All Articles Mentioning *{topic_name}*")
    
    if not articles:
        st.info(f"No articles found for {topic_name}")
        return
    
    st.markdown(f"**{len(articles)} articles** tracked over time")
    st.markdown("---")
    
    # Sort articles by published date (newest first)
    sorted_articles = sorted(
        articles,
        key=lambda x: x.get('published_at', x.get('created_at', '')),
        reverse=True
    )
    
    # Group by month for timeline visualization
    from datetime import datetime
    current_month = None
    
    for article in sorted_articles:
        # Get published date
        published = article.get('published_at') or article.get('created_at')
        
        if published:
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                month_label = pub_date.strftime("%B %Y")
                
                # Show month header
                if month_label != current_month:
                    st.markdown(f"#### 📅 {month_label}")
                    current_month = month_label
            except (ValueError, AttributeError):
                pass
        
        # Article card
        with st.container():
            col1, col2 = st.columns([4, 1])
            
            with col1:
                title = article.get('title', 'Untitled Article')
                st.markdown(f"**{title}**")
                
                # Meta info
                source = article.get('source', 'Unknown')
                if published:
                    formatted_date = format_ist_datetime(published, "%d %b %Y %H:%M IST")
                    st.caption(f"📡 {source} • {formatted_date}")
                else:
                    st.caption(f"📡 {source}")
                
                # Summary if available
                if article.get('summary'):
                    with st.expander("📄 Summary"):
                        st.write(article['summary'])
            
            with col2:
                # Link to article
                url = article.get('url', '#')
                st.link_button("Read →", url, use_container_width=True)
        
        st.markdown("---")


def render_topic_relationships(relationships: Dict, topic_name: str):
    """Render related topics (incoming and outgoing relationships)"""
    
    st.markdown(f"### 🔗 Topics Related to *{topic_name}*")
    
    outgoing = relationships.get('outgoing', [])
    incoming = relationships.get('incoming', [])
    
    if not outgoing and not incoming:
        st.info(f"No relationships found for {topic_name}")
        return
    
    # OUTGOING RELATIONSHIPS (This topic → Other topics)
    if outgoing:
        st.markdown(f"#### → {topic_name} is connected to:")
        
        # Create DataFrame for better visualization
        outgoing_data = []
        for rel in outgoing:
            target = rel.get('target_topic', {})
            outgoing_data.append({
                'Topic': target.get('name', 'Unknown'),
                'Type': target.get('type', 'unknown').replace('_', ' ').title(),
                'Relationship': rel.get('relationship_type', 'related_to').replace('_', ' ').title(),
                'Strength': f"{rel.get('strength', 0):.2f}",
                'Slug': target.get('slug', '')
            })
        
        df_outgoing = pd.DataFrame(outgoing_data)
        
        # Display as table with clickable links
        for idx, row in df_outgoing.iterrows():
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            
            with col1:
                st.write(f"**{row['Topic']}**")
            
            with col2:
                st.caption(row['Type'])
            
            with col3:
                st.caption(row['Relationship'])
            
            with col4:
                if st.button("View →", key=f"out_{idx}", use_container_width=True):
                    st.session_state['viewing_topic'] = row['Slug']
                    st.rerun()
        
        st.markdown("---")
    
    # INCOMING RELATIONSHIPS (Other topics → This topic)
    if incoming:
        st.markdown(f"#### ← {topic_name} is mentioned by:")
        
        # Create DataFrame for better visualization
        incoming_data = []
        for rel in incoming:
            source = rel.get('source_topic', {})
            incoming_data.append({
                'Topic': source.get('name', 'Unknown'),
                'Type': source.get('type', 'unknown').replace('_', ' ').title(),
                'Relationship': rel.get('relationship_type', 'related_to').replace('_', ' ').title(),
                'Strength': f"{rel.get('strength', 0):.2f}",
                'Slug': source.get('slug', '')
            })
        
        df_incoming = pd.DataFrame(incoming_data)
        
        # Display as table with clickable links
        for idx, row in df_incoming.iterrows():
            col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
            
            with col1:
                st.write(f"**{row['Topic']}**")
            
            with col2:
                st.caption(row['Type'])
            
            with col3:
                st.caption(row['Relationship'])
            
            with col4:
                if st.button("View →", key=f"in_{idx}", use_container_width=True):
                    st.session_state['viewing_topic'] = row['Slug']
                    st.rerun()


def render_topic_iocs(kg_manager: KnowledgeGraphManager, topic_id: int, topic_name: str):
    """Render IOCs related to this topic"""
    
    st.markdown(f"### 🎯 IOCs Related to *{topic_name}*")
    
    # Query IOCs from articles related to this topic
    # This requires a custom query since we need to join through article_topics
    try:
        result = kg_manager.supabase.rpc(
            'get_topic_iocs',
            {'topic_id_param': topic_id}
        ).execute()
        
        iocs = result.data if result.data else []
    except Exception:
        # Fallback: get all IOCs and filter manually (less efficient but works)
        st.info("Advanced IOC filtering not available. Showing related IOCs from all articles.")
        all_iocs = kg_manager.export_iocs()
        
        # Try to filter by topic - check if IOC is from an article mentioning this topic
        # This is a basic filter; ideally the RPC function should work
        topic_name_lower = topic_name.lower()
        
        def match_tags(tags_value):
            """Check if topic_name appears in tags (handles list or string)"""
            if isinstance(tags_value, (list, tuple)):
                return any(topic_name_lower in str(tag).lower() for tag in tags_value)
            elif tags_value:
                return topic_name_lower in str(tags_value).lower()
            return False
        
        iocs = [
            ioc for ioc in all_iocs 
            if isinstance(ioc, dict) and (
                topic_name_lower in str(ioc.get('article_title', '')).lower() or
                match_tags(ioc.get('tags'))
            )
        ]
        
        # If filtering yields nothing, show all IOCs with disclaimer
        if not iocs:
            st.warning(f"No IOCs directly linked to {topic_name}. Showing all extracted IOCs (unfiltered).")
            iocs = all_iocs
    
    # Type guard: ensure iocs is a list
    if not isinstance(iocs, list):
        iocs = []
    
    if not iocs:
        st.info(f"No IOCs extracted from articles about {topic_name}")
        return
    
    st.markdown(f"**{len(iocs)} indicators** extracted from articles mentioning {topic_name}")
    
    # Group by IOC type
    ioc_types = {}
    for ioc in iocs:
        # Type guard for each IOC
        if not isinstance(ioc, dict):
            continue
            
        ioc_type_raw = ioc.get('ioc_type', 'unknown')
        ioc_type = str(ioc_type_raw).replace('ioc_', '').replace('_', ' ').title()
        if ioc_type not in ioc_types:
            ioc_types[ioc_type] = []
        ioc_types[ioc_type].append(ioc)
    
    # Display by type
    for ioc_type, type_iocs in ioc_types.items():
        with st.expander(f"**{ioc_type}** ({len(type_iocs)} indicators)", expanded=True):
            ioc_data = []
            for ioc in type_iocs[:20]:  # Limit to 20 per type
                ioc_data.append({
                    'Value': ioc.get('value', 'N/A'),
                    'Confidence': f"{ioc.get('confidence', 0):.2f}",
                    'First Seen': format_ist_datetime(ioc['first_seen'], "%d %b %Y") if ioc.get('first_seen') else 'N/A',
                    'Last Seen': format_ist_datetime(ioc['last_seen'], "%d %b %Y") if ioc.get('last_seen') else 'N/A',
                })
            
            st.dataframe(pd.DataFrame(ioc_data), use_container_width=True, hide_index=True)


def render_topic_notes(kg_manager: KnowledgeGraphManager, topic_id: int, topic_slug: str, topic_name: str):
    """Render user notes and expertise tracking for this topic"""
    
    st.markdown(f"### 📝 Your Notes on *{topic_name}*")
    
    # Fetch existing notes from user_knowledge table
    try:
        result = kg_manager.supabase.table('user_knowledge').select('*').eq('topic_id', topic_id).execute()
        user_data = result.data[0] if result.data and len(result.data) > 0 else None
    except Exception:
        user_data = None
    
    # Type guard: ensure user_data is dict or None
    if user_data and not isinstance(user_data, dict):
        user_data = None
    
    # Notes editor (user_data is now guaranteed to be dict or None)
    existing_notes = user_data.get('notes', '') if (user_data and isinstance(user_data, dict)) else ''
    notes = st.text_area(
        "Personal notes, insights, or reminders about this topic:",
        value=existing_notes,
        height=200,
        placeholder="Add your observations, key takeaways, or action items..."
    )
    
    # Expertise level
    st.markdown("---")
    st.markdown("#### 📈 Expertise Level")
    
    expertise_raw = user_data.get('expertise_score', 0) if (user_data and isinstance(user_data, dict)) else 0
    expertise = int(expertise_raw) if isinstance(expertise_raw, (int, float)) else 0
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.progress(expertise / 100)
        st.caption(f"**{expertise}/100** - {get_expertise_label(expertise)}")
    
    with col2:
        st.metric("Level", get_expertise_level(expertise))
    
    # Save button
    if st.button("💾 Save Notes", use_container_width=True, type="primary"):
        save_user_knowledge(kg_manager, topic_id, topic_slug, notes or '', expertise)
        st.success("✅ Notes saved successfully!")
        st.rerun()
    
    # Expertise explanation
    with st.expander("ℹ️ How expertise is calculated"):
        st.markdown("""
        Your expertise level increases as you:
        - Read articles about this topic
        - Add notes and insights
        - Track IOCs related to this topic
        - Follow related topics
        
        **Expertise Levels:**
        - 0-20: Beginner 🌱
        - 21-40: Learning 📚
        - 41-60: Intermediate ⚙️
        - 61-80: Advanced 🎓
        - 81-100: Expert 🏆
        """)


def get_expertise_label(score: int) -> str:
    """Get expertise label based on score"""
    if score >= 81:
        return "Expert 🏆"
    elif score >= 61:
        return "Advanced 🎓"
    elif score >= 41:
        return "Intermediate ⚙️"
    elif score >= 21:
        return "Learning 📚"
    else:
        return "Beginner 🌱"


def get_expertise_level(score: int) -> int:
    """Get expertise level (1-5) based on score"""
    if score >= 81:
        return 5
    elif score >= 61:
        return 4
    elif score >= 41:
        return 3
    elif score >= 21:
        return 2
    else:
        return 1


def save_user_knowledge(kg_manager: KnowledgeGraphManager, topic_id: int, topic_slug: str, notes: str, expertise: int):
    """Save or update user knowledge for a topic"""
    
    try:
        # --- Input validation (CWE-20: Improper Input Validation) ---
        # Validate expertise is within expected range
        if not isinstance(expertise, int) or expertise < 0 or expertise > 100:
            st.error("Expertise level must be between 0 and 100.")
            return
        
        # Validate notes length (prevent storage abuse)
        MAX_NOTES_LENGTH = 10000
        if notes and len(notes) > MAX_NOTES_LENGTH:
            st.error(f"Notes too long ({len(notes)} chars). Maximum is {MAX_NOTES_LENGTH} characters.")
            return
        
        # Strip null bytes and control characters (except newlines/tabs) from notes
        if notes:
            notes = notes.replace('\x00', '')
            import re as _re
            notes = _re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', notes)
        
        # Validate topic_id is a positive integer
        if not isinstance(topic_id, int) or topic_id <= 0:
            st.error("Invalid topic ID.")
            return

        # Check if record exists
        result = kg_manager.supabase.table('user_knowledge').select('id').eq('topic_id', topic_id).execute()
        
        # Map numeric score to text enum for expertise_level column
        level_map = {5: 'expert', 4: 'advanced', 3: 'intermediate', 2: 'intermediate', 1: 'beginner', 0: 'beginner'}
        expertise_label = level_map.get(get_expertise_level(expertise), 'beginner')

        data = {
            'topic_id': topic_id,
            'notes': notes,
            'expertise_level': expertise_label,
            'expertise_score': expertise,
            'updated_at': datetime.now().isoformat()
        }
        
        if result.data and len(result.data) > 0:
            # Update existing record
            kg_manager.supabase.table('user_knowledge').update(data).eq('topic_id', topic_id).execute()
        else:
            # Insert new record
            data['created_at'] = datetime.now().isoformat()
            kg_manager.supabase.table('user_knowledge').insert(data).execute()
            
    except Exception as e:
        print(f"Error saving notes: {e}")  # Log internally only
        st.error("Failed to save notes. Please try again.")
