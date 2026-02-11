"""
Knowledge Dashboard UI Components
Provides visualizations and exploration for the knowledge graph
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from knowledge_graph import KnowledgeGraphManager
from date_utils import format_ist_datetime
import json


def render_knowledge_overview(kg_manager: KnowledgeGraphManager):
    """Render knowledge graph overview with statistics"""
    st.header("🧠 Knowledge Graph Overview")
    
    # Get statistics
    stats = kg_manager.get_topic_statistics()
    ioc_stats = kg_manager.get_ioc_statistics()
    
    # Display key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Topics", stats.get('topics', 0))
    
    with col2:
        st.metric("Relationships", stats.get('relationships', 0))
    
    with col3:
        st.metric("IOCs", stats.get('iocs', 0))
    
    with col4:
        st.metric("IOC Types", len(ioc_stats))
    
    # IOC breakdown
    if ioc_stats:
        st.subheader("IOC Distribution")
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Create DataFrame for chart
            ioc_df = pd.DataFrame([
                {'Type': k.replace('ioc_', '').replace('_', ' ').title(), 'Count': v}
                for k, v in ioc_stats.items()
            ])
            
            if not ioc_df.empty:
                st.bar_chart(ioc_df.set_index('Type'))
        
        with col2:
            # Show breakdown table
            st.dataframe(ioc_df, use_container_width=True, hide_index=True)


def render_topic_explorer(kg_manager: KnowledgeGraphManager):
    """Topic search and exploration interface"""
    st.header("🔍 Topic Explorer")
    
    # Search interface
    col1, col2 = st.columns([3, 1])
    
    with col1:
        search_query = st.text_input("Search topics", placeholder="Enter CVE, threat actor, technology...")
    
    with col2:
        topic_filter = st.selectbox("Filter", ["All", "CVE", "Threat Actor", "Technology", "Attack Type", "Malware"])
    
    # Perform search if query provided
    if search_query:
        filter_map = {
            "All": None,
            "CVE": "cve",
            "Threat Actor": "threat_actor",
            "Technology": "technology",
            "Attack Type": "attack_type",
            "Malware": "malware",
        }
        
        results = kg_manager.search_topics(
            search_query,
            topic_type=filter_map.get(topic_filter)
        )
        
        if results:
            st.success(f"Found {len(results)} topic(s)")
            
            for topic in results:
                with st.expander(f"📊 {topic.get('name', 'Unknown')} ({topic.get('article_count', 0)} articles)"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Type:** {topic.get('topic_type', 'N/A').replace('_', ' ').title()}")
                    
                    with col2:
                        st.write(f"**Slug:** `{topic.get('slug', 'N/A')}`")
                    
                    with col3:
                        st.write(f"**Articles:** {topic.get('article_count', 0)}")
                    
                    if topic.get('description'):
                        st.write(f"**Description:** {topic['description']}")
                    
                    # Button to view full topic page
                    if st.button("View Details", key=f"view_{topic.get('id')}"):
                        st.session_state['selected_topic'] = topic.get('slug')
                        st.rerun()
        else:
            st.info("No topics found. Try a different search term.")


def render_topic_details(kg_manager: KnowledgeGraphManager, topic_slug: str):
    """Detailed view of a single topic"""
    topic_data = kg_manager.get_topic_with_articles(topic_slug)
    
    if not topic_data:
        st.error(f"Topic '{topic_slug}' not found")
        return
    
    # Back button
    if st.button("← Back to Explorer"):
        st.session_state['selected_topic'] = None
        st.rerun()
    
    # Topic header
    st.header(f"📑 {topic_data.get('name', 'Unknown Topic')}")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Articles", topic_data.get('article_count', 0))
    
    with col2:
        st.write(f"**Type:** {topic_data.get('topic_type', 'N/A').replace('_', ' ').title()}")
    
    with col3:
        created = topic_data.get('created_at')
        if created:
            formatted_date = format_ist_datetime(created, "%d %b %Y")
            st.write(f"**First Seen:** {formatted_date}")
    
    with col4:
        updated = topic_data.get('updated_at')
        if updated:
            formatted_date = format_ist_datetime(updated, "%d %b %Y")
            st.write(f"**Last Seen:** {formatted_date}")
    
    if topic_data.get('description'):
        st.info(topic_data['description'])
    
    # Relationships
    st.subheader("🔗 Relationships")
    relationships = kg_manager.get_topic_relationships(topic_slug)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Outgoing Relationships** (This topic affects/uses)")
        outgoing = relationships.get('outgoing', [])
        if outgoing:
            for rel in outgoing[:10]:  # Limit to 10
                target = rel.get('target_topic', {})
                if isinstance(target, dict):
                    rel_type = rel.get('relationship_type', 'related').replace('_', ' ').title()
                    strength = rel.get('strength', 0)
                    evidence = rel.get('evidence_count', 0)
                    
                    st.write(f"- **{rel_type}** → {target.get('name', 'Unknown')} (strength: {strength:.2f}, evidence: {evidence})")
        else:
            st.write("_No outgoing relationships_")
    
    with col2:
        st.write("**Incoming Relationships** (Other topics affecting this)")
        incoming = relationships.get('incoming', [])
        if incoming:
            for rel in incoming[:10]:  # Limit to 10
                source = rel.get('source_topic', {})
                if isinstance(source, dict):
                    rel_type = rel.get('relationship_type', 'related').replace('_', ' ').title()
                    strength = rel.get('strength', 0)
                    evidence = rel.get('evidence_count', 0)
                    
                    st.write(f"- {source.get('name', 'Unknown')} → **{rel_type}** (strength: {strength:.2f}, evidence: {evidence})")
        else:
            st.write("_No incoming relationships_")
    
    # Related articles
    st.subheader(f"📰 Related Articles ({len(topic_data.get('articles', []))})")
    
    articles = topic_data.get('articles', [])
    if articles:
        for article_link in articles[:20]:  # Show top 20
            article = article_link.get('daily_brief', {})
            if isinstance(article, dict):
                confidence = article_link.get('confidence', 0)
                method = article_link.get('detection_method', 'unknown')
                
                with st.expander(f"🔖 {article.get('title', 'Untitled')} (confidence: {confidence:.2f})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        if article.get('url'):
                            st.write(f"[🔗 Read Article]({article['url']})")
                    
                    with col2:
                        published = article.get('published_at')
                        if published:
                            pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                            st.write(f"**Published:** {pub_date.strftime('%Y-%m-%d')}")
                    
                    st.write(f"**Detection:** {method} | **Source:** {article.get('source', 'Unknown')}")
    else:
        st.info("No articles linked to this topic yet.")


def render_ioc_dashboard(kg_manager: KnowledgeGraphManager):
    """IOC exploration and export interface"""
    st.header("🛡️ IOC Dashboard")
    
    st.write("Export Indicators of Compromise for SIEM integration and threat intelligence feeds.")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        ioc_type = st.selectbox("IOC Type", ["All", "IP Addresses", "Domains", "File Hashes"])
    
    with col2:
        min_confidence = st.slider("Minimum Confidence", 0.0, 1.0, 0.7, 0.05)
    
    with col3:
        days_filter = st.selectbox("Time Period", [7, 30, 90, 180, 365, "All Time"])
    
    # Map selections
    type_map = {
        "All": None,
        "IP Addresses": "ioc_ip",
        "Domains": "ioc_domain",
        "File Hashes": None,  # Will need to handle multiple hash types
    }
    
    days = days_filter if isinstance(days_filter, int) else 0
    
    # Get IOCs
    iocs = kg_manager.export_iocs(
        ioc_type=type_map.get(ioc_type),
        min_confidence=min_confidence,
        days=days
    )
    
    # Filter for hashes if selected
    if ioc_type == "File Hashes":
        iocs = [ioc for ioc in iocs if 'hash' in ioc.get('ioc_type', '')]
    
    st.metric("IOCs Found", len(iocs))
    
    if iocs:
        # Display IOCs in table
        ioc_df = pd.DataFrame([
            {
                'Type': ioc.get('ioc_type', 'unknown').replace('ioc_', '').replace('_', ' ').title(),
                'Value': ioc.get('value', 'N/A'),
                'Confidence': f"{ioc.get('confidence', 0):.2f}",
                'First Seen': format_ist_datetime(ioc['first_seen'], "%d %b %Y") if ioc.get('first_seen') else 'N/A',
                'Last Seen': format_ist_datetime(ioc['last_seen'], "%d %b %Y") if ioc.get('last_seen') else 'N/A',
                'Occurrences': ioc.get('occurrence_count', 1),
            }
            for ioc in iocs
        ])
        
        st.dataframe(ioc_df, use_container_width=True, hide_index=True)
        
        # Export options
        st.subheader("📥 Export Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # CSV export
            csv = ioc_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            # JSON export (STIX format friendly)
            json_data = json.dumps([
                {
                    'type': ioc.get('ioc_type', 'unknown'),
                    'value': ioc.get('value', ''),
                    'confidence': ioc.get('confidence', 0),
                    'first_seen': ioc.get('first_seen', ''),
                    'last_seen': ioc.get('last_seen', ''),
                    'occurrences': ioc.get('occurrence_count', 1),
                    'context': f"Extracted from {ioc.get('occurrence_count', 1)} cyber threat articles"
                }
                for ioc in iocs
            ], indent=2)
            
            st.download_button(
                label="Download JSON",
                data=json_data,
                file_name=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        with col3:
            # Simple text list for quick copy-paste
            text_list = "\n".join([ioc.get('value', '') for ioc in iocs])
            st.download_button(
                label="Download TXT",
                data=text_list,
                file_name=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
        
        # SIEM integration hints
        with st.expander("💡 SIEM Integration Tips"):
            st.markdown("""
            **🔍 Splunk:**
            ```spl
            | inputlookup iocs.csv
            | where confidence >= 0.8
            | search index=* [| inputlookup iocs.csv | fields value | rename value as query]
            ```
            
            **📊 QRadar:**
            Import CSV into Reference Set: `Admin → Reference Set Management → Add New → Upload CSV`
            
            **🛡️ Sentinel:**
            ```kusto
            let IOCs = externaldata(type:string, value:string, confidence:real)
            [@"https://your-storage.blob.core.windows.net/iocs.csv"]
            with (format="csv", ignoreFirstRecord=true);
            CommonSecurityLog
            | where DestinationIP in ((IOCs | where type == "ip" | project value))
            ```
            
            **🔬 Elastic:**
            Use Filebeat to ingest IOCs, then create detection rules based on confidence scores.
            """)
    else:
        st.info("No IOCs found matching your criteria. Try adjusting the filters.")


def render_knowledge_dashboard(kg_manager: KnowledgeGraphManager):
    """Main knowledge dashboard router"""
    st.title("🧠 Knowledge Management")
    
    # Tab navigation
    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔍 Topic Explorer", "🛡️ IOC Dashboard"])
    
    with tab1:
        render_knowledge_overview(kg_manager)
    
    with tab2:
        # Check if topic is selected for detailed view
        if 'selected_topic' in st.session_state and st.session_state['selected_topic']:
            render_topic_details(kg_manager, st.session_state['selected_topic'])
        else:
            render_topic_explorer(kg_manager)
    
    with tab3:
        render_ioc_dashboard(kg_manager)
