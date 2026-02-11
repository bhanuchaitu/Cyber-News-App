"""
Personal MDR Cyber Threat Intelligence Collector
Transforms public security news into analyst-ready intelligence
"""
import os
import sys
import time
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
import feedparser
import requests
from sentence_transformers import SentenceTransformer
from supabase import create_client, Client
from dotenv import load_dotenv

# Import MDR intelligence modules
from mdr_intelligence import (
    normalize_event,
    determine_exploitation_status,
    extract_delta_reason,
    generate_mdr_analyst_take,
    calculate_signal_strength,
    determine_source_confidence,
    generate_story_hash,
    extract_pattern_tags,
    extract_technical_method,
    build_evidence_list,
    calculate_threat_velocity,
    classify_unknown_reason
)
from attack_mapping import map_to_mitre_attack, map_to_kill_chain, extract_attack_name
from date_utils import parse_feed_date_utc, is_within_last_n_days
from knowledge_graph import KnowledgeGraphManager

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')  # type: ignore

load_dotenv()

# ============ CONFIGURATION ============
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing SUPABASE_URL or SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
embed_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

# RSS Feeds (reputable sources only)
RSS_FEEDS = {
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
    'Krebs on Security': 'https://krebsonsecurity.com/feed/',
    'Schneier on Security': 'https://www.schneier.com/feed/atom/',
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
    'Dark Reading': 'https://www.darkreading.com/rss.xml',
}

print("=" * 80)
print("🎯 PERSONAL MDR CYBER THREAT INTELLIGENCE COLLECTOR")
print("=" * 80)
print("Transforming public security news into analyst-ready intelligence...")
print()


def extract_cve_id(text: str) -> Optional[str]:
    """Extract CVE ID from text"""
    match = re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def enrich_cve_from_nvd(cve_id: str) -> Dict:
    """Fetch CVE data from NVD API (free, no key required)"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                vuln = data['vulnerabilities'][0]['cve']
                
                # Extract CVSS score
                cvss_score = None
                cvss_vector = None
                
                if 'metrics' in vuln:
                    if 'cvssMetricV31' in vuln['metrics'] and vuln['metrics']['cvssMetricV31']:
                        cvss_data = vuln['metrics']['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                    elif 'cvssMetricV30' in vuln['metrics'] and vuln['metrics']['cvssMetricV30']:
                        cvss_data = vuln['metrics']['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        cvss_vector = cvss_data.get('vectorString')
                
                # Extract published date
                published_date = vuln.get('published', '')[:10] if 'published' in vuln else None
                
                return {
                    'cve_id': cve_id,
                    'cvss_score': cvss_score,
                    'cvss_vector': cvss_vector,
                    'cve_published_date': published_date
                }
    except Exception as e:
        print(f"    ⚠️  NVD API error for {cve_id}: {e}")
    
    return {'cve_id': cve_id, 'cvss_score': None, 'cvss_vector': None, 'cve_published_date': None}


def check_cisa_kev(cve_id: str) -> bool:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog"""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return any(vuln['cveID'] == cve_id for vuln in data.get('vulnerabilities', []))
    except Exception:
        pass
    
    return False


def calculate_weaponization_speed(cve_published_date: Optional[str], article_date: datetime) -> Optional[int]:
    """Calculate days from CVE disclosure to article (proxy for weaponization speed)"""
    if not cve_published_date:
        return None
    
    try:
        published = datetime.fromisoformat(cve_published_date)
        delta = article_date - published.replace(tzinfo=timezone.utc)
        return max(0, delta.days)
    except:
        return None


def collect_rss_feeds() -> List[Dict]:
    """Collect and process security news from RSS feeds"""
    print("📡 Collecting from RSS feeds...")
    items = []
    
    for source_name, feed_url in RSS_FEEDS.items():
        try:
            print(f"\n  📰 {source_name}")
            feed = feedparser.parse(feed_url)
            
            if not hasattr(feed, 'entries') or not feed.entries:
                print(f"    ⚠️  No entries found")
                continue
            
            count = 0
            for entry in feed.entries[:15]:  # Process last 15 from each source
                try:
                    title = str(entry.get('title', '')).strip()
                    url = str(entry.get('link', ''))
                    summary_raw = entry.get('summary', entry.get('description', ''))
                    summary = str(summary_raw)[:500] if summary_raw else ''
                    
                    if not title or not url:
                        continue
                    
                    # Parse published date (CENTRALIZED - CRITICAL)
                    published_at = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        published_at = parse_feed_date_utc(entry.published_parsed)
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        published_at = parse_feed_date_utc(entry.updated_parsed)
                    else:
                        published_at = parse_feed_date_utc(None)  # Falls back to now
                    
                    # Clean HTML from summary
                    summary = re.sub(r'<[^>]+>', '', summary)
                    
                    # Extract CVE
                    cve_id = extract_cve_id(title + ' ' + summary)
                    
                    # ============ MDR INTELLIGENCE PROCESSING ============
                    
                    # 1️⃣ Event Normalization
                    event_data = normalize_event(title, summary, '', cve_id)
                    
                    # 2️⃣ CVE Enrichment
                    cve_data = {}
                    cisa_exploited = False
                    if cve_id:
                        cve_data = enrich_cve_from_nvd(cve_id)
                        cisa_exploited = check_cisa_kev(cve_id)
                        if cisa_exploited:
                            print(f"    🔴 CISA KEV: {cve_id} actively exploited!")
                        time.sleep(2)  # NVD rate limiting
                    
                    # 3️⃣ Exploitation Reality Check
                    exploitation_status = determine_exploitation_status(
                        title, summary, cisa_exploited, bool(cve_id)
                    )
                    
                    # 4️⃣ Source Confidence
                    source_confidence = determine_source_confidence(source_name, url, title)
                    
                    # 5️⃣ Attack Name Identification
                    attack_name = extract_attack_name(title, summary)
                    
                    # 6️⃣ MITRE ATT&CK & Kill Chain
                    mitre_mapping = map_to_mitre_attack(title, summary)
                    kill_chain_phases = map_to_kill_chain(title, summary)
                    
                    # 7️⃣ Technical Method
                    technical_method = extract_technical_method(title, summary, event_data['attack_vector'])
                    
                    # 8️⃣ MDR Analyst Take
                    mdr_analyst_take = generate_mdr_analyst_take(
                        event_data['event_type'],
                        event_data['primary_target'],
                        event_data['attack_vector'],
                        exploitation_status,
                        title,
                        summary,
                        cve_id,
                        cve_data.get('cvss_score'),
                        attack_name
                    )
                    
                    # 9️⃣ Delta Reason
                    delta_reason = extract_delta_reason(title, summary, exploitation_status)
                    
                    # 🔟 Pattern Tags
                    pattern_tags = extract_pattern_tags(title, summary, event_data['attack_vector'], event_data['event_type'])
                    
                    # Calculate weaponization speed
                    article_dt = datetime.fromisoformat(published_at)
                    weaponization_speed = calculate_weaponization_speed(cve_data.get('cve_published_date'), article_dt)
                    
                    # Signal Strength
                    has_technical_detail = len(summary) > 300  # Proxy for technical depth
                    signal_strength, signal_reason = calculate_signal_strength(
                        exploitation_status,
                        source_confidence,
                        bool(cve_id),
                        cve_data.get('cvss_score'),
                        cisa_exploited,
                        has_technical_detail,
                        len(summary)
                    )
                    
                    # Story Hash for de-duplication
                    story_hash = generate_story_hash(cve_id, None, attack_name, event_data['primary_target'])
                    
                    # First observed date
                    first_observed_date = cve_data.get('cve_published_date') or published_at[:10]
                    
                    # Calculate threat velocity
                    threat_velocity = calculate_threat_velocity(
                        first_observed_date,
                        exploitation_status,
                        cve_data.get('cve_published_date')
                    )
                    
                    # Build evidence list (for transparency)
                    evidence_sources, evidence_count = build_evidence_list(
                        cisa_exploited,
                        source_name,
                        cve_data.get('cvss_score'),
                        has_technical_detail,
                        cve_id,
                        exploitation_status
                    )
                    
                    # Classify unknown reason if needed
                    unknown_reason = None
                    if exploitation_status == 'unknown':
                        unknown_reason = classify_unknown_reason(title, summary, cve_id, source_name)
                    
                    # Create embedding
                    embedding_text = f"{title} {summary}"
                    embedding = embed_model.encode(embedding_text).tolist()
                    
                    # Build MDR intelligence item
                    item = {
                        # Core fields
                        'source': source_name,
                        'title': title,
                        'url': url,
                        'summary': summary,
                        'published_at': published_at,
                        'embedding': embedding,
                        
                        # Event Normalization
                        'event_type': event_data['event_type'],
                        'primary_target': event_data['primary_target'],
                        'attack_vector': event_data['attack_vector'],
                        'impact_outcome': event_data['impact_outcome'],
                        
                        # Exploitation Reality
                        'first_observed_date': first_observed_date,
                        'exploitation_status': exploitation_status,
                        'weaponization_speed': weaponization_speed,
                        
                        # Intelligence
                        'mdr_analyst_take': mdr_analyst_take,
                        'technical_method': technical_method,
                        'delta_reason': delta_reason,
                        
                        # Signal & Source
                        'signal_strength': signal_strength,
                        'signal_strength_reason': signal_reason,
                        'source_confidence': source_confidence,
                        'has_technical_detail': has_technical_detail,
                        'article_quality_score': min(100, len(summary) // 5),
                        
                        # Evidence & Transparency
                        'evidence_sources': evidence_sources,
                        'evidence_count': evidence_count,
                        'threat_velocity': threat_velocity,
                        'unknown_reason': unknown_reason,
                        'last_collector_run': datetime.now(timezone.utc).isoformat(),
                        
                        # Pattern & Trends
                        'pattern_tags': pattern_tags,
                        'story_hash': story_hash,
                        
                        # CVE Data
                        'cve_id': cve_id,
                        'cvss_score': cve_data.get('cvss_score'),
                        'cvss_vector': cve_data.get('cvss_vector'),
                        'cve_published_date': cve_data.get('cve_published_date'),
                        'cisa_exploited': cisa_exploited,
                        
                        # Attack Frameworks
                        'attack_name': attack_name,
                        'mitre_tactics': mitre_mapping['tactics'],
                        'mitre_techniques': mitre_mapping['techniques'],
                        'kill_chain_phases': kill_chain_phases,
                        
                        # Metadata
                        'has_iocs': bool(cve_id),  # CVE is a type of IOC
                    }
                    
                    items.append(item)
                    count += 1
                    
                    # Status emoji based on signal strength and exploitation
                    status_emoji = "🔴" if exploitation_status == 'actively_exploited' else \
                                   "🟡" if exploitation_status == 'poc_available' else \
                                   "🟢"
                    
                    print(f"    {status_emoji} {event_data['event_type']}: {title[:60]}... [{signal_strength} signal]")
                    
                except Exception as e:
                    print(f"    ❌ Error processing entry: {e}")
                    continue
            
            print(f"    ✅ Collected {count} intelligence items from {source_name}")
            
        except Exception as e:
            print(f"    ❌ Error fetching {source_name}: {e}")
    
    return items


def save_to_supabase(items: List[Dict]) -> int:
    """Save intelligence items to Supabase and populate knowledge graph"""
    print(f"\n💾 Saving {len(items)} intelligence items to database...")
    
    # Initialize knowledge graph manager
    kg_manager = KnowledgeGraphManager(supabase)
    
    saved = 0
    escalations_detected = 0
    total_topics = 0
    total_iocs = 0
    total_relationships = 0
    
    for item in items:
        try:
            # Check for existing record to detect escalations
            existing = supabase.table('daily_brief').select(
                'id', 'exploitation_status', 'signal_strength', 'url'
            ).eq('url', item['url']).execute()
            
            # Detect exploitation status escalation
            if existing.data and len(existing.data) > 0:
                old_record = existing.data[0]
                old_status = old_record.get('exploitation_status', 'unknown')
                new_status = item.get('exploitation_status', 'unknown')
                old_signal = old_record.get('signal_strength', 'Low')
                new_signal = item.get('signal_strength', 'Low')
                
                # Define escalation hierarchy
                status_hierarchy = {
                    'unknown': 0,
                    'theoretical': 1,
                    'poc_available': 2,
                    'actively_exploited': 3
                }
                
                signal_hierarchy = {
                    'Low': 0,
                    'Medium': 1,
                    'High': 2
                }
                
                # Check exploitation status escalation
                if status_hierarchy.get(new_status, 0) > status_hierarchy.get(old_status, 0):
                    item['previous_exploitation_status'] = old_status
                    item['exploitation_escalated_at'] = datetime.now(timezone.utc).isoformat()
                    escalations_detected += 1
                    print(f"    ⬆️  ESCALATION DETECTED: {item['title'][:60]} - {old_status} → {new_status}")
                
                # Check signal strength upgrade
                if signal_hierarchy.get(new_signal, 0) > signal_hierarchy.get(old_signal, 0):
                    item['previous_signal_strength'] = old_signal
                    item['signal_upgraded_at'] = datetime.now(timezone.utc).isoformat()
            
            # Save article to database
            result = supabase.table('daily_brief').upsert(
                item,
                on_conflict='url'
            ).execute()
            
            if result.data and len(result.data) > 0:
                article_id = result.data[0]['id']
                saved += 1
                
                # Extract entities and populate knowledge graph
                article_data = {
                    'title': item.get('title', ''),
                    'description': item.get('description', ''),
                    'content': item.get('summary', ''),
                }
                
                stats = kg_manager.process_article(article_id, article_data)
                total_topics += stats['topics_linked']
                total_iocs += stats['iocs_stored']
                total_relationships += stats['relationships_created']
                
        except Exception as e:
            print(f"    ❌ Error saving {item['title'][:50]}: {e}")
    
    print(f"    ✅ Successfully saved {saved}/{len(items)} items")
    if escalations_detected > 0:
        print(f"    ⬆️  Detected {escalations_detected} escalations (exploitation or signal upgrades)")
    print(f"    🔗 Linked {total_topics} topics, stored {total_iocs} IOCs, created {total_relationships} relationships")
    
    return saved


def print_summary(items: List[Dict]):
    """Print MDR-focused summary"""
    print("\n" + "=" * 80)
    print("📊 MDR INTELLIGENCE SUMMARY")
    print("=" * 80)
    
    # Signal strength breakdown
    high = sum(1 for i in items if i.get('signal_strength') == 'High')
    medium = sum(1 for i in items if i.get('signal_strength') == 'Medium')
    low = sum(1 for i in items if i.get('signal_strength') == 'Low')
    
    print(f"\n🎯 Signal Strength Distribution:")
    print(f"   🔴 High Signal: {high} items (requires immediate attention)")
    print(f"   🟡 Medium Signal: {medium} items (monitor)")
    print(f"   🟢 Low Signal: {low} items (awareness)")
    
    # Exploitation status
    active = sum(1 for i in items if i.get('exploitation_status') == 'actively_exploited')
    poc = sum(1 for i in items if i.get('exploitation_status') == 'poc_available')
    
    print(f"\n⚠️  Exploitation Reality:")
    print(f"   🔴 Actively Exploited: {active} threats")
    print(f"   🟡 PoC Available: {poc} threats")
    
    # Event types
    event_types = {}
    for item in items:
        et = item.get('event_type', 'Unknown')
        event_types[et] = event_types.get(et, 0) + 1
    
    print(f"\n📋 Event Type Breakdown:")
    for et, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   • {et}: {count}")
    
    # CVEs found
    cves = [i.get('cve_id') for i in items if i.get('cve_id')]
    if cves:
        print(f"\n🔍 CVEs Identified: {len(cves)}")
        cisa_kev = [i for i in items if i.get('cisa_exploited')]
        if cisa_kev:
            print(f"   ⚠️  CISA KEV: {len(cisa_kev)} actively exploited")
    
    print("\n" + "=" * 80)


def main():
    """Main execution"""
    start_time = time.time()
    
    # Collect intelligence
    items = collect_rss_feeds()
    
    if not items:
        print("\n⚠️  No intelligence collected. Check RSS feeds.")
        return
    
    # Save to database
    saved = save_to_supabase(items)
    
    # Print summary
    print_summary(items)
    
    elapsed = time.time() - start_time
    print(f"\n⏱️  Intelligence collection completed in {elapsed:.1f} seconds")
    print(f"✅ {saved} intelligence items ready for MDR analyst review")
    print("\n🚀 Launch Streamlit UI to review intelligence: streamlit run app_mdr.py")


if __name__ == "__main__":
    main()
