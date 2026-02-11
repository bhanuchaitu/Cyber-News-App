"""
Knowledge Graph Manager
Handles topic creation, linking, and relationship management
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone
from supabase import Client
from entity_extractor import EntityExtractor, extract_and_format


class KnowledgeGraphManager:
    """Manages the knowledge graph - topics, relationships, IOCs"""
    
    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.extractor = EntityExtractor()
        
        # Cache topics to avoid repeated DB queries
        self.topic_cache = {}
    
    def process_article(self, article_id: int, article_data: Dict) -> Dict:
        """
        Extract entities from article and populate knowledge graph
        
        Returns: Dict with extraction statistics
        """
        # Extract all entities
        entities = extract_and_format(article_data)
        
        stats = {
            'topics_created': 0,
            'topics_linked': 0,
            'iocs_stored': 0,
            'attck_linked': 0,
            'relationships_created': 0,
        }
        
        # Track all topic IDs for relationship building
        topic_ids = []
        
        # Process CVEs
        for cve in entities['cves']:
            topic_id = self._ensure_topic_exists(
                slug=cve.lower(),
                name=cve.upper(),
                description="Common Vulnerabilities and Exposures identifier",
                topic_type='cve'
            )
            if topic_id:
                topic_ids.append(('cve', topic_id))
                self._link_article_to_topic(article_id, topic_id, 1.0, 'regex')
                stats['topics_linked'] += 1
        
        # Process Threat Actors
        for actor_slug in entities['threat_actors']:
            topic_id = self._get_or_create_preseeded_topic(actor_slug)
            if topic_id:
                topic_ids.append(('threat_actor', topic_id))
                self._link_article_to_topic(article_id, topic_id, 0.9, 'keyword')
                stats['topics_linked'] += 1
        
        # Process Technologies
        for tech_slug in entities['technologies']:
            topic_id = self._get_or_create_preseeded_topic(tech_slug)
            if topic_id:
                topic_ids.append(('technology', topic_id))
                self._link_article_to_topic(article_id, topic_id, 0.85, 'keyword')
                stats['topics_linked'] += 1
        
        # Process Attack Types
        for attack_slug in entities['attack_types']:
            topic_id = self._get_or_create_preseeded_topic(attack_slug)
            if topic_id:
                topic_ids.append(('attack_type', topic_id))
                self._link_article_to_topic(article_id, topic_id, 0.8, 'keyword')
                stats['topics_linked'] += 1
        
        # Process Malware
        for malware_slug in entities.get('malware', []):
            topic_id = self._get_or_create_preseeded_topic(malware_slug)
            if topic_id:
                topic_ids.append(('malware', topic_id))
                self._link_article_to_topic(article_id, topic_id, 0.85, 'keyword')
                stats['topics_linked'] += 1
        
        # Process IOCs
        ioc_count = 0
        for ip in entities['iocs']['ips']:
            if self._store_ioc('ip', ip, article_id):
                ioc_count += 1
        
        for domain in entities['iocs']['domains']:
            if self._store_ioc('domain', domain, article_id):
                ioc_count += 1
        
        for hash_val in entities['iocs']['hashes']:
            # Map hash length to type: 64=SHA256, 40=SHA1, 32=MD5
            hash_length = len(hash_val)
            if hash_length == 64:
                hash_type = "hash_sha256"
            elif hash_length == 40:
                hash_type = "hash_sha1"
            elif hash_length == 32:
                hash_type = "hash_md5"
            else:
                hash_type = "hash_unknown"
            
            if self._store_ioc(hash_type, hash_val, article_id):
                ioc_count += 1
        
        stats['iocs_stored'] = ioc_count
        
        # Link to MITRE ATT&CK techniques
        for technique_id in entities['attck_techniques']:
            if self._link_article_to_attck(article_id, technique_id):
                stats['attck_linked'] += 1
        
        # Build relationships between topics
        relationships = self._build_topic_relationships(topic_ids, article_id)
        stats['relationships_created'] = relationships
        
        return stats
    
    def _ensure_topic_exists(self, slug: str, name: str, description: str, topic_type: str) -> Optional[int]:
        """Ensure topic exists, create if not, return topic_id"""
        # Check cache
        if slug in self.topic_cache:
            return self.topic_cache[slug]
        
        try:
            # Check if exists
            result = self.supabase.table('topics').select('id').eq('slug', slug).execute()
            
            if result.data and isinstance(result.data, list) and len(result.data) > 0:
                item = result.data[0]
                if isinstance(item, dict):
                    id_val = item.get('id')
                    if isinstance(id_val, (int, str)):
                        topic_id = int(id_val)
                        self.topic_cache[slug] = topic_id
                        return topic_id
            
            # Create new topic
            topic_data = {
                'slug': slug,
                'name': name,
                'description': description,
                'type': topic_type,
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'last_seen': datetime.now(timezone.utc).isoformat(),
            }
            
            result = self.supabase.table('topics').insert(topic_data).execute()
            
            if result.data and isinstance(result.data, list) and len(result.data) > 0:
                item = result.data[0]
                if isinstance(item, dict):
                    id_val = item.get('id')
                    if isinstance(id_val, int) or isinstance(id_val, str):
                        topic_id = int(id_val)
                        self.topic_cache[slug] = topic_id
                        return topic_id
            
        except Exception as e:
            print(f"    ⚠️  Error ensuring topic {slug}: {e}")
        
        return None
    
    def _get_or_create_preseeded_topic(self, slug: str) -> Optional[int]:
        """Get pre-seeded topic ID (threat actors, technologies, attack types)"""
        if slug in self.topic_cache:
            return self.topic_cache[slug]
        
        try:
            result = self.supabase.table('topics').select('id').eq('slug', slug).execute()
            
            if result.data and isinstance(result.data, list) and len(result.data) > 0:
                item = result.data[0]
                if isinstance(item, dict):
                    id_val = item.get('id')
                    if isinstance(id_val, (int, str)):
                        topic_id = int(id_val)
                        self.topic_cache[slug] = topic_id
                        return topic_id
        except Exception as e:
            print(f"    ⚠️  Error fetching topic {slug}: {e}")
        
        return None
    
    def _link_article_to_topic(self, article_id: int, topic_id: int, relevance: float, method: str) -> bool:
        """Create article-topic link"""
        try:
            link_data = {
                'article_id': article_id,
                'topic_id': topic_id,
                'relevance_score': relevance,
                'extraction_method': method,
            }
            
            self.supabase.table('article_topics').upsert(link_data, on_conflict='article_id,topic_id').execute()
            return True
        except Exception as e:
            print(f"    ⚠️  Error linking article {article_id} to topic {topic_id}: {e}")
            return False
    
    def _store_ioc(self, ioc_type: str, value: str, article_id: int) -> bool:
        """Store IOC (Indicator of Compromise)"""
        try:
            ioc_data = {
                'ioc_type': ioc_type,
                'value': value,
                'article_id': article_id,
                'confidence': 0.7,  # Default confidence
                'active': True,
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'last_seen': datetime.now(timezone.utc).isoformat(),
                'source': 'article',
            }
            
            self.supabase.table('iocs').upsert(ioc_data, on_conflict='ioc_type,value').execute()
            return True
        except Exception:
            # Silent fail for IOCs to avoid noise
            return False
    
    def _link_article_to_attck(self, article_id: int, technique_id: str) -> bool:
        """Link article to MITRE ATT&CK technique"""
        try:
            link_data = {
                'article_id': article_id,
                'technique_id': technique_id,
                'confidence': 0.9,
            }
            
            self.supabase.table('article_attck').upsert(link_data, on_conflict='article_id,technique_id').execute()
            return True
        except Exception as e:
            print(f"    ⚠️  Error linking ATT&CK {technique_id}: {e}")
            return False
    
    def _build_topic_relationships(self, topic_ids: List[tuple], article_id: int) -> int:
        """
        Build relationships between topics found in the same article
        
        Examples:
        - threat_actor -> cve: 'exploits'
        - threat_actor -> technology: 'targets'
        - cve -> technology: 'affects'
        - attack_type -> technology: 'targets'
        """
        relationships_created = 0
        
        # Extract topic types and IDs
        threat_actors = [tid for ttype, tid in topic_ids if ttype == 'threat_actor']
        cves = [tid for ttype, tid in topic_ids if ttype == 'cve']
        technologies = [tid for ttype, tid in topic_ids if ttype == 'technology']
        attack_types = [tid for ttype, tid in topic_ids if ttype == 'attack_type']
        
        # Build relationships
        # threat_actor -> cve: 'exploits'
        for actor_id in threat_actors:
            for cve_id in cves:
                if self._create_relationship(actor_id, cve_id, 'exploits'):
                    relationships_created += 1
        
        # threat_actor -> technology: 'targets'
        for actor_id in threat_actors:
            for tech_id in technologies:
                if self._create_relationship(actor_id, tech_id, 'targets'):
                    relationships_created += 1
        
        # cve -> technology: 'affects'
        for cve_id in cves:
            for tech_id in technologies:
                if self._create_relationship(cve_id, tech_id, 'affects'):
                    relationships_created += 1
        
        # attack_type -> technology: 'targets' (e.g., ransomware -> windows)
        for attack_id in attack_types:
            for tech_id in technologies:
                if self._create_relationship(attack_id, tech_id, 'targets'):
                    relationships_created += 1
        
        # attack_type -> cve: 'uses' (e.g., ransomware -> CVE-2024-1234)
        for attack_id in attack_types:
            for cve_id in cves:
                if self._create_relationship(attack_id, cve_id, 'uses'):
                    relationships_created += 1
        
        return relationships_created
    
    def _create_relationship(self, source_id: int, target_id: int, rel_type: str) -> bool:
        """Create or update topic relationship"""
        try:
            # Check if relationship exists
            result = self.supabase.table('topic_relationships').select('id, evidence_count, strength').eq('source_topic_id', source_id).eq('target_topic_id', target_id).eq('relationship_type', rel_type).execute()
            
            if result.data and isinstance(result.data, list) and len(result.data) > 0:
                # Update existing relationship
                existing = result.data[0]
                if isinstance(existing, dict):
                    evidence_val = existing.get('evidence_count', 0)
                    strength_val = existing.get('strength', 0.5)
                    id_val = existing.get('id')
                    
                    # Safe type conversions
                    if isinstance(evidence_val, (int, float, str)):
                        new_evidence_count = int(evidence_val) + 1
                    else:
                        new_evidence_count = 1
                    
                    if isinstance(strength_val, (int, float, str)):
                        new_strength = min(1.0, float(strength_val) + 0.1)
                    else:
                        new_strength = 0.5
                    
                    if isinstance(id_val, (int, str)):
                        self.supabase.table('topic_relationships').update({
                            'evidence_count': new_evidence_count,
                            'strength': new_strength,
                            'last_observed': datetime.now(timezone.utc).isoformat(),
                        }).eq('id', int(id_val)).execute()
            else:
                # Create new relationship
                rel_data = {
                    'source_topic_id': source_id,
                    'target_topic_id': target_id,
                    'relationship_type': rel_type,
                    'strength': 0.5,  # Initial strength
                    'evidence_count': 1,
                    'first_observed': datetime.now(timezone.utc).isoformat(),
                    'last_observed': datetime.now(timezone.utc).isoformat(),
                }
                
                self.supabase.table('topic_relationships').insert(rel_data).execute()
            
            return True
        except Exception:
            # Silent fail for relationships to avoid excessive logging
            return False
    
    def get_topic_statistics(self) -> Dict:
        """Get knowledge graph statistics"""
        try:
            topics = self.supabase.table('topics').select('id').execute()
            relationships = self.supabase.table('topic_relationships').select('id').execute()
            iocs = self.supabase.table('iocs').select('id').execute()
            
            return {
                'topics': len(topics.data) if topics.data and isinstance(topics.data, list) else 0,
                'relationships': len(relationships.data) if relationships.data and isinstance(relationships.data, list) else 0,
                'iocs': len(iocs.data) if iocs.data and isinstance(iocs.data, list) else 0,
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {'topics': 0, 'relationships': 0, 'iocs': 0}    
    def search_topics(self, query: str, topic_type: Optional[str] = None, limit: int = 20) -> List[Dict]:
        """
        Search topics by name or slug
        
        Args:
            query: Search term
            topic_type: Filter by type (cve, threat_actor, technology, etc.)
            limit: Max results to return
        """
        try:
            query_builder = self.supabase.table('topics').select('*')
            
            # Text search on name or slug
            query_builder = query_builder.or_(f"name.ilike.%{query}%,slug.ilike.%{query}%")
            
            # Filter by type if specified
            if topic_type:
                query_builder = query_builder.eq('type', topic_type)
            
            result = query_builder.order('article_count', desc=True).limit(limit).execute()
            
            return result.data if result.data and isinstance(result.data, list) else []
        except Exception as e:
            print(f"Error searching topics: {e}")
            return []
    
    def get_topic_with_articles(self, topic_slug: str) -> Optional[Dict]:
        """Get topic with all linked articles"""
        try:
            # Get topic details
            topic_result = self.supabase.table('topics').select('*').eq('slug', topic_slug).execute()
            
            if not topic_result.data or not isinstance(topic_result.data, list) or len(topic_result.data) == 0:
                return None
            
            topic = topic_result.data[0] if isinstance(topic_result.data[0], dict) else {}
            
            # Get linked articles
            article_links = self.supabase.table('article_topics')\
                .select('article_id,confidence,detection_method,daily_brief(id,title,published_at,url,source)')\
                .eq('topic_id', topic.get('id'))\
                .order('confidence', desc=True)\
                .limit(100)\
                .execute()
            
            topic['articles'] = article_links.data if article_links.data and isinstance(article_links.data, list) else []
            
            return topic
        except Exception as e:
            print(f"Error getting topic with articles: {e}")
            return None
    
    def get_topic_relationships(self, topic_identifier: str) -> Dict:
        """Get all relationships for a topic (by slug or ID)
        Args:
            topic_identifier: Topic slug (string) or ID (integer/string of digits)
        """
        try:
            # Validate topic_identifier
            if topic_identifier is None or (isinstance(topic_identifier, str) and not topic_identifier.strip()):
                return {}
            
            # Detect if identifier is an ID (integer or string of digits)
            if isinstance(topic_identifier, int) or (isinstance(topic_identifier, str) and topic_identifier.isdigit()):
                # Query by ID
                topic_result = self.supabase.table('topics').select('id').eq('id', int(topic_identifier)).execute()
            else:
                # Query by slug
                topic_result = self.supabase.table('topics').select('id').eq('slug', topic_identifier).execute()
            
            if not topic_result.data or not isinstance(topic_result.data, list) or len(topic_result.data) == 0:
                return {}
            
            topic_item = topic_result.data[0]
            if not isinstance(topic_item, dict):
                return {}
            
            topic_id = topic_item.get('id')
            
            # Get outgoing relationships (this topic -> targets)
            outgoing = self.supabase.table('topic_relationships')\
                .select('relationship_type,strength,evidence_count,target_topic:target_topic_id(slug,name,type)')\
                .eq('source_topic_id', topic_id)\
                .order('strength', desc=True)\
                .execute()
            
            # Get incoming relationships (sources -> this topic)
            incoming = self.supabase.table('topic_relationships')\
                .select('relationship_type,strength,evidence_count,source_topic:source_topic_id(slug,name,type)')\
                .eq('target_topic_id', topic_id)\
                .order('strength', desc=True)\
                .execute()
            
            return {
                'outgoing': outgoing.data if outgoing.data and isinstance(outgoing.data, list) else [],
                'incoming': incoming.data if incoming.data and isinstance(incoming.data, list) else [],
            }
        except Exception as e:
            print(f"Error getting relationships: {e}")
            return {'outgoing': [], 'incoming': []}
    
    def export_iocs(self, ioc_type: Optional[str] = None, min_confidence: float = 0.0, days: int = 30) -> List[Dict]:
        """
        Export IOCs for SIEM/threat intelligence feeds
        
        Args:
            ioc_type: Filter by type (ip, domain, hash_sha256, etc.)
            min_confidence: Minimum confidence score
            days: Only IOCs observed in last N days
        """
        try:
            query_builder = self.supabase.table('iocs').select('*')
            
            # Filter by type
            if ioc_type:
                query_builder = query_builder.eq('ioc_type', ioc_type)
            
            # Filter by confidence
            if min_confidence > 0:
                query_builder = query_builder.gte('confidence', min_confidence)
            
            # Filter by date (last N days)
            if days > 0:
                cutoff_date = datetime.now(timezone.utc)
                from datetime import timedelta
                cutoff_date = cutoff_date - timedelta(days=days)
                query_builder = query_builder.gte('first_seen', cutoff_date.isoformat())
            
            result = query_builder.order('confidence', desc=True).execute()
            
            return result.data if result.data and isinstance(result.data, list) else []
        except Exception as e:
            print(f"Error exporting IOCs: {e}")
            return []
    
    def get_ioc_statistics(self) -> Dict:
        """Get IOC statistics by type"""
        try:
            # Get all IOCs grouped by type
            result = self.supabase.table('iocs').select('ioc_type').execute()
            
            if not result.data or not isinstance(result.data, list):
                return {}
            
            stats = {}
            for item in result.data:
                if isinstance(item, dict):
                    ioc_type = item.get('ioc_type', 'unknown')
                    stats[ioc_type] = stats.get(ioc_type, 0) + 1
            
            return stats
        except Exception as e:
            print(f"Error getting IOC stats: {e}")
            return {}