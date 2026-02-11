"""
CyberMind Entity Extraction Engine
Extracts knowledge entities from cybersecurity articles
- CVEs, IOCs, Threat Actors, Technologies, Attack Types
"""

import re
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class ExtractedEntity:
    """Represents an extracted entity from text"""
    entity_type: str  # 'cve', 'threat_actor', 'technology', 'attack_type', 'ioc_ip', etc.
    value: str
    confidence: float
    context: str = ""  # Surrounding text for validation
    

class EntityExtractor:
    """Extracts structured knowledge from unstructured security articles"""
    
    def __init__(self):
        # CVE pattern: CVE-YYYY-NNNNN
        self.cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
        
        # IOC patterns
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        
        # MITRE ATT&CK technique pattern: T1234 or T1234.001
        self.attck_pattern = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
        
        # Known threat actors (expanded - 60+ APT groups and ransomware gangs)
        self.threat_actors = {
            # Ransomware Groups
            'lockbit': ['lockbit', 'lockbit 3.0', 'lockbit black'],
            'alphv-blackcat': ['alphv', 'blackcat', 'noberus'],
            'cl0p': ['cl0p', 'clop'],
            'conti': ['conti'],
            'revil': ['revil', 'sodinokibi'],
            'akira': ['akira ransomware', 'akira group'],
            'black-basta': ['black basta', 'blackbasta'],
            'play-ransomware': ['play ransomware', 'play group'],
            'royal-ransomware': ['royal ransomware', 'royal group'],
            'bianlian': ['bianlian'],
            'medusa-ransomware': ['medusa ransomware', 'medusa blog'],
            'rhysida': ['rhysida'],
            '8base': ['8base'],
            'monti': ['monti ransomware'],
            'ragnar-locker': ['ragnar locker', 'ragnarlocker'],
            'cuba-ransomware': ['cuba ransomware'],
            'vice-society': ['vice society'],
            'hive': ['hive ransomware'],
            'avoslocker': ['avoslocker'],
            
            # Nation-State APTs - Russia
            'apt28': ['apt28', 'apt 28', 'fancy bear', 'sofacy', 'pawn storm', 'strontium'],
            'apt29': ['apt29', 'apt 29', 'cozy bear', 'the dukes', 'yttrium', 'nobelium'],
            'sandworm': ['sandworm', 'voodoo bear', 'electrum', 'telebots'],
            'turla': ['turla', 'venomous bear', 'waterbug', 'snake'],
            'gamaredon': ['gamaredon', 'primitive bear'],
            'energetic-bear': ['energetic bear', 'crouching yeti'],
            'dragonfly': ['dragonfly', 'crouching yeti'],
            
            # Nation-State APTs - China
            'apt1': ['apt1', 'apt 1', 'comment crew'],
            'apt10': ['apt10', 'apt 10', 'stone panda', 'menupass'],
            'apt27': ['apt27', 'apt 27', 'emissary panda'],
            'apt40': ['apt40', 'apt 40', 'leviathan'],
            'apt41': ['apt41', 'apt 41', 'winnti', 'barium', 'double dragon'],
            'mustang-panda': ['mustang panda', 'red lich'],
            'volt-typhoon': ['volt typhoon'],
            'flax-typhoon': ['flax typhoon'],
            'granite-typhoon': ['granite typhoon'],
            'aquatic-panda': ['aquatic panda'],
            'APT15': ['apt15', 'apt 15', 'vixen panda', 'ke3chang'],
            
            # Nation-State APTs - North Korea
            'lazarus-group': ['lazarus', 'lazarus group', 'hidden cobra', 'guardians of peace', 'zinc'],
            'kimsuky': ['kimsuky', 'thallium', 'black banshee'],
            'andariel': ['andariel'],
            'bluenoroff': ['bluenoroff'],
            'apt38': ['apt38', 'apt 38'],
            
            # Nation-State APTs - Iran
            'apt33': ['apt33', 'apt 33', 'elfin', 'holmium'],
            'apt34': ['apt34', 'apt 34', 'oilrig', 'helix kitten'],
            'apt35': ['apt35', 'apt 35', 'charming kitten', 'phosphorus'],
            'muddywater': ['muddywater', 'muddy water'],
            'moses-staff': ['moses staff'],
            
            # Nation-State APTs - Middle East
            'apt28': ['apt28', 'apt 28'],
            'molerats': ['molerats', 'gaza cybergang'],
            
            # FIN Groups
            'fin7': ['fin7', 'carbanak', 'fin 7'],
            'fin11': ['fin11', 'fin 11'],
            'fin12': ['fin12', 'fin 12'],
            
            # TA Groups  
            'ta505': ['ta505', 'ta 505'],
            'ta558': ['ta558', 'ta 558'],
            'ta577': ['ta577', 'ta 577'],
            
            # Other Notable Groups
            'wizard-spider': ['wizard spider'],
            'scattered-spider': ['scattered spider', 'octo tempest'],
            'lapsus': ['lapsus', 'lapsus$'],
            'hafnium': ['hafnium'],
            'bronze-butler': ['bronze butler', 'tick'],
            'carbanak': ['carbanak'],
            'emotet': ['emotet'],
            'trickbot': ['trickbot'],
            'qakbot': ['qakbot', 'qbot'],
            'icedid': ['icedid'],
        }
        
        # Known technologies (expanded - 60+ common CVE targets)
        self.technologies = {
            # Microsoft Products
            'microsoft-exchange': ['microsoft exchange', 'exchange server', 'ms exchange'],
            'windows-server': ['windows server', 'windows 10', 'windows 11', 'windows os'],
            'microsoft-iis': ['iis', 'microsoft iis', 'internet information services'],
            'sharepoint': ['sharepoint', 'microsoft sharepoint'],
            'active-directory': ['active directory', 'ad', 'azure ad', 'entra id'],
            'microsoft-sql': ['sql server', 'mssql', 'microsoft sql'],
            'azure': ['azure', 'microsoft azure'],
            'office-365': ['office 365', 'o365', 'microsoft 365', 'm365'],
            
            # VMware Products
            'vmware-esxi': ['vmware esxi', 'esxi', 'vmware vcenter'],
            'vmware-vcenter': ['vcenter', 'vmware vcenter'],
            'vmware-horizon': ['vmware horizon', 'horizon view'],
            'vmware-nsx': ['vmware nsx', 'nsx manager'],
            
            # Apache Products
            'apache-log4j': ['log4j', 'log4shell', 'apache log4j'],
            'apache-tomcat': ['apache tomcat', 'tomcat'],
            'apache-httpd': ['apache http', 'apache web server', 'apache2'],
            'apache-struts': ['apache struts', 'struts'],
            
            # Networking/Security Appliances
            'cisco-ios': ['cisco ios', 'cisco router', 'cisco switch'],
            'fortinet-fortigate': ['fortinet', 'fortigate', 'fortios'],
            'citrix-netscaler': ['citrix', 'netscaler', 'citrix adc'],
            'palo-alto': ['palo alto', 'pan-os', 'palo alto firewall'],
            'juniper': ['juniper', 'junos'],
            'checkpoint': ['checkpoint', 'check point'],
            'f5-big-ip': ['f5 big-ip', 'big-ip', 'f5 networks'],
            'sonicwall': ['sonicwall'],
            'barracuda': ['barracuda'],
            'pulse-secure': ['pulse secure', 'ivanti connect secure'],
            'ivanti': ['ivanti'],
            'sophos': ['sophos firewall', 'sophos xg'],
            'watchguard': ['watchguard'],
            
            # Web/App Servers
            'nginx': ['nginx'],
            'oracle-weblogic': ['weblogic', 'oracle weblogic'],
            'jboss': ['jboss', 'wildfly'],
            'websphere': ['websphere', 'ibm websphere'],
            
            # Collaboration/Productivity
            'confluence': ['confluence', 'atlassian confluence'],
            'jira': ['jira', 'atlassian jira'],
            'slack': ['slack'],
            'zoom': ['zoom'],
            'microsoft-teams': ['microsoft teams', 'teams'],
            
            # Identity/SSO
            'okta': ['okta'],
            'auth0': ['auth0'],
            'ping-identity': ['ping identity', 'pingfederate'],
            'onelogin': ['onelogin'],
            
            # Cloud Platforms
            'aws': ['aws', 'amazon web services'],
            'azure': ['azure', 'microsoft azure'],
            'gcp': ['gcp', 'google cloud', 'google cloud platform'],
            
            # Container/Orchestration
            'kubernetes': ['kubernetes', 'k8s'],
            'docker': ['docker', 'docker container'],
            'openshift': ['openshift', 'red hat openshift'],
            
            # Databases
            'mysql': ['mysql'],
            'postgresql': ['postgresql', 'postgres'],
            'mongodb': ['mongodb', 'mongo'],
            'redis': ['redis'],
            'elasticsearch': ['elasticsearch'],
            
            # CMS/E-commerce
            'wordpress': ['wordpress', 'wp'],
            'drupal': ['drupal'],
            'joomla': ['joomla'],
            'magento': ['magento'],
            'woocommerce': ['woocommerce'],
            
            # VPN/Remote Access
            'citrix-gateway': ['citrix gateway', 'citrix netscaler gateway'],
            'fortinet-vpn': ['fortinet vpn', 'forticlient'],
            'cisco-anyconnect': ['cisco anyconnect'],
            
            # Backup/Storage
            'veeam': ['veeam', 'veeam backup'],
            'commvault': ['commvault'],
            'rubrik': ['rubrik'],
        }
        
        # Common attack types (expanded)
        self.attack_types = {
            'ransomware': ['ransomware', 'crypto-locker', 'file encryption', 'ransom demand'],
            'supply-chain': ['supply chain', 'supply-chain', 'third-party compromise', '3rd party attack'],
            'zero-day': ['zero-day', 'zero day', '0-day', 'zeroday', 'n-day'],
            'sql-injection': ['sql injection', 'sqli', 'sql vuln'],
            'ddos': ['ddos', 'denial of service', 'dos attack', 'amplification attack'],
            'man-in-the-middle': ['man-in-the-middle', 'mitm', 'man in the middle'],
            'credential-stuffing': ['credential stuffing', 'password spray', 'brute force'],
            'business-email-compromise': ['bec', 'business email compromise', 'email fraud'],
            'phishing': ['phishing', 'spear phishing', 'spearphishing', 'malicious email'],
            'web-shell': ['web shell', 'webshell', 'command injection'],
            'privilege-escalation': ['privilege escalation', 'privesc', 'local exploit'],
            'remote-code-execution': ['rce', 'remote code execution', 'arbitrary code'],
            'path-traversal': ['path traversal', 'directory traversal', 'lfi', 'local file inclusion'],
            'xss': ['xss', 'cross-site scripting', 'stored xss', 'reflected xss'],
            'command-injection': ['command injection', 'os command injection'],
            'buffer-overflow': ['buffer overflow', 'heap overflow', 'stack overflow'],
            'data-breach': ['data breach', 'data leak', 'data exfiltration', 'stolen data'],
            'backdoor': ['backdoor', 'persistence mechanism'],
            'cryptojacking': ['cryptojacking', 'crypto mining', 'illicit mining'],
            'watering-hole': ['watering hole', 'wateringhole', 'strategic web compromise'],
            'living-off-the-land': ['living off the land', 'lolbins', 'lotl'],
            'pass-the-hash': ['pass the hash', 'pass-the-hash', 'pth'],
            'golden-ticket': ['golden ticket', 'silver ticket', 'kerberos attack'],
            'dcsync': ['dcsync', 'dc sync', 'domain controller sync'],
            'lateral-movement': ['lateral movement', 'east-west movement'],
            'exfiltration': ['data exfiltration', 'data theft', 'data stealing'],
        }
        
        # Malware families
        self.malware_families = {
            'cobalt-strike': ['cobalt strike', 'beacon'],
            'mimikatz': ['mimikatz'],
            'metasploit': ['metasploit', 'meterpreter'],
            'powershell-empire': ['powershell empire', 'empire'],
            'sliver': ['sliver c2'],
            'brute-ratel': ['brute ratel', 'bruteratel'],
            'darkside': ['darkside'],
            'maze': ['maze ransomware'],
            'ryuk': ['ryuk'],
            'wannacry': ['wannacry', 'wanna cry'],
            'notpetya': ['notpetya', 'not petya'],
            'dridex': ['dridex'],
            'ursnif': ['ursnif', 'gozi'],
            'njrat': ['njrat', 'bladabindi'],
            'asyncrat': ['asyncrat'],
            'xworm': ['xworm'],
            'agenttesla': ['agent tesla', 'agenttesla'],
            'formbook': ['formbook'],
            'redline-stealer': ['redline', 'redline stealer'],
            'vidar': ['vidar stealer'],
            'raccoon-stealer': ['raccoon stealer'],
        }
    
    def extract_all(self, text: str, title: str = "") -> Dict[str, List[ExtractedEntity]]:
        """Extract all entity types from text"""
        combined_text = f"{title} {text}".lower()
        
        entities = {
            'cves': self.extract_cves(combined_text),
            'threat_actors': self.extract_threat_actors(combined_text),
            'technologies': self.extract_technologies(combined_text),
            'attack_types': self.extract_attack_types(combined_text),
            'malware': self.extract_malware(combined_text),
            'iocs': self.extract_iocs(text),  # Case-sensitive for hashes
            'attck_techniques': self.extract_attck_techniques(combined_text),
        }
        
        return entities
    
    def extract_cves(self, text: str) -> List[ExtractedEntity]:
        """Extract CVE identifiers"""
        matches = self.cve_pattern.findall(text)
        return [
            ExtractedEntity(
                entity_type='cve',
                value=cve.upper(),
                confidence=1.0
            )
            for cve in set(matches)
        ]
    
    def extract_threat_actors(self, text: str) -> List[ExtractedEntity]:
        """Extract threat actor mentions"""
        found = []
        text_lower = text.lower()
        
        for slug, aliases in self.threat_actors.items():
            for alias in aliases:
                # Use word boundaries to avoid false positives
                pattern = r'\b' + re.escape(alias) + r'\b'
                if re.search(pattern, text_lower):
                    found.append(ExtractedEntity(
                        entity_type='threat_actor',
                        value=slug,
                        confidence=0.9 if len(alias) > 5 else 0.7
                    ))
                    break  # Only count once per actor
        
        return found
    
    def extract_technologies(self, text: str) -> List[ExtractedEntity]:
        """Extract technology/product mentions"""
        found = []
        text_lower = text.lower()
        
        for slug, aliases in self.technologies.items():
            for alias in aliases:
                # Case-insensitive search
                if alias.lower() in text_lower:
                    found.append(ExtractedEntity(
                        entity_type='technology',
                        value=slug,
                        confidence=0.85
                    ))
                    break  # Only count once per technology
        
        return found
    
    def extract_attack_types(self, text: str) -> List[ExtractedEntity]:
        """Extract attack type mentions"""
        found = []
        text_lower = text.lower()
        
        for slug, aliases in self.attack_types.items():
            for alias in aliases:
                if alias.lower() in text_lower:
                    found.append(ExtractedEntity(
                        entity_type='attack_type',
                        value=slug,
                        confidence=0.8
                    ))
                    break  # Only count once per attack type
        
        return found
    
    def extract_malware(self, text: str) -> List[ExtractedEntity]:
        """Extract malware family mentions"""
        found = []
        text_lower = text.lower()
        
        for slug, aliases in self.malware_families.items():
            for alias in aliases:
                pattern = r'\b' + re.escape(alias) + r'\b'
                if re.search(pattern, text_lower):
                    found.append(ExtractedEntity(
                        entity_type='malware',
                        value=slug,
                        confidence=0.85
                    ))
                    break  # Only count once per malware family
        
        return found
    
    def extract_iocs(self, text: str) -> List[ExtractedEntity]:
        """Extract Indicators of Compromise"""
        iocs = []
        
        # IP addresses
        for ip in set(self.ip_pattern.findall(text)):
            if self._is_valid_ip(ip):
                iocs.append(ExtractedEntity(
                    entity_type='ioc_ip',
                    value=ip,
                    confidence=0.7  # Lower confidence, many false positives
                ))
        
        # Domains (filter out common false positives)
        for domain in set(self.domain_pattern.findall(text)):
            if self._is_likely_malicious_domain(domain):
                iocs.append(ExtractedEntity(
                    entity_type='ioc_domain',
                    value=domain.lower(),
                    confidence=0.6
                ))
        
        # File hashes
        for sha256 in set(self.sha256_pattern.findall(text)):
            iocs.append(ExtractedEntity(
                entity_type='ioc_hash_sha256',
                value=sha256.lower(),
                confidence=0.95
            ))
        
        for md5 in set(self.md5_pattern.findall(text)):
            iocs.append(ExtractedEntity(
                entity_type='ioc_hash_md5',
                value=md5.lower(),
                confidence=0.95
            ))
        
        for sha1 in set(self.sha1_pattern.findall(text)):
            iocs.append(ExtractedEntity(
                entity_type='ioc_hash_sha1',
                value=sha1.lower(),
                confidence=0.95
            ))
        
        return iocs
    
    def extract_attck_techniques(self, text: str) -> List[ExtractedEntity]:
        """Extract MITRE ATT&CK technique IDs"""
        matches = self.attck_pattern.findall(text)
        return [
            ExtractedEntity(
                entity_type='attck_technique',
                value=tech.upper(),
                confidence=1.0
            )
            for tech in set(matches)
        ]
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address and filter out common false positives"""
        octets = ip.split('.')
        try:
            octets = [int(o) for o in octets]
            # Check valid range
            if any(o < 0 or o > 255 for o in octets):
                return False
            # Filter out private IPs and common false positives
            if octets[0] in [10, 127]:  # Private/loopback
                return False
            if octets[0] == 192 and octets[1] == 168:  # Private
                return False
            if octets[0] == 172 and 16 <= octets[1] <= 31:  # Private
                return False
            # Filter out version numbers (1.0.0.0)
            if octets == [0, 0, 0, 0]:
                return False
            return True
        except (ValueError, IndexError):
            return False
    
    def _is_likely_malicious_domain(self, domain: str) -> bool:
        """Filter out legitimate domains to reduce false positives"""
        domain_lower = domain.lower()
        
        # Common legitimate TLDs to filter
        legitimate_domains = [
            '.com', '.org', '.net', '.edu', '.gov',
            'microsoft.com', 'apple.com', 'google.com', 'github.com',
            'amazon.com', 'azure.com', 'cisco.com', 'vmware.com',
            'example.com', 'test.com', 'localhost'
        ]
        
        # If it's a known legitimate domain, reject
        for legit in legitimate_domains:
            if domain_lower.endswith(legit) and len(domain_lower.split('.')) <= 3:
                return False
        
        # Accept if it looks suspicious (many hyphens, weird TLD, etc.)
        if domain_lower.count('-') > 2:
            return True
        if any(domain_lower.endswith(tld) for tld in ['.xyz', '.top', '.tk', '.ml', '.ga']):
            return True
        
        # Otherwise, need more context - return False to avoid noise
        return False


def create_topic_slug(name: str) -> str:
    """Convert entity name to URL-friendly slug"""
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-')


def extract_and_format(article: Dict) -> Dict:
    """
    Extract entities from an article and format for database insertion
    
    Args:
        article: Dict with 'title', 'content', 'description' fields
    
    Returns:
        Dict with extracted entities ready for DB insertion
    """
    extractor = EntityExtractor()
    
    # Combine all text fields
    full_text = f"{article.get('title', '')} {article.get('description', '')} {article.get('content', '')}"
    
    # Extract all entities
    entities = extractor.extract_all(full_text, article.get('title', ''))
    
    return {
        'cves': [e.value for e in entities['cves']],
        'threat_actors': [e.value for e in entities['threat_actors']],
        'technologies': [e.value for e in entities['technologies']],
        'attack_types': [e.value for e in entities['attack_types']],
        'iocs': {
            'ips': [e.value for e in entities['iocs'] if e.entity_type == 'ioc_ip'],
            'domains': [e.value for e in entities['iocs'] if e.entity_type == 'ioc_domain'],
            'hashes': [e.value for e in entities['iocs'] if 'hash' in e.entity_type],
        },
        'attck_techniques': [e.value for e in entities['attck_techniques']],
    }


if __name__ == '__main__':
    # Test the extractor
    test_article = {
        'title': 'LockBit Ransomware Exploits CVE-2024-1234 in VMware ESXi',
        'description': 'The LockBit ransomware gang has been observed exploiting a critical RCE vulnerability in VMware ESXi servers.',
        'content': '''
        Security researchers have identified a new campaign by the LockBit ransomware group targeting 
        VMware ESXi servers through CVE-2024-1234, a remote code execution vulnerability with a CVSS 
        score of 9.8. The attackers use MITRE ATT&CK technique T1190 (Exploit Public-Facing Application) 
        to gain initial access. The malicious payload contacts C2 server at 192.168.1.100 and drops a 
        web shell for persistence. Indicators include SHA256 hash 
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        '''
    }
    
    entities = extract_and_format(test_article)
    
    print("🔍 Entity Extraction Test Results")
    print("=" * 60)
    print(f"CVEs found: {entities['cves']}")
    print(f"Threat actors: {entities['threat_actors']}")
    print(f"Technologies: {entities['technologies']}")
    print(f"Attack types: {entities['attack_types']}")
    print(f"ATT&CK techniques: {entities['attck_techniques']}")
    print(f"IOCs - IPs: {entities['iocs']['ips']}")
    print(f"IOCs - Domains: {entities['iocs']['domains']}")
    print(f"IOCs - Hashes: {entities['iocs']['hashes']}")
