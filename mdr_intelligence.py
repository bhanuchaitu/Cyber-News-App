"""
MDR Threat Intelligence Engine
Transforms raw security news into analyst-ready intelligence
"""
import re
from datetime import datetime, timezone
from typing import Dict, Tuple, List, Optional
import hashlib
from date_utils import calculate_days_between


# ============ EVENT NORMALIZATION ============

EVENT_TYPE_PATTERNS = {
    'Vulnerability': [
        r'vulnerability', r'cve-\d{4}-\d+', r'security flaw', r'bug', 
        r'patch', r'zero-day', r'exploit', r'rce', r'sql injection'
    ],
    'Active Exploit': [
        r'actively exploited', r'in the wild', r'weaponized', 
        r'attacks observed', r'exploitation detected', r'mass scanning'
    ],
    'Malware': [
        r'malware', r'ransomware', r'trojan', r'backdoor', r'rat\b',
        r'stealer', r'loader', r'dropper', r'botnet'
    ],
    'Campaign': [
        r'campaign', r'operation\s+\w+', r'apt\d+', r'targeted attack',
        r'threat actor', r'nation-state', r'intrusion set'
    ],
    'Cloud Abuse': [
        r'aws', r'azure', r'gcp', r'cloud', r's3 bucket', r'api abuse',
        r'oauth', r'saas', r'tenant', r'identity'
    ],
    'Supply Chain': [
        r'supply chain', r'third.?party', r'dependency', r'package',
        r'npm', r'pypi', r'software update', r'vendor compromise'
    ],
    'Research': [
        r'research', r'analysis', r'deep dive', r'technical write-up',
        r'methodology', r'technique'
    ]
}

ATTACK_VECTORS = {
    'Phishing': ['phishing', 'spear phishing', 'email', 'attachment', 'malicious link'],
    'RCE': ['remote code execution', 'rce', 'command injection', 'code execution'],
    'OAuth Abuse': ['oauth', 'token', 'authentication bypass', 'sso'],
    'API Misuse': ['api', 'rest', 'graphql', 'endpoint abuse'],
    'SQL Injection': ['sql injection', 'sqli', 'database injection'],
    'XSS': ['cross-site scripting', 'xss', 'script injection'],
    'File Upload': ['file upload', 'unrestricted upload', 'web shell'],
    'Credential Theft': ['credential', 'password', 'steal', 'harvest', 'keylog'],
    'Misconfiguration': ['misconfiguration', 'exposed', 'publicly accessible', 'default credentials'],
    'Social Engineering': ['social engineering', 'pretexting', 'vishing', 'smishing'],
    'Supply Chain': ['compromised package', 'malicious dependency', 'typosquatting'],
    'Zero-Day': ['zero-day', 'zero day', '0day', 'unpatched'],
}

IMPACT_OUTCOMES = {
    'RCE': ['remote code execution', 'arbitrary code', 'execute commands'],
    'Data Exfiltration': ['data theft', 'steal data', 'exfiltration', 'data breach'],
    'Account Takeover': ['account takeover', 'unauthorized access', 'session hijack'],
    'Persistence': ['persistence', 'backdoor', 'maintain access', 'implant'],
    'Lateral Movement': ['lateral movement', 'spread', 'move laterally', 'pivot'],
    'Privilege Escalation': ['privilege escalation', 'elevated privileges', 'admin access'],
    'Denial of Service': ['dos', 'ddos', 'denial of service', 'crash', 'unavailable'],
    'Ransomware': ['ransomware', 'encrypt files', 'ransom demand'],
    'Credential Dumping': ['credential dump', 'lsass', 'mimikatz', 'extract passwords'],
}


def normalize_event(title: str, content: str, category: str, cve_id: Optional[str]) -> Dict:
    """
    Convert raw article into normalized threat event
    Returns: event_type, primary_target, attack_vector, impact_outcome
    """
    text = (title + ' ' + content).lower()
    
    # Determine event type (priority order matters)
    event_type = 'Industry News'  # default
    
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Active Exploit']):
        event_type = 'Active Exploit'
    elif cve_id or any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Vulnerability']):
        event_type = 'Vulnerability'
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Campaign']):
        event_type = 'Campaign'
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Malware']):
        event_type = 'Malware'
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Supply Chain']):
        event_type = 'Supply Chain'
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Cloud Abuse']):
        event_type = 'Cloud Abuse'
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in EVENT_TYPE_PATTERNS['Research']):
        event_type = 'Research'
    
    # Extract primary target (product/platform)
    primary_target = extract_primary_target(title, content)
    
    # Identify attack vector
    attack_vector = 'Unknown'
    for vector, keywords in ATTACK_VECTORS.items():
        if any(keyword in text for keyword in keywords):
            attack_vector = vector
            break
    
    # Identify impact outcome
    impact_outcome = 'Unknown'
    for impact, keywords in IMPACT_OUTCOMES.items():
        if any(keyword in text for keyword in keywords):
            impact_outcome = impact
            break
    
    return {
        'event_type': event_type,
        'primary_target': primary_target,
        'attack_vector': attack_vector,
        'impact_outcome': impact_outcome
    }


def extract_primary_target(title: str, content: str) -> str:
    """Extract the primary product/platform/service being targeted"""
    text = title + ' ' + content
    
    # Common products/platforms
    targets = [
        # Software
        'Microsoft Office', 'Windows', 'Exchange', 'SharePoint', 'Active Directory',
        'Chrome', 'Firefox', 'Safari', 'Edge',
        'Java', 'Python', 'Node.js', 'PHP',
        'WordPress', 'Drupal', 'Joomla',
        
        # Cloud/Services
        'AWS', 'Azure', 'GCP', 'Office 365', 'Google Workspace',
        'Salesforce', 'ServiceNow', 'Okta', 'Auth0',
        
        # Infrastructure
        'VMware', 'Citrix', 'Fortinet', 'Palo Alto', 'Cisco',
        'Apache', 'Nginx', 'IIS', 'Tomcat',
        
        # Protocols
        'SSH', 'RDP', 'SMB', 'HTTP', 'HTTPS',
    ]
    
    for target in targets:
        if target.lower() in text.lower():
            return target
    
    # Try to extract from title (usually mentions product)
    words = title.split()
    for i, word in enumerate(words):
        if word.lower() in ['vulnerability', 'flaw', 'bug', 'exploit', 'in', 'affecting']:
            if i > 0:
                return words[i-1].strip(',:;.')
    
    return 'Unspecified'


# ============ EXPLOITATION REALITY CHECK ============

def determine_exploitation_status(title: str, content: str, cisa_exploited: bool, has_cve: bool) -> str:
    """
    Determine exploitation reality: actively_exploited, poc_available, theoretical, unknown
    """
    text = (title + ' ' + content).lower()
    
    # 🔴 Actively exploited indicators
    active_indicators = [
        'actively exploited', 'in the wild', 'mass exploitation',
        'attacks observed', 'exploitation detected', 'being exploited',
        'widespread attacks', 'active scanning', 'exploited by attackers'
    ]
    
    if cisa_exploited or any(indicator in text for indicator in active_indicators):
        return 'actively_exploited'
    
    # 🟡 PoC available indicators
    poc_indicators = [
        'poc', 'proof of concept', 'proof-of-concept', 'exploit code',
        'public exploit', 'exploit released', 'weaponized'
    ]
    
    if any(indicator in text for indicator in poc_indicators):
        return 'poc_available'
    
    # 🟢 Theoretical
    if has_cve or 'vulnerability' in text:
        return 'theoretical'
    
    return 'unknown'


# ============ DELTA DETECTION ============

def extract_delta_reason(title: str, content: str, exploitation_status: str) -> Optional[str]:
    """
    Identify why this is news TODAY - what changed?
    """
    text = (title + ' ' + content).lower()
    
    deltas = {
        'New PoC Released': ['poc released', 'exploit published', 'proof of concept'],
        'First Wild Exploitation': ['first observed', 'now exploited', 'exploitation began', 'attacks detected'],
        'Patch Bypass': ['bypass', 'patch ineffective', 'still vulnerable', 'workaround found'],
        'Scope Expansion': ['additional', 'also affects', 'expanded to', 'more victims'],
        'Attribution Update': ['attributed to', 'linked to', 'identified as', 'confirmed as'],
        'Weaponization': ['weaponized', 'actively exploited', 'mass scanning'],
        'Advisory Published': ['advisory', 'alert', 'bulletin', 'security update'],
        'Critical Upgrade': ['critical', 'urgent', 'immediate', 'patch now'],
    }
    
    for delta, keywords in deltas.items():
        if any(keyword in text for keyword in keywords):
            return delta
    
    # Default based on exploitation status
    if exploitation_status == 'actively_exploited':
        return 'Active Exploitation Confirmed'
    elif exploitation_status == 'poc_available':
        return 'Proof-of-Concept Available'
    
    return 'Initial Report'


# ============ MDR ANALYST TAKE GENERATOR ============

def generate_mdr_analyst_take(
    event_type: str,
    primary_target: str,
    attack_vector: str,
    exploitation_status: str,
    title: str,
    content: str,
    cve_id: Optional[str],
    cvss_score: Optional[float],
    attack_name: Optional[str]
) -> str:
    """
    Generate 1-3 sentence MDR analyst summary
    Answers: "What should an MDR analyst remember from this?"
    """
    text = (title + ' ' + content).lower()
    
    # Build contextual summary
    parts = []
    
    # Lead with exploitation reality
    if exploitation_status == 'actively_exploited':
        if attack_name:
            parts.append(f"{attack_name} actively exploiting {primary_target}")
        else:
            parts.append(f"Active exploitation of {primary_target} confirmed in the wild")
    elif exploitation_status == 'poc_available':
        parts.append(f"PoC available for {primary_target} {attack_vector.lower()}")
    else:
        parts.append(f"{primary_target} {event_type.lower()}")
    
    # Add impact context
    if attack_vector != 'Unknown':
        if cvss_score and cvss_score >= 9.0:
            parts.append(f"using {attack_vector.lower()} (CVSS {cvss_score}, critical severity)")
        else:
            parts.append(f"via {attack_vector.lower()}")
    
    # Add strategic context
    strategic_flags = []
    if 'zero-day' in text or 'zero day' in text:
        strategic_flags.append('zero-day')
    if 'supply chain' in text:
        strategic_flags.append('supply chain risk')
    if 'nation-state' in text or 'apt' in text:
        strategic_flags.append('APT-level threat')
    if 'ransomware' in text:
        strategic_flags.append('ransomware capable')
    
    if strategic_flags:
        parts.append(f"Notable: {', '.join(strategic_flags)}")
    
    # Speed context
    if 'hours' in text or 'days' in text:
        if 'three days' in text or '3 days' in text:
            parts.append("Rapid weaponization (3 days)")
        elif 'within hours' in text or 'same day' in text:
            parts.append("Same-day weaponization")
    
    return '. '.join(parts) + '.'


# ============ SIGNAL STRENGTH SCORER ============

def calculate_signal_strength(
    exploitation_status: str,
    source_confidence: str,
    has_cve: bool,
    cvss_score: Optional[float],
    cisa_exploited: bool,
    has_technical_detail: bool,
    article_body_length: int
) -> Tuple[str, str]:
    """
    Calculate signal strength: High / Medium / Low
    Returns: (signal_strength, reason)
    """
    score = 0
    reasons = []
    
    # Exploitation status (most important)
    if exploitation_status == 'actively_exploited':
        score += 40
        reasons.append("active exploitation confirmed")
    elif exploitation_status == 'poc_available':
        score += 20
        reasons.append("PoC available")
    elif exploitation_status == 'theoretical':
        score += 5
    
    # CISA KEV (critical signal)
    if cisa_exploited:
        score += 30
        reasons.append("CISA KEV listed")
    
    # Source confidence
    if source_confidence == 'High':
        score += 15
        reasons.append("high-confidence source")
    elif source_confidence == 'Medium':
        score += 8
    
    # CVE and severity
    if has_cve:
        score += 5
        if cvss_score:
            if cvss_score >= 9.0:
                score += 15
                reasons.append("critical CVSS")
            elif cvss_score >= 7.0:
                score += 8
    
    # Technical depth
    if has_technical_detail:
        score += 7
        reasons.append("technical details")
    elif article_body_length > 1000:
        score += 3
    
    # Determine tier
    if score >= 50:
        strength = 'High'
    elif score >= 25:
        strength = 'Medium'
    else:
        strength = 'Low'
    
    reason = ', '.join(reasons) if reasons else 'standard reporting'
    
    return strength, reason.capitalize()


# ============ SOURCE CONFIDENCE RATING ============

HIGH_CONFIDENCE_SOURCES = [
    'cisa', 'nist', 'nvd', 'cert', 'microsoft', 'google', 'apple',
    'adobe', 'cisco', 'fortinet', 'palo alto', 'vmware', 'citrix',
    'sans', 'mitre', 'cve.org', 'cve details'
]

MEDIUM_CONFIDENCE_SOURCES = [
    'bleepingcomputer', 'krebs', 'schneier', 'the hacker news',
    'dark reading', 'threatpost', 'security week', 'ars technica',
    'wired', 'zdnet', 'techcrunch'
]

def determine_source_confidence(source: str, url: str, title: str) -> str:
    """
    Rate source credibility: High / Medium / Low
    """
    source_lower = source.lower()
    url_lower = url.lower()
    
    # High confidence: Official vendors, CERT, government
    if any(vendor in source_lower or vendor in url_lower for vendor in HIGH_CONFIDENCE_SOURCES):
        return 'High'
    
    # Medium confidence: Reputable security media
    if any(outlet in source_lower for outlet in MEDIUM_CONFIDENCE_SOURCES):
        return 'Medium'
    
    # Check if vendor advisory
    if 'security advisory' in title.lower() or 'security bulletin' in title.lower():
        return 'High'
    
    return 'Low'


# ============ STORY DE-DUPLICATION ============

def generate_story_hash(cve_id: Optional[str], campaign_id: Optional[str], attack_name: Optional[str], primary_target: str) -> Optional[str]:
    """
    Generate hash for grouping related articles
    Same CVE, campaign, or attack + target = same story
    """
    story_components = []
    
    if cve_id:
        story_components.append(f"cve:{cve_id}")
    if campaign_id:
        story_components.append(f"campaign:{campaign_id}")
    if attack_name:
        story_components.append(f"attack:{attack_name}")
    if primary_target and primary_target != 'Unspecified':
        story_components.append(f"target:{primary_target}")
    
    if not story_components:
        return None
    
    story_key = '|'.join(sorted(story_components))
    return hashlib.md5(story_key.encode()).hexdigest()[:16]


# ============ PATTERN EXTRACTION ============

def extract_pattern_tags(title: str, content: str, attack_vector: str, event_type: str) -> List[str]:
    """
    Extract pattern tags for trend detection
    """
    text = (title + ' ' + content).lower()
    tags = []
    
    # Technique patterns
    patterns = {
        'oauth_abuse': ['oauth', 'token abuse'],
        'rtf_exploit': ['rtf', 'rich text format'],
        'api_abuse': ['api abuse', 'api exploitation'],
        'supply_chain': ['supply chain', 'dependency'],
        'phishing_campaign': ['phishing campaign', 'mass phishing'],
        'zero_day': ['zero-day', 'zero day'],
        'ransomware': ['ransomware'],
        'web_shell': ['web shell', 'webshell'],
        'credential_theft': ['credential', 'password theft'],
    }
    
    for tag, keywords in patterns.items():
        if any(keyword in text for keyword in keywords):
            tags.append(tag)
    
    # Add attack vector as pattern
    if attack_vector != 'Unknown':
        tags.append(attack_vector.lower().replace(' ', '_'))
    
    # Add event type as pattern
    tags.append(event_type.lower().replace(' ', '_'))
    
    return list(set(tags))  # deduplicate


# ============ TECHNICAL METHOD EXTRACTION ============

def extract_technical_method(title: str, content: str, attack_vector: str) -> str:
    """
    Extract brief technical method description (how attack works)
    """
    text_lower = (title + ' ' + content).lower()
    
    # Pattern-based extraction
    methods = {
        'Phishing': 'Delivers malicious payload via email attachment or link',
        'RCE': 'Exploits vulnerability to execute arbitrary code remotely',
        'OAuth Abuse': 'Compromises OAuth tokens to gain unauthorized access',
        'API Misuse': 'Exploits API endpoints to bypass authentication or extract data',
        'SQL Injection': 'Injects SQL commands to manipulate database queries',
        'XSS': 'Injects malicious scripts into web pages viewed by users',
        'Credential Theft': 'Steals authentication credentials via keylogging or dumping',
        'Zero-Day': 'Exploits previously unknown vulnerability without patch',
    }
    
    # Return method description or generic
    return methods.get(attack_vector, f'Exploits {attack_vector.lower()} vulnerability')


# ============ EVIDENCE & CONFIDENCE TRACKING ============

def build_evidence_list(
    cisa_exploited: bool,
    source: str,
    cvss_score: Optional[float],
    has_technical_detail: bool,
    cve_id: Optional[str],
    exploitation_status: str
) -> Tuple[List[str], int]:
    """
    Build list of evidence sources that contributed to signal strength
    Returns: (evidence_sources, evidence_count)
    
    This is the "why" behind High signal ratings
    """
    evidence = []
    
    if cisa_exploited:
        evidence.append('CISA KEV listed')
    
    # High-confidence sources
    high_confidence_sources = [
        'microsoft', 'google', 'apple', 'cisco', 'vmware', 
        'oracle', 'adobe', 'amazon', 'cloudflare', 'github'
    ]
    if any(vendor in source.lower() for vendor in high_confidence_sources):
        evidence.append(f'Vendor advisory ({source})')
    
    if cvss_score and cvss_score >= 9.0:
        evidence.append(f'Critical CVSS ({cvss_score})')
    elif cvss_score and cvss_score >= 7.0:
        evidence.append(f'High CVSS ({cvss_score})')
    
    if exploitation_status == 'actively_exploited':
        evidence.append('Confirmed exploitation in wild')
    elif exploitation_status == 'poc_available':
        evidence.append('Proof-of-concept published')
    
    if has_technical_detail:
        evidence.append('Technical details available')
    
    if cve_id:
        evidence.append(f'CVE assigned ({cve_id})')
    
    # Check for multiple independent reports
    multiple_sources = ['multiple reports', 'confirmed by', 'also reported']
    # Would need access to content to check properly
    
    return evidence, len(evidence)


def calculate_threat_velocity(
    first_observed_date: Optional[str],
    exploitation_status: str,
    cve_published_date: Optional[str] = None
) -> str:
    """
    Calculate threat velocity: FAST / MODERATE / SLOW / UNKNOWN
    Based on time from disclosure to exploitation
    
    Returns velocity category for UI display
    """
    if exploitation_status not in ['actively_exploited', 'poc_available']:
        return 'UNKNOWN'
    
    # Calculate weaponization speed
    if not first_observed_date:
        return 'UNKNOWN'
    
    if cve_published_date:
        days = calculate_days_between(cve_published_date, first_observed_date)
    else:
        # Use today as reference if no CVE date
        return 'UNKNOWN'
    
    if days is None:
        return 'UNKNOWN'
    
    # Velocity thresholds
    if days <= 7:
        return 'FAST'
    elif days <= 14:
        return 'MODERATE'
    else:
        return 'SLOW'


def classify_unknown_reason(
    title: str,
    content: str,
    cve_id: Optional[str],
    source: str
) -> Optional[str]:
    """
    When exploitation status is unknown, classify WHY it's unknown
    Returns: unknown_no_data | unknown_conflicting_sources | unknown_early_report | None
    """
    text_lower = (title + ' ' + content).lower()
    
    # Early report indicators
    early_indicators = ['just disclosed', 'breaking', 'developing', 'unconfirmed', 'initial report']
    if any(indicator in text_lower for indicator in early_indicators):
        return 'unknown_early_report'
    
    # Conflicting source indicators
    conflict_indicators = ['disputed', 'contradicts', 'unclear', 'unverified']
    if any(indicator in text_lower for indicator in conflict_indicators):
        return 'unknown_conflicting_sources'
    
    # No data indicators
    if not cve_id and 'vulnerability' in text_lower:
        return 'unknown_no_data'
    
    # Default
    return 'unknown_no_data'

