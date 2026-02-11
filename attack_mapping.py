"""
MITRE ATT&CK and Cyber Kill Chain Mapping
Maps security news to attack frameworks for better threat contextualization
"""

# MITRE ATT&CK Tactics (high-level goals)
MITRE_TACTICS = {
    'Reconnaissance': ['scan', 'enumerate', 'discover', 'reconnaissance', 'osint', 'footprint'],
    'Resource Development': ['infrastructure', 'c2', 'command and control', 'establish', 'capability'],
    'Initial Access': ['phishing', 'exploit public', 'valid accounts', 'supply chain', 'initial access', 'breach', 'compromise'],
    'Execution': ['command', 'script', 'payload', 'execute', 'run', 'launch'],
    'Persistence': ['backdoor', 'create account', 'scheduled task', 'persistence', 'implant', 'rootkit'],
    'Privilege Escalation': ['privilege escalation', 'elevated', 'admin', 'root', 'sudo', 'uac bypass'],
    'Defense Evasion': ['obfuscate', 'evasion', 'bypass', 'disable', 'anti-virus', 'edr', 'masquerade'],
    'Credential Access': ['credential', 'password', 'hash', 'keylog', 'token', 'steal credentials'],
    'Discovery': ['network discovery', 'account discovery', 'enumerate', 'system information'],
    'Lateral Movement': ['lateral', 'remote service', 'pass the hash', 'spread', 'move laterally'],
    'Collection': ['collect', 'data staged', 'archive', 'clipboard', 'screen capture'],
    'Command and Control': ['c2', 'c&c', 'command and control', 'remote access', 'tunnel', 'beacon'],
    'Exfiltration': ['exfil', 'data transfer', 'steal data', 'upload', 'exfiltration'],
    'Impact': ['ransomware', 'encrypt', 'destroy', 'wipe', 'denial of service', 'ddos', 'defacement']
}

# Cyber Kill Chain Phases
KILL_CHAIN_PHASES = {
    'Reconnaissance': ['reconnaissance', 'scan', 'harvest', 'email addresses', 'footprint'],
    'Weaponization': ['exploit', 'payload', 'backdoor', 'weaponize', 'malicious'],
    'Delivery': ['phishing', 'email', 'usb', 'watering hole', 'deliver', 'attachment'],
    'Exploitation': ['vulnerability', 'cve', 'exploit', 'zero-day', 'rce', 'buffer overflow'],
    'Installation': ['install', 'persistence', 'implant', 'backdoor', 'malware install'],
    'Command & Control': ['c2', 'c&c', 'command', 'control', 'beacon', 'remote access'],
    'Actions on Objectives': ['exfil', 'ransomware', 'data theft', 'destroy', 'encrypt', 'steal']
}

# Common techniques mapped to keywords
MITRE_TECHNIQUES = {
    'T1566': ['phishing', 'spearphishing'],  # Phishing
    'T1190': ['exploit public', 'vulnerability', 'cve'],  # Exploit Public-Facing Application
    'T1133': ['vpn', 'remote service', 'external remote'],  # External Remote Services
    'T1059': ['powershell', 'command line', 'script', 'shell'],  # Command and Scripting Interpreter
    'T1486': ['ransomware', 'encrypt'],  # Data Encrypted for Impact
    'T1082': ['system information', 'enumerate'],  # System Information Discovery
    'T1021': ['remote desktop', 'rdp', 'ssh'],  # Remote Services
    'T1078': ['valid accounts', 'compromised credentials'],  # Valid Accounts
    'T1055': ['process injection'],  # Process Injection
    'T1027': ['obfuscate', 'encode'],  # Obfuscated Files or Information
    'T1071': ['application layer', 'http', 'dns'],  # Application Layer Protocol
    'T1105': ['download', 'upload', 'transfer'],  # Ingress Tool Transfer
    'T1548': ['privilege escalation', 'bypass uac'],  # Abuse Elevation Control Mechanism
    'T1003': ['credential dump', 'lsass', 'mimikatz'],  # OS Credential Dumping
    'T1562': ['disable security', 'disable av', 'disable edr'],  # Impair Defenses
}

def map_to_mitre_attack(title: str, content: str) -> dict:
    """Map article content to MITRE ATT&CK framework"""
    text = (title + ' ' + content).lower()
    
    mapped_tactics = []
    mapped_techniques = []
    
    # Find matching tactics
    for tactic, keywords in MITRE_TACTICS.items():
        if any(keyword in text for keyword in keywords):
            mapped_tactics.append(tactic)
    
    # Find matching techniques
    for technique_id, keywords in MITRE_TECHNIQUES.items():
        if any(keyword in text for keyword in keywords):
            mapped_techniques.append(technique_id)
    
    return {
        'tactics': mapped_tactics[:3],  # Limit to top 3
        'techniques': mapped_techniques[:3],
        'has_mapping': len(mapped_tactics) > 0 or len(mapped_techniques) > 0
    }

def map_to_kill_chain(title: str, content: str) -> list:
    """Map article content to Cyber Kill Chain phases"""
    text = (title + ' ' + content).lower()
    
    mapped_phases = []
    
    for phase, keywords in KILL_CHAIN_PHASES.items():
        if any(keyword in text for keyword in keywords):
            mapped_phases.append(phase)
    
    return mapped_phases[:3]  # Return top 3 most relevant phases

def extract_context(title: str, summary: str, category: str) -> str:
    """
    Extract key context to understand the threat before reading full article
    Provides a "Why this matters" perspective
    """
    
    # Category-specific context templates
    context_map = {
        'Vulnerability': f"A security vulnerability has been identified. Review this to assess if your systems are affected and understand the exploitation risk.",
        'Data Breach': f"A data breach has been reported. This may involve credential exposure, customer data, or sensitive information that could impact your organization.",
        'Malware': f"New malware activity detected. Understanding this threat helps update detection rules and identify similar patterns in your environment.",
        'Threat Intel': f"Threat actor activity reported. This intelligence helps assess if your organization fits the targeting profile and prepare defenses.",
        'Tool/Resource': f"New security tool or resource available. This could enhance your security operations or defensive capabilities.",
        'General Security': f"Security news and updates. Stay informed about the evolving threat landscape and industry developments."
    }
    
    base_context = context_map.get(category, "Security update requiring review.")
    
    # Add specific indicators if present
    indicators = []
    text_lower = (title + ' ' + summary).lower()
    
    if 'zero-day' in text_lower or 'zero day' in text_lower:
        indicators.append("⚠️ Zero-day exploit")
    if 'actively exploited' in text_lower or 'in the wild' in text_lower:
        indicators.append("🔴 Active exploitation")
    if 'ransomware' in text_lower:
        indicators.append("💰 Ransomware campaign")
    if 'supply chain' in text_lower:
        indicators.append("🔗 Supply chain risk")
    if 'nation-state' in text_lower or 'apt' in text_lower:
        indicators.append("🎯 Nation-state actor")
    
    if indicators:
        base_context = f"{' | '.join(indicators)}\n\n{base_context}"
    
    return base_context


def extract_attack_name(title: str, content: str) -> str | None:
    """
    Extract specific attack/campaign/threat actor name from article
    Returns attack name if identified, None otherwise
    """
    text = (title + ' ' + content).lower()
    
    # Known threat actors / APT groups
    apt_groups = {
        'apt28': ['apt28', 'apt 28', 'fancy bear', 'sofacy', 'sednit'],
        'apt29': ['apt29', 'apt 29', 'cozy bear', 'nobelium'],
        'apt41': ['apt41', 'apt 41', 'double dragon'],
        'lazarus': ['lazarus', 'lazarus group', 'hidden cobra'],
        'kimsuky': ['kimsuky', 'velvet chollima'],
        'sandworm': ['sandworm', 'voodoo bear'],
        'mustang panda': ['mustang panda'],
        'volt typhoon': ['volt typhoon'],
        'storm-0558': ['storm-0558', 'storm 0558'],
        'storm-1811': ['storm-1811', 'storm 1811'],
    }
    
    # Ransomware families
    ransomware = {
        'lockbit': ['lockbit'],
        'alphv': ['alphv', 'blackcat'],
        'ragnar locker': ['ragnar locker', 'ragnarlocker'],
        'rhysida': ['rhysida'],
        'akira': ['akira ransomware', 'akira'],
        'play': ['play ransomware'],
        'clop': ['clop', 'cl0p'],
        'royal': ['royal ransomware'],
        'blackbasta': ['blackbasta', 'black basta'],
    }
    
    # Malware families
    malware = {
        'qbot': ['qbot', 'qakbot', 'quakbot'],
        'emotet': ['emotet'],
        'trickbot': ['trickbot'],
        'cobalt strike': ['cobalt strike'],
        'mimikatz': ['mimikatz'],
        'icedid': ['icedid'],
        'bumblebee': ['bumblebee'],
        'dridex': ['dridex'],
    }
    
    # Check all categories
    for attack_name, keywords in {**apt_groups, **ransomware, **malware}.items():
        for keyword in keywords:
            if keyword in text:
                return attack_name.upper().replace(' ', ' ')
    
    return None
