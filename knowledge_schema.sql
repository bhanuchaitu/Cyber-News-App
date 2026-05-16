-- ============================================================
-- CyberMind Knowledge Architecture v2.0 - Database Schema
-- Phase 1: From News Feed to Knowledge Graph
-- ============================================================

-- Enable pgvector extension for embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- TABLE 1: topics - Living knowledge entities
-- ============================================================
CREATE TABLE IF NOT EXISTS topics (
    id SERIAL PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL CHECK (type IN ('threat_actor', 'cve', 'technology', 'attack_type', 'vendor', 'concept')),
    article_count INT DEFAULT 0,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    embedding vector(384), -- For semantic search with sentence-transformers
    metadata JSONB DEFAULT '{}', -- Flexible storage for type-specific data
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_topics_slug ON topics(slug);
CREATE INDEX idx_topics_type ON topics(type);
CREATE INDEX idx_topics_article_count ON topics(article_count DESC);
CREATE INDEX idx_topics_last_seen ON topics(last_seen DESC);
CREATE INDEX idx_topics_embedding ON topics USING hnsw (embedding vector_cosine_ops);

-- ============================================================
-- TABLE 2: topic_relationships - Knowledge graph edges
-- ============================================================
CREATE TABLE IF NOT EXISTS topic_relationships (
    id SERIAL PRIMARY KEY,
    source_topic_id INT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    target_topic_id INT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL, -- 'uses', 'targets', 'affects', 'attributed_to', 'exploits', 'mitigates'
    strength FLOAT DEFAULT 1.0 CHECK (strength >= 0 AND strength <= 1.0),
    evidence_count INT DEFAULT 1,
    first_observed TIMESTAMPTZ DEFAULT NOW(),
    last_observed TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_topic_id, target_topic_id, relationship_type)
);

CREATE INDEX idx_relationships_source ON topic_relationships(source_topic_id);
CREATE INDEX idx_relationships_target ON topic_relationships(target_topic_id);
CREATE INDEX idx_relationships_type ON topic_relationships(relationship_type);

-- ============================================================
-- TABLE 3: iocs - Indicators of Compromise
-- ============================================================
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    ioc_type TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email')),
    value TEXT NOT NULL,
    threat_actor_id INT REFERENCES topics(id) ON DELETE SET NULL,
    article_id INT REFERENCES daily_brief(id) ON DELETE CASCADE,
    confidence FLOAT DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1.0),
    active BOOLEAN DEFAULT TRUE,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    source TEXT, -- 'article', 'abuse_ch', 'manual'
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ioc_type, value)
);

CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_threat_actor ON iocs(threat_actor_id);
CREATE INDEX idx_iocs_active ON iocs(active);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen DESC);

-- ============================================================
-- TABLE 4: user_knowledge - Personal expertise tracking
-- ============================================================
CREATE TABLE IF NOT EXISTS user_knowledge (
    id SERIAL PRIMARY KEY,
    topic_id INT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    notes TEXT,
    articles_read_count INT DEFAULT 0,
    expertise_level TEXT DEFAULT 'beginner' CHECK (expertise_level IN ('beginner', 'intermediate', 'advanced', 'expert')),
    expertise_score INT DEFAULT 0 CHECK (expertise_score >= 0 AND expertise_score <= 100),
    last_reviewed_at TIMESTAMPTZ,
    bookmarked BOOLEAN DEFAULT FALSE,
    review_due_at TIMESTAMPTZ, -- For spaced repetition
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(topic_id)
);

CREATE INDEX idx_user_knowledge_topic ON user_knowledge(topic_id);
CREATE INDEX idx_user_knowledge_expertise ON user_knowledge(expertise_level, expertise_score DESC);
CREATE INDEX idx_user_knowledge_bookmarked ON user_knowledge(bookmarked);
CREATE INDEX idx_user_knowledge_review_due ON user_knowledge(review_due_at);

-- ============================================================
-- TABLE 5: attck_techniques - MITRE ATT&CK reference
-- ============================================================
CREATE TABLE IF NOT EXISTS attck_techniques (
    id SERIAL PRIMARY KEY,
    technique_id TEXT UNIQUE NOT NULL, -- e.g., 'T1190', 'T1068'
    name TEXT NOT NULL,
    description TEXT,
    tactic TEXT, -- e.g., 'Initial Access', 'Privilege Escalation'
    article_count INT DEFAULT 0,
    keywords TEXT[], -- For matching in articles
    url TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_attck_technique_id ON attck_techniques(technique_id);
CREATE INDEX idx_attck_tactic ON attck_techniques(tactic);
CREATE INDEX idx_attck_article_count ON attck_techniques(article_count DESC);

-- ============================================================
-- TABLE 6: article_topics - Many-to-many link
-- ============================================================
CREATE TABLE IF NOT EXISTS article_topics (
    id SERIAL PRIMARY KEY,
    article_id INT NOT NULL REFERENCES daily_brief(id) ON DELETE CASCADE,
    topic_id INT NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    relevance_score FLOAT DEFAULT 1.0,
    extraction_method TEXT, -- 'regex', 'keyword', 'manual'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(article_id, topic_id)
);

CREATE INDEX idx_article_topics_article ON article_topics(article_id);
CREATE INDEX idx_article_topics_topic ON article_topics(topic_id);

-- ============================================================
-- TABLE 7: article_attck - Article to ATT&CK mapping
-- ============================================================
CREATE TABLE IF NOT EXISTS article_attck (
    id SERIAL PRIMARY KEY,
    article_id INT NOT NULL REFERENCES daily_brief(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES attck_techniques(technique_id) ON DELETE CASCADE,
    confidence FLOAT DEFAULT 0.5,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(article_id, technique_id)
);

CREATE INDEX idx_article_attck_article ON article_attck(article_id);
CREATE INDEX idx_article_attck_technique ON article_attck(technique_id);

-- ============================================================
-- FUNCTIONS: Auto-update triggers
-- ============================================================

-- Update topics.article_count when article_topics changes
CREATE OR REPLACE FUNCTION update_topic_article_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE topics SET article_count = article_count + 1, last_seen = NOW() WHERE id = NEW.topic_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE topics SET article_count = article_count - 1 WHERE id = OLD.topic_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_topic_article_count
AFTER INSERT OR DELETE ON article_topics
FOR EACH ROW EXECUTE FUNCTION update_topic_article_count();

-- Update attck_techniques.article_count when article_attck changes
CREATE OR REPLACE FUNCTION update_attck_article_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE attck_techniques SET article_count = article_count + 1 WHERE technique_id = NEW.technique_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE attck_techniques SET article_count = article_count - 1 WHERE technique_id = OLD.technique_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_attck_article_count
AFTER INSERT OR DELETE ON article_attck
FOR EACH ROW EXECUTE FUNCTION update_attck_article_count();

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_topics_updated_at BEFORE UPDATE ON topics
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_user_knowledge_updated_at BEFORE UPDATE ON user_knowledge
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- SEED DATA: Common MITRE ATT&CK Techniques
-- ============================================================

INSERT INTO attck_techniques (technique_id, name, description, tactic, keywords) VALUES
-- Initial Access
('T1190', 'Exploit Public-Facing Application', 'Exploiting internet-facing applications', 'Initial Access', ARRAY['exploit', 'web application', 'public-facing', 'internet-facing', 'vulnerability']),
('T1133', 'External Remote Services', 'Using external remote services like VPN', 'Initial Access', ARRAY['vpn', 'remote desktop', 'rdp', 'remote access', 'citrix']),
('T1566', 'Phishing', 'Using phishing for initial access', 'Initial Access', ARRAY['phishing', 'spearphishing', 'email attack', 'malicious email']),

-- Execution
('T1059', 'Command and Scripting Interpreter', 'Executing commands via interpreters', 'Execution', ARRAY['powershell', 'cmd', 'bash', 'python script', 'shell command']),
('T1203', 'Exploitation for Client Execution', 'Exploiting client software', 'Execution', ARRAY['browser exploit', 'office exploit', 'pdf exploit', 'client-side']),

-- Persistence
('T1053', 'Scheduled Task/Job', 'Using scheduled tasks for persistence', 'Persistence', ARRAY['scheduled task', 'cron', 'task scheduler', 'at command']),
('T1078', 'Valid Accounts', 'Using stolen credentials', 'Persistence', ARRAY['stolen credentials', 'compromised account', 'valid account', 'credential theft']),
('T1547', 'Boot or Logon Autostart Execution', 'Auto-execution at boot', 'Persistence', ARRAY['autostart', 'registry run key', 'startup folder', 'boot']),

-- Privilege Escalation
('T1068', 'Exploitation for Privilege Escalation', 'Local privilege escalation exploits', 'Privilege Escalation', ARRAY['privilege escalation', 'local exploit', 'kernel exploit', 'elevation']),
('T1055', 'Process Injection', 'Injecting code into processes', 'Privilege Escalation', ARRAY['process injection', 'code injection', 'dll injection', 'reflective loading']),

-- Defense Evasion
('T1070', 'Indicator Removal', 'Clearing logs and artifacts', 'Defense Evasion', ARRAY['log clearing', 'event log cleared', 'forensic obfuscation', 'artifact removal']),
('T1027', 'Obfuscated Files or Information', 'Obfuscating malicious content', 'Defense Evasion', ARRAY['obfuscation', 'encoding', 'encryption', 'packing', 'steganography']),
('T1562', 'Impair Defenses', 'Disabling security tools', 'Defense Evasion', ARRAY['disable antivirus', 'disable edr', 'security tool bypass', 'defender disabled']),

-- Credential Access
('T1003', 'OS Credential Dumping', 'Dumping credentials from OS', 'Credential Access', ARRAY['credential dumping', 'lsass', 'mimikatz', 'sam database', 'password dump']),
('T1110', 'Brute Force', 'Password guessing attacks', 'Credential Access', ARRAY['brute force', 'password spray', 'credential stuffing', 'dictionary attack']),
('T1555', 'Credentials from Password Stores', 'Credentials from browsers/vaults', 'Credential Access', ARRAY['browser credentials', 'password manager', 'credential vault', 'saved passwords']),

-- Discovery
('T1083', 'File and Directory Discovery', 'Enumerating filesystem', 'Discovery', ARRAY['file enumeration', 'directory listing', 'file discovery']),
('T1082', 'System Information Discovery', 'Gathering system info', 'Discovery', ARRAY['system information', 'reconnaissance', 'os version', 'system enumeration']),

-- Lateral Movement
('T1021', 'Remote Services', 'Moving laterally via remote services', 'Lateral Movement', ARRAY['lateral movement', 'remote desktop', 'psexec', 'wmi', 'smb']),
('T1210', 'Exploitation of Remote Services', 'Exploiting network services', 'Lateral Movement', ARRAY['network exploit', 'remote exploit', 'service exploitation']),

-- Collection
('T1005', 'Data from Local System', 'Collecting local data', 'Collection', ARRAY['data collection', 'file exfiltration', 'document theft', 'sensitive data']),
('T1056', 'Input Capture', 'Keylogging and input monitoring', 'Collection', ARRAY['keylogger', 'keystroke logging', 'input capture', 'screen capture']),

-- Command and Control
('T1071', 'Application Layer Protocol', 'C2 over common protocols', 'Command and Control', ARRAY['c2', 'command and control', 'http c2', 'dns tunneling', 'c&c']),
('T1573', 'Encrypted Channel', 'Encrypted C2 communications', 'Command and Control', ARRAY['encrypted c2', 'ssl c2', 'tls', 'encrypted communication']),

-- Exfiltration
('T1041', 'Exfiltration Over C2 Channel', 'Data exfil over C2', 'Exfiltration', ARRAY['data exfiltration', 'data theft', 'data exfil', 'stolen data']),
('T1567', 'Exfiltration Over Web Service', 'Exfil to cloud services', 'Exfiltration', ARRAY['cloud exfiltration', 'dropbox upload', 'onedrive exfil', 'file sharing']),

-- Impact
('T1486', 'Data Encrypted for Impact', 'Ransomware encryption', 'Impact', ARRAY['ransomware', 'file encryption', 'crypto-locker', 'data encryption', 'encrypted files']),
('T1490', 'Inhibit System Recovery', 'Deleting backups', 'Impact', ARRAY['backup deletion', 'shadow copy delete', 'recovery disabled', 'vssadmin']),
('T1491', 'Defacement', 'Website/system defacement', 'Impact', ARRAY['defacement', 'website vandalism', 'defaced']),
('T1489', 'Service Stop', 'Stopping critical services', 'Impact', ARRAY['service stop', 'service disabled', 'service termination'])

ON CONFLICT (technique_id) DO NOTHING;

-- ============================================================
-- SEED DATA: Common Threat Actors
-- ============================================================

INSERT INTO topics (slug, name, description, type, metadata) VALUES
('lockbit', 'LockBit', 'Ransomware-as-a-Service operation known for high-profile attacks', 'threat_actor', '{"aliases": ["LockBit 3.0", "LockBit Black"], "first_observed": "2019"}'),
('alphv-blackcat', 'ALPHV/BlackCat', 'Rust-based ransomware group', 'threat_actor', '{"aliases": ["BlackCat", "Noberus"], "first_observed": "2021"}'),
('cl0p', 'Cl0p', 'Ransomware group behind MOVEit and GoAnywhere attacks', 'threat_actor', '{"aliases": ["Clop"], "first_observed": "2019"}'),
('apt29', 'APT29', 'Russian state-sponsored group', 'threat_actor', '{"aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"], "attribution": "Russia", "first_observed": "2008"}'),
('apt28', 'APT28', 'Russian military intelligence group', 'threat_actor', '{"aliases": ["Fancy Bear", "Sofacy", "Pawn Storm"], "attribution": "Russia - GRU", "first_observed": "2007"}'),
('apt41', 'APT41', 'Chinese state-sponsored group', 'threat_actor', '{"aliases": ["Winnti", "Barium", "Double Dragon"], "attribution": "China", "first_observed": "2012"}'),
('lazarus-group', 'Lazarus Group', 'North Korean state-sponsored APT', 'threat_actor', '{"aliases": ["Hidden Cobra", "Guardians of Peace"], "attribution": "North Korea", "first_observed": "2009"}'),
('conti', 'Conti', 'Russian ransomware cartel (disbanded 2022)', 'threat_actor', '{"status": "disbanded", "first_observed": "2020", "last_active": "2022"}'),
('revil', 'REvil', 'Ransomware group (disbanded)', 'threat_actor', '{"aliases": ["Sodinokibi"], "status": "disbanded", "first_observed": "2019"}'),
('emotet', 'Emotet', 'Banking trojan and botnet', 'threat_actor', '{"status": "disrupted", "first_observed": "2014"}')

ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- SEED DATA: Common Technologies
-- ============================================================

INSERT INTO topics (slug, name, description, type) VALUES
('microsoft-exchange', 'Microsoft Exchange', 'Email and calendaring server', 'technology'),
('vmware-esxi', 'VMware ESXi', 'Hypervisor for virtualization', 'technology'),
('apache-log4j', 'Apache Log4j', 'Java logging library', 'technology'),
('windows-server', 'Windows Server', 'Microsoft server OS', 'technology'),
('cisco-ios', 'Cisco IOS', 'Cisco network device OS', 'technology'),
('fortinet-fortigate', 'Fortinet FortiGate', 'Network security appliance', 'technology'),
('citrix-netscaler', 'Citrix NetScaler', 'Application delivery controller', 'technology'),
('kubernetes', 'Kubernetes', 'Container orchestration platform', 'technology')

ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- SEED DATA: Common Attack Types
-- ============================================================

INSERT INTO topics (slug, name, description, type) VALUES
('ransomware', 'Ransomware', 'Malware that encrypts data for ransom', 'attack_type'),
('supply-chain', 'Supply Chain Attack', 'Compromise through third-party vendors', 'attack_type'),
('zero-day', 'Zero-Day Exploit', 'Exploit of previously unknown vulnerability', 'attack_type'),
('sql-injection', 'SQL Injection', 'Database query injection attack', 'attack_type'),
('ddos', 'DDoS Attack', 'Distributed Denial of Service', 'attack_type'),
('man-in-the-middle', 'Man-in-the-Middle', 'Interception of communications', 'attack_type'),
('credential-stuffing', 'Credential Stuffing', 'Automated login attempts with stolen credentials', 'attack_type'),
('business-email-compromise', 'Business Email Compromise', 'Email fraud targeting businesses', 'attack_type')

ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- SUCCESS MESSAGE
-- ============================================================
DO $$ 
BEGIN 
    RAISE NOTICE '✓ CyberMind Knowledge Schema v2.0 installed successfully!';
    RAISE NOTICE '✓ Created 7 tables: topics, topic_relationships, iocs, user_knowledge, attck_techniques, article_topics, article_attck';
    RAISE NOTICE '✓ Seeded % MITRE ATT&CK techniques', (SELECT COUNT(*) FROM attck_techniques);
    RAISE NOTICE '✓ Seeded % threat actors', (SELECT COUNT(*) FROM topics WHERE type = 'threat_actor');
    RAISE NOTICE '✓ Seeded % technologies', (SELECT COUNT(*) FROM topics WHERE type = 'technology');
    RAISE NOTICE '✓ Seeded % attack types', (SELECT COUNT(*) FROM topics WHERE type = 'attack_type');
    RAISE NOTICE 'Next: Run entity extraction in collector to populate topics!';
END $$;
