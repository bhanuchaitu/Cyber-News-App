-- Lean Cyber News Daily Brief schema
-- Run this in the Supabase SQL editor before starting the collector.

CREATE TABLE IF NOT EXISTS daily_brief (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    summary TEXT,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    event_type TEXT,
    primary_target TEXT,
    attack_vector TEXT,
    impact_outcome TEXT,
    first_observed_date TEXT,
    exploitation_status TEXT CHECK (
        exploitation_status IN ('actively_exploited', 'poc_available', 'theoretical', 'unknown')
    ),
    weaponization_speed INTEGER,
    threat_velocity TEXT CHECK (threat_velocity IN ('FAST', 'MODERATE', 'SLOW', 'UNKNOWN')),

    mdr_analyst_take TEXT,
    technical_method TEXT,
    delta_reason TEXT,

    signal_strength TEXT CHECK (signal_strength IN ('High', 'Medium', 'Low')),
    signal_strength_reason TEXT,
    source_confidence TEXT CHECK (source_confidence IN ('High', 'Medium', 'Low')),
    has_technical_detail BOOLEAN DEFAULT FALSE,
    article_quality_score INTEGER,

    evidence_sources JSONB DEFAULT '[]'::jsonb,
    evidence_count INTEGER DEFAULT 0,
    unknown_reason TEXT,
    last_collector_run TIMESTAMPTZ,
    pattern_tags JSONB DEFAULT '[]'::jsonb,
    story_hash TEXT,

    cve_id TEXT,
    cvss_score NUMERIC,
    cvss_vector TEXT,
    cve_published_date TEXT,
    cisa_exploited BOOLEAN DEFAULT FALSE,
    attack_name TEXT,
    mitre_tactics JSONB DEFAULT '[]'::jsonb,
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    kill_chain_phases JSONB DEFAULT '[]'::jsonb,
    has_iocs BOOLEAN DEFAULT FALSE,

    previous_exploitation_status TEXT,
    exploitation_escalated_at TIMESTAMPTZ,
    previous_signal_strength TEXT,
    signal_upgraded_at TIMESTAMPTZ,

    reviewed_at TIMESTAMPTZ,
    bookmarked BOOLEAN DEFAULT FALSE,
    follow_up_required BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_daily_brief_published_at ON daily_brief(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_daily_brief_signal ON daily_brief(signal_strength);
CREATE INDEX IF NOT EXISTS idx_daily_brief_exploitation ON daily_brief(exploitation_status);
CREATE INDEX IF NOT EXISTS idx_daily_brief_unreviewed ON daily_brief(reviewed_at) WHERE reviewed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_daily_brief_cve ON daily_brief(cve_id) WHERE cve_id IS NOT NULL;
