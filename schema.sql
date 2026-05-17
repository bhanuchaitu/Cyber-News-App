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
    action_category TEXT DEFAULT 'Awareness' CHECK (
        action_category IN ('Action Needed', 'Patch Soon', 'Watch', 'Breach', 'Malware', 'Supply Chain', 'Awareness')
    ),
    watchlist_matches JSONB DEFAULT '[]'::jsonb,
    noise_reason TEXT,
    story_key TEXT,
    review_status TEXT DEFAULT 'New' CHECK (
        review_status IN ('New', 'Reviewed', 'Monitoring', 'Action Needed', 'Ignored')
    ),

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

-- Existing tables created before these productivity fields can be upgraded in-place.
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS action_category TEXT DEFAULT 'Awareness';
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS watchlist_matches JSONB DEFAULT '[]'::jsonb;
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS noise_reason TEXT;
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS story_key TEXT;
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'New';

-- Existing tables created before review workflow fields can also be upgraded in-place.
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS bookmarked BOOLEAN DEFAULT FALSE;
ALTER TABLE daily_brief ADD COLUMN IF NOT EXISTS follow_up_required BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_daily_brief_published_at ON daily_brief(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_daily_brief_signal ON daily_brief(signal_strength);
CREATE INDEX IF NOT EXISTS idx_daily_brief_exploitation ON daily_brief(exploitation_status);
CREATE INDEX IF NOT EXISTS idx_daily_brief_unreviewed ON daily_brief(reviewed_at) WHERE reviewed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_daily_brief_cve ON daily_brief(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_daily_brief_action_category ON daily_brief(action_category);
CREATE INDEX IF NOT EXISTS idx_daily_brief_review_status ON daily_brief(review_status);
CREATE INDEX IF NOT EXISTS idx_daily_brief_story_key ON daily_brief(story_key);

-- RLS policy for the Streamlit UI.
-- The collector should use SUPABASE_SERVICE_ROLE_KEY, which bypasses RLS for inserts/upserts.
-- The app uses the publishable/anon key for reading articles and saving review flags.
ALTER TABLE daily_brief ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "daily_brief_read" ON daily_brief;
CREATE POLICY "daily_brief_read"
ON daily_brief
FOR SELECT
TO anon, authenticated
USING (true);

DROP POLICY IF EXISTS "daily_brief_review_update" ON daily_brief;
CREATE POLICY "daily_brief_review_update"
ON daily_brief
FOR UPDATE
TO anon, authenticated
USING (true)
WITH CHECK (true);
