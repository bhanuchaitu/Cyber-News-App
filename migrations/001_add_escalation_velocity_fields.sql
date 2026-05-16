-- ============================================================
-- Migration 001: Add Escalation & Velocity Tracking Fields
-- Purpose: Enable Delta View, Escalation Indicators, and Threat Velocity
-- Date: February 11, 2026
-- ============================================================

-- Add escalation tracking fields
ALTER TABLE daily_brief
ADD COLUMN IF NOT EXISTS previous_exploitation_status TEXT,
ADD COLUMN IF NOT EXISTS exploitation_escalated_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS previous_signal_strength TEXT,
ADD COLUMN IF NOT EXISTS signal_upgraded_at TIMESTAMPTZ;

-- Add threat velocity field
ALTER TABLE daily_brief
ADD COLUMN IF NOT EXISTS threat_velocity TEXT CHECK (threat_velocity IN ('FAST', 'MODERATE', 'SLOW', 'UNKNOWN'));

-- Add last analyst review timestamp for Delta View
ALTER TABLE daily_brief
ADD COLUMN IF NOT EXISTS last_analyst_review TIMESTAMPTZ;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_exploitation_escalated ON daily_brief(exploitation_escalated_at DESC) 
WHERE exploitation_escalated_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_signal_upgraded ON daily_brief(signal_upgraded_at DESC) 
WHERE signal_upgraded_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_threat_velocity ON daily_brief(threat_velocity) 
WHERE threat_velocity IS NOT NULL;

-- Index for Delta View (uses created_at since updated_at may not exist)
CREATE INDEX IF NOT EXISTS idx_delta_review ON daily_brief(created_at, last_analyst_review) 
WHERE last_analyst_review IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN daily_brief.previous_exploitation_status IS 'Previous exploitation status before escalation';
COMMENT ON COLUMN daily_brief.exploitation_escalated_at IS 'Timestamp when exploitation status escalated (e.g., PoC → Active)';
COMMENT ON COLUMN daily_brief.previous_signal_strength IS 'Previous signal strength before upgrade';
COMMENT ON COLUMN daily_brief.signal_upgraded_at IS 'Timestamp when signal strength was upgraded';
COMMENT ON COLUMN daily_brief.threat_velocity IS 'Weaponization speed category: FAST (0-3d), MODERATE (4-14d), SLOW (15+d)';
COMMENT ON COLUMN daily_brief.last_analyst_review IS 'Timestamp of last analyst review for Delta View';

-- Backfill threat_velocity based on weaponization_speed
UPDATE daily_brief
SET threat_velocity = CASE
    WHEN weaponization_speed <= 3 THEN 'FAST'
    WHEN weaponization_speed <= 14 THEN 'MODERATE'
    WHEN weaponization_speed > 14 THEN 'SLOW'
    ELSE 'UNKNOWN'
END
WHERE weaponization_speed IS NOT NULL AND threat_velocity IS NULL;

-- Mark all existing items as reviewed (to avoid flooding Delta View on first use)
UPDATE daily_brief
SET last_analyst_review = NOW()
WHERE last_analyst_review IS NULL;
