# 🚀 Quick Wins Deployment Guide

**Features Implemented:**
1. ⬆️ Escalation Indicators (exploitation status & signal strength)
2. 🔥 Threat Velocity Badges (FAST/MODERATE/SLOW)
3. 📊 Delta View foundation (last_analyst_review tracking)

---

## 📋 Pre-Deployment Checklist

- [ ] Backup Supabase database (Settings → Database → Backup)
- [ ] Test on local development database first (if available)
- [ ] Verify collector is not currently running
- [ ] Close all dashboard instances

---

## 🛠️ Step 1: Run Database Migration

### Option A: Supabase SQL Editor (Recommended)

1. **Go to Supabase Dashboard**
   - Navigate to: https://supabase.com/dashboard
   - Select your project
   - Click "SQL Editor" in left sidebar

2. **Execute Migration Script**
   - Click "New Query"
   - Copy entire contents of `migrations/001_add_escalation_velocity_fields.sql`
   - Paste into SQL editor
   - Click "Run" or press `Ctrl+Enter`

3. **Verify Success**
   ```sql
   -- Check new columns exist
   SELECT column_name, data_type 
   FROM information_schema.columns 
   WHERE table_name = 'daily_brief' 
   AND column_name IN (
       'previous_exploitation_status',
       'exploitation_escalated_at',
       'threat_velocity',
       'last_analyst_review'
   );
   ```
   
   **Expected output:** Should show 4 rows

### Option B: psql Command Line

```bash
# If you have direct database access
psql postgresql://postgres:[YOUR-PASSWORD]@[YOUR-HOST]:5432/postgres < migrations/001_add_escalation_velocity_fields.sql
```

---

## 🔄 Step 2: Test Collector

```bash
# Activate environment
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Run collector
python collector_mdr.py
```

**What to Look For:**
```
💾 Saving 67 intelligence items to database...
    ⬆️  ESCALATION DETECTED: Microsoft Exchange Zero-Day... - poc_available → actively_exploited
    ⬆️  ESCALATION DETECTED: LockBit 3.0 Ransomware... - theoretical → actively_exploited
    ✅ Successfully saved 67/67 items
    ⬆️  Detected 2 escalations (exploitation or signal upgrades)
```

**Note:** First run won't detect escalations (no existing data to compare). Run twice to test.

---

## 🎨 Step 3: Test Dashboard

```bash
streamlit run app_mdr.py
```

### Expected UI Changes

**1. Escalation Indicators** (at top of cards)
```
🔴 Actively Exploited   High Signal   ↑ ESCALATED from PoC Available   🔥 Velocity: FAST
```

**2. Signal Upgrades** (orange badge)
```
🟡 PoC Available   High Signal   ↑ Signal Upgraded from Medium
```

**3. Threat Velocity** (colored badges)
- 🔥 **FAST** (red) - 0-3 days weaponization
- ⚡ **MODERATE** (orange) - 4-14 days
- 📊 **SLOW** (green) - 15+ days

---

## ✅ Verification Tests

### Test 1: Check Database Fields

**In Supabase SQL Editor:**
```sql
SELECT 
    title,
    exploitation_status,
    previous_exploitation_status,
    exploitation_escalated_at,
    threat_velocity,
    weaponization_speed
FROM daily_brief
WHERE exploitation_escalated_at IS NOT NULL
ORDER BY exploitation_escalated_at DESC
LIMIT 5;
```

**Expected:** Should show items with escalation data

### Test 2: Check Velocity Distribution

```sql
SELECT 
    threat_velocity,
    COUNT(*) as count,
    ROUND(AVG(weaponization_speed), 1) as avg_days
FROM daily_brief
WHERE threat_velocity IS NOT NULL
GROUP BY threat_velocity
ORDER BY 
    CASE threat_velocity
        WHEN 'FAST' THEN 1
        WHEN 'MODERATE' THEN 2
        WHEN 'SLOW' THEN 3
        ELSE 4
    END;
```

**Expected output example:**
```
threat_velocity | count | avg_days
----------------|-------|----------
FAST            |    12 |     2.3
MODERATE        |    34 |     8.7
SLOW            |    21 |    28.4
```

### Test 3: Simulate Escalation

**Run this test to verify escalation detection:**

1. **Manually downgrade an item** (in Supabase SQL Editor):
   ```sql
   UPDATE daily_brief
   SET exploitation_status = 'poc_available'
   WHERE id IN (
     SELECT id FROM daily_brief
     WHERE exploitation_status = 'actively_exploited'
     LIMIT 1
   )
   RETURNING id, title, url;
   ```
   
2. **Note the URL** from the result

3. **Re-run collector** - It should fetch the same article and detect escalation:
   ```bash
   python collector_mdr.py
   ```

4. **Check for escalation message in output:**
   ```
   ⬆️  ESCALATION DETECTED: [article title] - poc_available → actively_exploited
   ```

5. **Verify in database:**
   ```sql
   SELECT 
       title,
       exploitation_status,
       previous_exploitation_status,
       exploitation_escalated_at
   FROM daily_brief
   WHERE url = '[paste-url-here]';
   ```

---

## 🐛 Troubleshooting

### Issue: Migration fails with "column already exists"

**Solution:** Columns were already added. Safe to ignore.

```sql
-- Check which columns exist
SELECT column_name 
FROM information_schema.columns 
WHERE table_name = 'daily_brief' 
AND column_name LIKE '%escalat%' OR column_name LIKE '%velocity%';
```

### Issue: No escalations detected in collector

**Cause:** This is normal on first run (no existing data to compare)

**Solution:** Run collector twice:
```bash
python collector_mdr.py  # First run - populates data
# Wait 1 minute
python collector_mdr.py  # Second run - detects escalations
```

### Issue: Velocity badges not showing

**Check 1:** Verify threat_velocity field populated
```sql
SELECT COUNT(*) as items_with_velocity
FROM daily_brief
WHERE threat_velocity IS NOT NULL;
```

**Check 2:** If count is 0, run backfill:
```sql
UPDATE daily_brief
SET threat_velocity = CASE
    WHEN weaponization_speed <= 3 THEN 'FAST'
    WHEN weaponization_speed <= 14 THEN 'MODERATE'
    WHEN weaponization_speed > 14 THEN 'SLOW'
    ELSE 'UNKNOWN'
END
WHERE weaponization_speed IS NOT NULL;
```

### Issue: Dashboard shows error after refreshing

**Cause:** Streamlit cache may have old data structure

**Solution:** Clear cache and restart:
```bash
# Stop dashboard (Ctrl+C)
# Clear Streamlit cache
streamlit cache clear
# Restart
streamlit run app_mdr.py
```

---

## 📊 Expected Impact

### Before Implementation:
- ❌ Re-reading same stories daily
- ❌ Missing silent escalations (PoC → Active)
- ❌ Manual prioritization based on dates

### After Implementation:
- ✅ **Escalations highlighted** with ↑ ESCALATED badges
- ✅ **Velocity-based prioritization** (FAST items = immediate attention)
- ✅ **Change tracking** ready for Delta View (Phase 2)

### Metrics to Track:
- **Escalations per week:** Track how many items escalate
- **Time to detect escalation:** Should be < 24 hours (next collector run)
- **FAST velocity items:** These need immediate action

---

## 🔮 Next Steps (Future Enhancements)

After validating Quick Wins implementation:

1. **Delta View Filter** (Week 2)
   - Add "Show Only New/Changed" toggle to sidebar
   - Filter by `last_analyst_review` timestamp
   - Highlight escalations from last 7 days

2. **Escalation Notifications** (Optional)
   - Email/Slack webhook when escalation detected
   - Daily summary of escalations

3. **Velocity Trends** (Optional)
   - Weekly velocity histogram
   - "Items getting faster" indicator

---

## 📝 Rollback Plan (If Needed)

**If issues arise, rollback is safe:**

```sql
-- Remove added columns (will lose escalation history)
ALTER TABLE daily_brief
DROP COLUMN IF EXISTS previous_exploitation_status,
DROP COLUMN IF EXISTS exploitation_escalated_at,
DROP COLUMN IF EXISTS previous_signal_strength,
DROP COLUMN IF EXISTS signal_upgraded_at,
DROP COLUMN IF EXISTS threat_velocity,
DROP COLUMN IF EXISTS last_analyst_review;

-- Drop indexes
DROP INDEX IF EXISTS idx_exploitation_escalated;
DROP INDEX IF EXISTS idx_signal_upgraded;
DROP INDEX IF EXISTS idx_threat_velocity;
DROP INDEX IF EXISTS idx_delta_review;
```

**Then revert collector changes:**
```bash
git checkout collector_mdr.py  # If using git
# Or manually remove escalation detection logic
```

---

## ✅ Success Criteria

**Consider implementation successful when:**

1. ✅ Migration runs without errors
2. ✅ Collector runs and populates new fields
3. ✅ Dashboard displays escalation badges  
4. ✅ Dashboard displays velocity badges
5. ✅ Escalation detection works on second collector run
6. ✅ No Python errors in collector or dashboard

**Time investment:** 15-20 minutes (migration + testing)
**Value delivered:** Immediate visibility into critical status changes

---

## 🎯 Questions or Issues?

If you encounter any issues:
1. Check troubleshooting section above
2. Verify migration SQL ran completely
3. Check Supabase logs (Database → Logs)
4. Review collector output for errors

**The goal:** Stop missing escalations. Prioritize threats correctly. Save 2-3 minutes per daily review.

---

*Deployment guide for ROADMAP.md Quick Wins implementation*
