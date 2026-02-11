"""
Database Migration Runner
Applies migration 001: Add escalation and velocity tracking fields
"""

import os
from supabase import create_client
from dotenv import load_dotenv

# Load environment
load_dotenv()

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ Error: SUPABASE_URL and SUPABASE_KEY must be set in .env file")
    exit(1)

# Initialize Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

print("🚀 Running Database Migration 001: Escalation & Velocity Tracking")
print("=" * 70)

# Read migration SQL
migration_file = 'migrations/001_add_escalation_velocity_fields.sql'

try:
    with open(migration_file, 'r') as f:
        migration_sql = f.read()
    
    print(f"\n📄 Loaded migration from: {migration_file}")
    print(f"   Size: {len(migration_sql)} characters\n")
    
    # Execute migration (Note: Supabase Python client doesn't support raw SQL execution directly)
    # User must run this in Supabase SQL Editor instead
    
    print("⚠️  IMPORTANT: Supabase Python client cannot execute raw SQL migrations.")
    print("")
    print("📋 Please follow these steps:")
    print("")
    print("1. Go to: https://supabase.com/dashboard")
    print("2. Select your project")
    print("3. Click 'SQL Editor' in left sidebar")
    print("4. Click 'New Query'")
    print("5. Copy-paste the contents of:")
    print(f"   {migration_file}")
    print("6. Click 'Run' or press Ctrl+Enter")
    print("")
    print("💡 SQL to execute:")
    print("-" * 70)
    print(migration_sql[:500] + "...\n(see full file for complete SQL)")
    print("-" * 70)
    print("")
    
    # Test if fields already exist by querying
    print("🔍 Testing database connection...")
    try:
        result = supabase.table('daily_brief').select('id').limit(1).execute()
        if result.data:
            print("✅ Database connection successful!")
            print(f"   Found {len(result.data)} record(s) in daily_brief table")
        else:
            print("✅ Database connection successful (table empty)")
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        print("   Please check your Supabase credentials in .env file")
    
    print("")
    print("📚 Next steps:")
    print("1. Run migration in Supabase SQL Editor (see instructions above)")
    print("2. Test collector: python collector_mdr.py")
    print("3. Test dashboard: streamlit run app_mdr.py")
    print("")
    print("📖 See DEPLOYMENT_GUIDE.md for detailed instructions")
    
except FileNotFoundError:
    print(f"❌ Error: Migration file not found: {migration_file}")
    print("   Make sure you're running this from the project root directory")
except Exception as e:
    print(f"❌ Error: {e}")
