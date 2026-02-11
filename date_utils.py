"""
Centralized Date Parsing Utilities for MDR Platform
CRITICAL: All feed dates MUST go through this module
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
import time


def parse_feed_date_utc(time_struct) -> str:
    """
    Centralized feed date parser - converts any feed timestamp to UTC ISO format
    
    RULE: ALL feed dates must use this function. No exceptions.
    
    Why this matters:
    - Delta detection relies on consistent timestamps
    - Weaponization speed calculations fail with mixed timezones
    - Trend analysis drifts with inconsistent parsing
    
    Args:
        time_struct: Feed parser time struct (9-tuple from feedparser)
        
    Returns:
        ISO 8601 UTC timestamp string (e.g., '2026-02-09T12:34:56+00:00')
    """
    if not time_struct:
        return datetime.now(timezone.utc).isoformat()
    
    try:
        # Parse time_struct to datetime
        dt = datetime(
            int(time_struct[0]),  # year
            int(time_struct[1]),  # month
            int(time_struct[2]),  # day
            int(time_struct[3]),  # hour
            int(time_struct[4]),  # minute
            int(time_struct[5]),  # second
            tzinfo=timezone.utc
        )
        return dt.isoformat()
    except (TypeError, ValueError, IndexError) as e:
        # Fallback to current time if parsing fails
        print(f"⚠️  Date parsing failed: {e}. Using current time.")
        return datetime.now(timezone.utc).isoformat()


def parse_iso_to_datetime(iso_string: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO timestamp string to datetime object
    
    Args:
        iso_string: ISO 8601 timestamp string
        
    Returns:
        datetime object or None if parsing fails
    """
    if not iso_string:
        return None
    
    try:
        return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


def calculate_days_between(start_date: Union[str, datetime], end_date: Union[str, datetime]) -> Optional[int]:
    """
    Calculate days between two dates (for weaponization speed, etc.)
    
    Args:
        start_date: Earlier date (ISO string or datetime)
        end_date: Later date (ISO string or datetime)
        
    Returns:
        Number of days between dates, or None if calculation fails
    """
    try:
        start_dt: Optional[datetime] = None
        end_dt: Optional[datetime] = None
        
        if isinstance(start_date, str):
            start_dt = parse_iso_to_datetime(start_date)
        else:
            start_dt = start_date
            
        if isinstance(end_date, str):
            end_dt = parse_iso_to_datetime(end_date)
        else:
            end_dt = end_date
        
        if not start_dt or not end_dt:
            return None
        
        delta = end_dt - start_dt
        return abs(delta.days)
    except (TypeError, ValueError):
        return None


def is_within_last_n_days(timestamp: Union[str, datetime], days: int = 1) -> bool:
    """
    Check if timestamp is within last N days
    
    Args:
        timestamp: ISO string or datetime object
        days: Number of days to check (default: 1 for "yesterday")
        
    Returns:
        True if within last N days, False otherwise
    """
    try:
        ts: Optional[datetime] = None
        
        if isinstance(timestamp, str):
            ts = parse_iso_to_datetime(timestamp)
        else:
            ts = timestamp
        
        if not ts:
            return False
        
        now = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        
        delta = now - ts
        return delta.days <= days
    except (TypeError, ValueError):
        return False


def get_time_category(timestamp: Union[str, datetime]) -> str:
    """
    Categorize time for velocity display
    
    Returns:
        'Today', '1 day ago', 'X days ago', 'This week', 'This month', 'Older'
    """
    try:
        ts: Optional[datetime] = None
        
        if isinstance(timestamp, str):
            ts = parse_iso_to_datetime(timestamp)
        else:
            ts = timestamp
        
        if not ts:
            return 'Unknown'
        
        now = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        
        delta = now - ts
        days = delta.days
        
        if days == 0:
            return 'Today'
        elif days == 1:
            return '1 day ago'
        elif days <= 7:
            return 'This week'
        elif days <= 30:
            return 'This month'
        else:
            return 'Older'
    except (TypeError, ValueError):
        return 'Unknown'


def convert_utc_to_ist(utc_time: Union[str, datetime]) -> Optional[datetime]:
    """
    Convert UTC time to IST (Indian Standard Time, UTC+5:30)
    
    Args:
        utc_time: UTC timestamp (ISO string or datetime object)
        
    Returns:
        datetime object in IST timezone, or None if conversion fails
    """
    try:
        if isinstance(utc_time, str):
            dt = parse_iso_to_datetime(utc_time)
        else:
            dt = utc_time
        
        if not dt:
            return None
        
        # Convert to IST (UTC+5:30)
        ist_offset = timedelta(hours=5, minutes=30)
        
        # Ensure datetime is timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        # Convert to IST
        ist_time = dt + ist_offset
        return ist_time
    except (TypeError, ValueError, AttributeError):
        return None


def format_ist_datetime(utc_time: Union[str, datetime], format_str: str = "%Y-%m-%d %H:%M IST") -> str:
    """
    Format UTC time as IST string for display
    
    Args:
        utc_time: UTC timestamp (ISO string or datetime object)
        format_str: Output format string (default: "YYYY-MM-DD HH:MM IST")
        
    Returns:
        Formatted IST datetime string, or "N/A" if conversion fails
    """
    ist_time = convert_utc_to_ist(utc_time)
    if not ist_time:
        return "N/A"
    
    return ist_time.strftime(format_str)

