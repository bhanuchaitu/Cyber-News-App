"""
Streamlit Cloud Entry Point
Redirects to the main MDR Intelligence Dashboard
"""

import sys
import traceback

try:
    # Import and run the main application
    import app_mdr
except Exception as e:
    import streamlit as st
    st.error(f"Failed to load app_mdr.py: {str(e)}")
    st.code(traceback.format_exc())
    st.stop()
