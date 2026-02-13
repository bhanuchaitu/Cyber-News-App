"""
Streamlit Cloud Entry Point
Redirects to the main MDR Intelligence Dashboard
"""

import traceback

try:
    # Import and run the main application (import has side effects - runs the app)
    import app_mdr  # noqa: F401
except Exception as e:
    import streamlit as st
    st.error(f"Failed to load app_mdr.py: {str(e)}")
    st.code(traceback.format_exc())
    st.stop()
