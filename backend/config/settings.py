import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Ingest security
DEVICE_INGEST_TOKEN = os.getenv("DEVICE_INGEST_TOKEN", "")

# Frontend URL for redirects (dashboard)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Dev convenience: auto-verify new users when set (DO NOT USE IN PRODUCTION)
DEV_AUTO_VERIFY = os.getenv("DEV_AUTO_VERIFY", "0") == "1"

"""OAuth configuration with Google-friendly defaults.
Environment fallbacks allow either OAUTH_* or GOOGLE_* variables.
"""
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET")
OAUTH_AUTH_URL = os.getenv("OAUTH_AUTH_URL") or "https://accounts.google.com/o/oauth2/v2/auth"
OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL") or "https://oauth2.googleapis.com/token"
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI") or os.getenv("GOOGLE_REDIRECT_URI") or "http://localhost:8000/api/users/oauth/google/callback"
OAUTH_SCOPES = os.getenv("OAUTH_SCOPES", "openid email profile")

# API Keys (Example: HaveIBeenPwned)
HAVEIBEENPWNED_API_KEY = os.getenv("HAVEIBEENPWNED_API_KEY")
