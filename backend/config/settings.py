import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# OAuth Credentials for authentication
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
OAUTH_AUTH_URL = os.getenv("OAUTH_AUTH_URL")  # Authorization URL (e.g., Google's OAuth URL)
OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL")  # Token exchange endpoint
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")  # Redirect URI for OAuth callback
OAUTH_SCOPES = os.getenv("OAUTH_SCOPES", "email profile openid")  # Define OAuth scopes

# API Keys (Example: HaveIBeenPwned)
HAVEIBEENPWNED_API_KEY = os.getenv("HAVEIBEENPWNED_API_KEY")
