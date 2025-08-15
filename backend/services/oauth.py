import os
from fastapi import HTTPException
from authlib.integrations.requests_client import OAuth2Session
from backend.config.settings import (
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_AUTH_URL,
    OAUTH_TOKEN_URL,
    OAUTH_REDIRECT_URI,
    OAUTH_SCOPES,
)

class OAuthService:
    def __init__(self):
        self.client_id = OAUTH_CLIENT_ID
        self.client_secret = OAUTH_CLIENT_SECRET
        self.auth_url = OAUTH_AUTH_URL
        self.token_url = OAUTH_TOKEN_URL
        self.redirect_uri = OAUTH_REDIRECT_URI

    def get_authorization_url(self):
        """Generate an OAuth authorization URL for user login."""
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri)
        scopes = [s.strip() for s in (OAUTH_SCOPES or "").split()] or ["openid", "email", "profile"]
        # Include Google-friendly params; state is returned by Authlib
        auth_url, state = oauth.create_authorization_url(
            self.auth_url,
            scope=scopes,
            prompt="consent",
            access_type="offline",
            include_granted_scopes="true",
        )
        return auth_url

    def fetch_token(self, authorization_response: str):
        """Exchange authorization code for an access token."""
        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri)
        token = oauth.fetch_token(self.token_url, authorization_response=authorization_response, client_secret=self.client_secret)
        if not token:
            raise HTTPException(status_code=400, detail="Failed to fetch OAuth token")
        return token
