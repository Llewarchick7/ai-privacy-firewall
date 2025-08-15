"""
This API module handles user registration and authentication, facilitating secure access to protected routes. 
It includes endpoints for registering new users, logging in, and verifying user credentials.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.users import Users, PrivacySettings
from backend.models.dns_models import RefreshSession
from backend.services.auth import (
    hash_password,
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token,
    refresh_token_expiry,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from backend.schemas.user_schemas import (
    UserRegister,
    UserProfile,
    PrivacySettingsUpdate,
    TwoFASetup,
    TwoFAVerify,
    TwoFAChallenge,
    VerificationRequest,
    ResendVerification,
    RefreshRequest,
    LogoutRequest,
    SessionInfo,
)
from backend.schemas.token_schema import Token
from typing import Union
from backend.dependencies import get_current_user
import pyotp # 'one time password ' library for two factor authentication 
from backend.services.oauth import OAuthService
from backend.config.settings import FRONTEND_URL, DEV_AUTO_VERIFY
import os
import secrets
from datetime import datetime, timedelta


# Initialize FASTAPI router for the /api/users endpoint
router = APIRouter()


# Register new User
@router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user.

    Args:
        user (UserRegister): _description_
        db (Session, optional): _description_. Defaults to Depends(get_db).

    Raises:
        HTTPException: If the email is already registered.

    Returns:
        dict: A message indicating successful registration and the user's name.
    """
    # Check if user already exists
    existing_user = db.query(Users).filter(Users.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered") 
    
    # Hash the password before storing it
    hashed_password = hash_password(user.password)
    
    # Create new user with email verification token
    verification_token = secrets.token_urlsafe(32)
    is_verified = DEV_AUTO_VERIFY
    new_user = Users(
        name=user.name,
        email=user.email,
        password_hash=hashed_password,
        role=user.role if getattr(user, "role", None) else "user",
        verification_token=None if is_verified else verification_token,
        verification_expires_at=None if is_verified else datetime.utcnow() + timedelta(hours=24),
        is_verified=is_verified,
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # NOTE: In production you would email the token; returning for dev convenience
    return {"message": "User successfully registered." + (" (auto-verified)" if is_verified else " Please verify your email."), "user": new_user.name, "verification_token_dev": None if is_verified else verification_token}


@router.post("/login", response_model=Union[Token, TwoFAChallenge])
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), request: Request = None):
    """
    Login a user.

    Args:
        form_data (OAuth2PasswordRequestForm, optional): The login form data. Defaults to Depends().
        db (Session, optional): The database session. Defaults to Depends(get_db).

    Raises:
        HTTPException: If the credentials are invalid.

    Returns:
        Token: An access token for the authenticated user.
    """
    user = db.query(Users).filter(Users.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid credentials"
        )
        
    # If 2FA is enabled, return a challenge instead of a token
    if user.twofa_enabled:
        return TwoFAChallenge()
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Use the verification token returned at registration or ask to resend.")
    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = generate_refresh_token()
    session = RefreshSession(
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=refresh_token_expiry(),
        user_agent=request.headers.get("User-Agent") if request else None,
        ip_address=request.client.host if request and request.client else None,
    )
    db.add(session)
    db.commit()
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES*60,
        refresh_expires_in=REFRESH_TOKEN_EXPIRE_DAYS*24*3600,
    )


# --- OAuth2 Login with Google (Auth Code Flow) ---------------------
@router.get("/oauth/google/login")
def oauth_google_login():
    svc = OAuthService()
    url = svc.get_authorization_url()
    return {"authorization_url": url}


@router.get("/oauth/google/callback")
def oauth_google_callback(request: Request, db: Session = Depends(get_db)):
    """Handle Google OAuth callback, create/find user, issue local JWT, and redirect to frontend."""
    svc = OAuthService()
    # Full URL with query for exchange
    authorization_response = str(request.url)
    token = svc.fetch_token(authorization_response)

    # ID token may contain user info
    id_token = token.get("id_token")
    from jwt import decode as jwt_decode
    user_email = None
    user_name = None
    try:
        if id_token:
            payload = jwt_decode(id_token, options={"verify_signature": False, "verify_aud": False})
            user_email = payload.get("email")
            user_name = payload.get("name") or payload.get("given_name")
    except Exception:
        pass

    if not user_email:
        raise HTTPException(status_code=400, detail="OAuth did not provide an email")

    # Ensure user exists
    user = db.query(Users).filter(Users.email == user_email).first()
    if not user:
        user = Users(name=user_name or user_email.split("@")[0], email=user_email, password_hash=hash_password(os.urandom(16).hex()), role="user")
        db.add(user)
        db.commit()
        db.refresh(user)

    # Issue local JWT
    access_token = create_access_token({"sub": user.email, "role": user.role})

    # Redirect to frontend with token in fragment to avoid logs
    redirect_url = f"{FRONTEND_URL}/#token={access_token}"
    return Response(status_code=302, headers={"Location": redirect_url})

# ---------------- Email Verification -------------------
@router.get("/verify/{token}")
def consume_verification(token: str, db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=404, detail="Invalid token")
    if user.is_verified:
        return {"message": "Already verified"}
    if not user.verification_expires_at or user.verification_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Token expired")
    user.is_verified = True
    user.verification_token = None
    user.verification_expires_at = None
    db.commit()
    return {"message": "Email verified"}

@router.post("/resend-verification")
def resend_verification(req: ResendVerification, db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"message": "Already verified"}
    user.verification_token = secrets.token_urlsafe(32)
    user.verification_expires_at = datetime.utcnow() + timedelta(hours=24)
    db.commit()
    return {"message": "Verification email resent", "verification_token_dev": user.verification_token}

# ---------------- Refresh Token Flow -------------------
@router.post("/token/refresh", response_model=Token)
def refresh_token(req: RefreshRequest, db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(req.refresh_token)
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == token_hash, RefreshSession.revoked == False).first()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if session.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")
    user = db.query(Users).filter(Users.id == session.user_id).first()
    if not user or not user.is_verified:
        raise HTTPException(status_code=401, detail="User invalid or unverified")
    # rotate
    new_refresh = generate_refresh_token()
    session.token_hash = hash_refresh_token(new_refresh)
    session.expires_at = refresh_token_expiry()
    db.commit()
    access_token = create_access_token({"sub": user.email, "role": user.role})
    return Token(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES*60,
        refresh_expires_in=REFRESH_TOKEN_EXPIRE_DAYS*24*3600,
    )

@router.post("/logout")
def logout(req: LogoutRequest, db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(req.refresh_token)
    session = db.query(RefreshSession).filter(RefreshSession.token_hash == token_hash, RefreshSession.revoked == False).first()
    if not session:
        return {"message": "Logged out"}
    session.revoked = True
    db.commit()
    return {"message": "Logged out"}

@router.get("/sessions", response_model=list[SessionInfo])
def list_sessions(current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(RefreshSession).filter(RefreshSession.user_id == current_user.id).all()
    return [SessionInfo(
        id=s.id,
        issued_at=s.issued_at,
        expires_at=s.expires_at,
        user_agent=s.user_agent,
        ip_address=s.ip_address,
        revoked=s.revoked,
    ) for s in sessions]

@router.delete("/sessions/{session_id}")
def revoke_session(session_id: int, current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    session = db.query(RefreshSession).filter(RefreshSession.id == session_id, RefreshSession.user_id == current_user.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.revoked = True
    db.commit()
    return {"message": "Session revoked"}
# ----------------------------------------------------------------------
        
@router.post("/profile")
def get_profile_info(current_user: Users = Depends(get_current_user)):
    """
    Get the profile information of the current user.

    Args:
        current_user (Users, optional): The current user. Defaults to Depends(get_current_user).

    Returns:
        dict: The profile information of the user.
    """
    return {"name": current_user.name, "email": current_user.email, "role": current_user.role}

@router.get("/me")
def get_me(current_user: Users = Depends(get_current_user)):
    return {"email": current_user.email, "verified": current_user.is_verified, "twofa_enabled": current_user.twofa_enabled}


@router.put("/profile")
def update_profile_info(profile_update: UserProfile, current_user: Users = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """
    Update the profile information of the current user.

    Args:
        profile_update (UserProfile): The updated profile information.
        current_user (Users, optional): The current user. Defaults to Depends(get_current_user).
        db (Session, optional): The database session. Defaults to Depends(get_db).
    
    Raises:
        HTTPException: If the email is already in use.
        
    Returns:
        dict: A message indicating successful profile update.
    """
    if profile_update.name:
        current_user.name = profile_update.name
    
    if profile_update.email:
        existing_user = db.query(Users).filter(Users.email == profile_update.email).first()
        if existing_user:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail = "Email already in use"
            ) 
        current_user.email = profile_update.email
        
    db.commit()
    db.refresh(current_user)
    
    return {"message": "Profile updated succesfully"}


@router.get("/privacy-settings")
def get_privacy_settings(current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    # Users privacy settings
    settings = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    if not settings:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Privacy Settings not found"
        )
    return {
        "allow_data_sharing": settings.allow_data_sharing,
        "receive_marketing_emails": settings.receive_marketing_emails,
        "auto_delete_old_data": settings.auto_delete_old_data
    }
    
    
@router.put("/privacy-settings")
def update_privacy_settings(privacy_settings_update: PrivacySettingsUpdate, 
                            current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    # Users privacy settings
    settings = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    
    if not settings:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "Privacy Settings not found"
        )
    
    if privacy_settings_update.allow_data_sharing:
        settings.allow_data_sharing = privacy_settings_update.allow_data_sharing
        
    if privacy_settings_update.receive_marketing_emails:
        settings.receive_marketing_emails = privacy_settings_update.receive_marketing_emails
        
    if privacy_settings_update.auto_delete_old_data:
        settings.auto_delete_old_data = privacy_settings_update.auto_delete_old_data
        
    db.commit()
    
    return {"message": "Privacy Settings updated succesfully"}
        
        
@router.post("/2fa/setup")
def setup_2fa(setup: TwoFASetup, current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    if setup.enabled:
        # Enable Two Factor Authentication
        secret = pyotp.random_base32() # generates random key
        current_user.twofa_secret = secret # stores key in user's database 
        current_user.twofa_enabled = True
        db.commit()
        return {"mesage": "Two Factor Authentication Enabled", 
                "secret": secret
               }
    else:
        # Disable two Factor Authentication
        current_user.twofa_secret = None 
        current_user.twofa_enabled = False
        db.commit()
        return {"message": "Two Factor Authentication Disabled"}
        

@router.post("/2fa/verify")
def verify_2fa(verification: TwoFAVerify, current_user: Users = Depends(get_current_user), db: Session = Depends(get_db)):
    # Check if 2FA is enabled for given user
    if not current_user.twofa_enabled or not current_user.twofa_secret:
        raise HTTPException(status_code=400, detail="2FA is not enabled for this account")
    
    # Check if datatbase 'secret' matches with information user passed in through schema 
    totp = pyotp.TOTP(current_user.twofa_secret)
    if not totp.verify(verification.key):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code")
    
    # If we get here, 2FA is verified 
    return {"message": "2FA verification successful"}
    


        
    
    