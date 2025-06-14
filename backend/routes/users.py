"""
This API module handles user registration and authentication, facilitating secure access to protected routes. 
It includes endpoints for registering new users, logging in, and verifying user credentials.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import get_db
from models.users import Users, PrivacySettings
from backend.services.auth import hash_password, verify_password, create_access_token
from backend.schemas.user_schemas import UserRegister, UserProfile, PrivacySettingsUpdate, TwoFASetup, TwoFAVerify
from backend.schemas.token_schema import Token
from dependencies import get_current_user
import pyotp # 'one time password ' library for two factor authentication 



# Initialize FASTAPI router for Users 
router = APIRouter()



# Register new User
@router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    # Check if user already exists
    existing_user = db.query(Users).filter(Users.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered") 
    
    # Hash the password before storing it
    hashed_password = hash_password(user.password)
    
    # Create new user
    new_user = Users(
        name = user.name,
        email = user.email,
        password = hashed_password,
        role = user.role if user.role else "user" # Default to "user"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User successfully registered", "user": new_user.name}


@router.post("/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid credentials"
        )
        
    # If 2FA is enabled, return a challenge instead of a token
    if user.twofa_enabled:
        return {"message": "2FA required", "2fa_required": True}
    
    access_token = create_access_token({"sub": user.email, "role": user.role})
    return Token(access_token=access_token)
        
        
@router.post("/profile")
def get_profile(current_user: Users = Depends(get_current_user)):
    return {"name": current_user.name, "email": current_user.email, "role": current_user.role}


@router.post("/profile")
def update_profile(profile_update: UserProfile, current_user: Users = Depends(get_current_user), 
                   db: Session = Depends(get_db)):
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


@router.post("/privacy-settings")
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
    
    
@router.post("/privacy-settings")
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
    


        
    
    