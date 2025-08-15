from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.dependencies import get_current_user
from backend.database import get_db
from backend.models.users import Users, PrivacySettings
from backend.schemas.user_schemas import UserRegister, UserProfile, PrivacySettingsUpdate, TwoFASetup, TwoFAVerify


# Initialize FASTAPI router for the /api/privacy endpoint
router = APIRouter()

@router.get("/privacy-settings", response_model=PrivacySettingsUpdate)
def get_privacy_settings(
    current_user: Users = Depends(get_current_user), 
    db: Session = Depends(get_db)
) -> PrivacySettingsUpdate:
    settings = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    if not settings:
        raise HTTPException(
            status_code=404,
            detail="Privacy Settings Not Found"
        )

    return PrivacySettingsUpdate.model_validate(settings)  # convert ORM object to Pydantic schema