"""
Schema definitions for serialization and validation of user-related data. This module includes schemas for 
user registration, login, profile updates, privacy settings, and two-factor authentication. When user changes their information, their data is validated/serialized 
using Pydantic, ensuring type safety and correctness.
"""

from pydantic import BaseModel, EmailStr
from typing import Optional 
from enum import Enum
from datetime import datetime


# Pydantic BaseModel extensions are schemas for data validation and serialization...

# Base scehma for others to inhereit from 
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True
        
# Enum for user roles
class UserRole(str, Enum):
    super_admin = "super_admin"
    org_admin = "org_admin"
    privacy_officer = "privacy_officer"
    it_admin = "it_admin"
    user = "user"
    guest = "guest"
    
    
# User registration schema
class UserRegister(BaseSchema):
    name: str
    email: EmailStr  
    password: str
    role: UserRole

# User response schema 
class UserResponse(BaseSchema):
    id: int
    name: str
    email: EmailStr
    role: UserRole
    created_at: datetime
    
# User authentication request schema
class UserLogin(BaseSchema):
    email: EmailStr
    password: str
    
# Allows users to update their profile  
class UserProfile(BaseSchema):
    name: Optional[str]
    email: Optional[str]

# Allows users to change their privacy settings
class PrivacySettingsUpdate(BaseSchema):
    allow_data_sharing: Optional[bool]
    receive_marketing_emails: Optional[bool]
    auto_delete_old_data: Optional[bool]
    
    
class TwoFASetup(BaseSchema):
    enabled: bool
    
class TwoFAVerify(BaseSchema):
    key: str