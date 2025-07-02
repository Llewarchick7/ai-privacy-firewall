"""
This module defines the User model for the database, representing users with their hashed passwords for security.
"""

from sqlalchemy import Column, Integer, String, Enum, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class Users(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum("super_admin", "org_admin", "privacy_officer", "it_admin", "user", "guest", name="user_roles"), 
                  default="user", nullable=False)
    
    # 2FA fields
    twofa_enabled = Column(Boolean, default=False)
    twofa_secret = Column(String, nullable=True)
    
    # one-to-one relationship -> returns the corresponding privacy_settings data for a given "user"(variable in PrivacySettings database)
    privacy_settings = relationship("PrivacySettings", back_populates="user")
    
    # one-to-many relationship -> user can have multiple devices
    devices = relationship("Device", back_populates="user") 
    
    
    
# Represents user-specefic privacy settings
class PrivacySettings(Base):
    __tablename__ = "privacy_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False) # The ForeignKey directly references the id coulumn in the User database, so we know whose privacy settings we have 
    allow_data_sharing = Column(Boolean, default=False)
    receive_marketing_emails = Column(Boolean, default=False)
    auto_delete_old_data = Column(Boolean, default=False)
    
    # one-to-one relationship -> returns the corresponding user data for given "privacy_settings"(variable in Users databse)
    user = relationship("Users", back_populates="privacy_settings")
    audit_logs = relationship("AuditLogs", back_populates="user")
    
    