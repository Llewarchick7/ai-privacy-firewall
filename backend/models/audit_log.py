from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship 
from database import Base


class AuditLogs(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False)
    action = Column(String, nullable=False) # e.g. "Update Profile" or "Changed Privacy Settings"
    details = Column(String, nullable=True) # store JSON-like changes
    
    user = relationship("Users", back_populates="audit_logs")