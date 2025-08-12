from sqlalchemy.orm import Session
import uuid
from backend.models.audit_log import AuditLogs

def log_action(db: Session, user_id: str, action: str, details: str = None):
    """Logs an action performed by a user"""
    
    log_entry = AuditLogs(
         id = str(uuid.uuid4()),
         user_id = user_id,
         action = action,
         details = details
    )
     
    db.add(log_entry)
    db.commit()
     



     