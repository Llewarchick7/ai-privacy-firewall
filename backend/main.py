"""
Main entry point for the ai-privacy-firewall API.
Ensures authentication routes are accessible at /api/users.
"""

from fastapi import FastAPI, Depends
from backend.routes import users, privacy, dns
from backend.database import Base, engine, get_db
from sqlalchemy.orm import Session

# Initialize database
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(
    title="AI Privacy Firewall API",
    description="AI-powered DNS firewall for network threat detection and privacy protection",
    version="1.0.0"
)

# Include routers
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(privacy.router, prefix="/api/privacy", tags=["Privacy"])
app.include_router(dns.router, prefix="/api/dns", tags=["DNS Monitoring"])

@app.get("/")
def read_root(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}


   
