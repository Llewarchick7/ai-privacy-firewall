"""
Main entry point for the ai-privacy-firewall API.
Ensures authentication routes are accessible at /api/users.
"""

from fastapi import FastAPI, Depends
from routes import users, privacy 
from backend.database import Base, engine, get_db
from sqlalchemy.orm import Session

# Initialize database
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI()

# Include user routes
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(privacy.router, prefix="/api/privacy", tags=["Privacy"])
# app.include_router(darkweb.router, prefix="/api/darkweb", tags=["DarkWeb"])

@app.get("/")
def read_root(db: Session = Depends(get_db)):
    return {"message": "Database connection successful"}


   
