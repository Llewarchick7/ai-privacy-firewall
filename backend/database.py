"""
Loads databse credentials from a .env file, initializes the databse connetion, and creates a session factory
"""

from sqlalchemy import create_engine 
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv


# Load environment variables 
load_dotenv()

# Database URL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:super_password@localhost/postgres")

# Print the DATABASE_URL for logging purposes 
print(f"Connecting to database with URL: {DATABASE_URL}")

# Create database engine to interface with the databse (i.e handles SQL queries)
try:
    engine = create_engine(DATABASE_URL)
    print("Connection to the database was successful.")
except Exception as e:
    print(f"Error connecting to the database: {e}")


# Create a session factory, which established a workspace for database interactions 
# (i.e Manages the context of database operations)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models from sqlalchemy
Base = declarative_base()

# Used as a Dependency Injection!!! 
# This function loads a database session for user to use in conjunction with FASTAPI routing 
def get_db():
    db = SessionLocal()
    try:
        yield db  # This is a generator that yields a session
    finally:
        db.close()



