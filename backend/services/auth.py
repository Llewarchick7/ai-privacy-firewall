"""
Authentication Service!
This module hashes passwords, verifies passwords, and generates JWT tokens 
"""

from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables
load_dotenv()

# Secret key for JWT (stored in .env)
# Use standard env name SECRET_KEY to match .env
SECRET_KEY = os.getenv("SECRET_KEY", "super_secret_key")
ALGORITHM = "HS256"  
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Password hashing and verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hash a password for secure storage"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a stored hash"""
    return pwd_context.verify(plain_password, hashed_password)


# JWT generation
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate a JWT for user authentication"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  

# JWT decoding 
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  
        return payload
    except jwt.ExpiredSignatureError:
        print("Token expired")  
        return None
    except jwt.InvalidTokenError:
        print("Invalid Token")  # logging
        return None
