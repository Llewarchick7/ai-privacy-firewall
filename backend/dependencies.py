from fastapi import Depends, HTTPException, status 
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.users import Users 
from backend.services.auth import decode_access_token
from fastapi.security import OAuth2PasswordBearer

# Define OAuth2PasswordBearer for token-based authentication
# The token URL is the endpoint where the user will login to get the token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")

# Dependency to get the current authenticated user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Users:
    # Decode the access token to get the payload
    payload = decode_access_token(token)
    
    # Check if the payload is valid and contains the "sub" (subject) field
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    # Extract the email from the token payload
    email = payload["sub"]
    
    # Query the User database to find the user by email
    user = db.query(Users).filter(Users.email == email).first()
    
    # If the user is not found, raise an HTTPException
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Return the user
    return user


# Dependency factory function to check if the current user has the role required to perform a given action
# (i.e Will be used to ensure users are authorized to do what they are trying to do)
def require_role(required_role: str):
    def role_checker(user: Users = Depends(get_current_user)) -> Users:
        if user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail = "Not enoguh permissions"
            )
        return user
    return role_checker


