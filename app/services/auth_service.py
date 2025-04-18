from datetime import datetime, timedelta, timezone
from typing import Optional
from supabase import create_client, Client
import os

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# Configure password hashing
# Using bcrypt as it's a strong, widely used algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Handle potential errors during verification if necessary
        return False

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Default expiry time from settings
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

# Function to decode/verify token (will be needed for dependency injection later)
def decode_access_token(token: str) -> Optional[dict]:
    """Decodes and verifies a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        # You might want to add more validation here, e.g., check username/id from payload
        return payload
    except JWTError:
        # Token is invalid (expired, wrong signature, etc.)
        return None

# Removed placeholder get_user function
# Removed placeholder authenticate_user function
# --- Supabase Client Initialization ---

def get_supabase_admin_client() -> Client:
    """Initializes and returns a Supabase client with admin privileges."""
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_role_key = os.getenv("SUPABASE_SERVICE_KEY")
    
    if not supabase_url or not supabase_role_key:
        raise ValueError("Supabase URL and Service Role Key must be configured in environment variables.")
    
    supabase: Client = create_client(supabase_url, supabase_role_key)
    return supabase

# --- Supabase User Deletion ---

async def delete_supabase_user(user_id: str) -> bool:
    """Deletes a user from Supabase Auth using the admin client."""
    try:
        supabase_admin = get_supabase_admin_client()
        # Use the admin auth interface to delete the user
        response = supabase_admin.auth.admin.delete_user(user_id)
        # Check response - supabase-py might not raise an error on failure, check response details
        print(f"Supabase delete response: {response}") # Debugging
        # Assuming success if no exception is raised. Add more robust checking if needed.
        return True
    except Exception as e:
        # Log the specific error
        print(f"Error deleting Supabase user {user_id}: {e}")
        # You might want to map specific Supabase errors to HTTPExceptions
        return False

def get_user_from_token(token: str):
    """
    Verify the Supabase JWT and return the user record.
    Returns None if invalid.
    """
    try:
        # This is NOT an async function, so no await
        supabase = create_client(
            os.getenv("SUPABASE_URL"),
            os.getenv("SUPABASE_SERVICE_KEY"),
        )
        result = supabase.auth.get_user(token)
        
        # Check if the result has user data
        if not result or not result.user:
            print(f"Invalid token or no user found")
            return None
            
        return result.user
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        return None
