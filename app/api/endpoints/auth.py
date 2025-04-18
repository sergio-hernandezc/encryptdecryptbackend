from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional # Added import

# Removed AuthRequest, TokenResponse import
from app.services import auth_service, supabase_service
from app.models.crypto_models import StatusResponse # Re-use for status

from app.core.config import settings # Potentially needed for token expiry override

from fastapi.security import OAuth2PasswordBearer # To get the token


router = APIRouter()

# Removed /register endpoint

# OAuth2 scheme for getting token from header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# Dependency to get current user ID from token using Supabase
async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    """
    Verify the token with Supabase and return the user ID.
    Will raise 401 Unauthorized if the token is invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # If no token provided
    if not token:
        raise credentials_exception
    
    # Verify token with Supabase
    user = await supabase_service.get_user_from_token(token)
    
    if not user:
        raise credentials_exception
    
    user_id = user.id  # Supabase user object should have an 'id' attribute
    
    if not user_id:
        raise credentials_exception
    
    return user_id

# Removed /login endpoint

# You might add endpoints for token refresh, password reset, etc. later.

@router.delete(
    "/users/me",
    response_model=StatusResponse,
    summary="Delete the currently authenticated user's account",
)
async def delete_current_user(
    current_user_id: str = Depends(get_current_user_id)
):
    """
    Deletes the account of the user associated with the provided authentication token.
    This action is irreversible.
    """
    deleted = await auth_service.delete_supabase_user(user_id=current_user_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user account from authentication provider."
        )

    # Optionally: Add logic here to delete user-related data from your application's database
    
    return StatusResponse(status="User account deleted successfully.")
