from fastapi import APIRouter, Depends, HTTPException, status
from typing import Optional # Added import

# Removed AuthRequest, TokenResponse import
from app.services import auth_service
from app.models.crypto_models import StatusResponse # Re-use for status

from app.core.config import settings # Potentially needed for token expiry override
from app.services.auth_service import decode_access_token # To get user ID from token
from fastapi.security import OAuth2PasswordBearer # To get the token


router = APIRouter()

# Removed /register endpoint

# OAuth2 scheme for getting token from header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login") # Points to our login endpoint

# Dependency to get current user ID from token
async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    user_id: Optional[str] = payload.get("sub") # Assuming 'sub' claim holds the Supabase user ID
    if user_id is None:
        raise credentials_exception
    # In a real app, you might also check if the user exists in your DB / is active
    return user_id
# Removed /login endpoint

# You might add endpoints for token refresh, password reset, etc. later.

@router.delete(
    "/users/me",
    response_model=StatusResponse,
    summary="Delete the currently authenticated user's account",
    dependencies=[Depends(get_current_user_id)] # Enforce authentication
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

    # Optionally: Add logic here to delete user-related data from *your* application's database
    # (e.g., user profiles, saved files if not handled by cascade deletes)

    return StatusResponse(status="User account deleted successfully.")
