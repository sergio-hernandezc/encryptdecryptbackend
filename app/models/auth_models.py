from pydantic import BaseModel, Field

class AuthRequest(BaseModel):
    """
    Request model for user registration and login.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Username for authentication")
    password: str = Field(..., min_length=8, description="Password for authentication")

class TokenResponse(BaseModel):
    """
    Response model for successful authentication, providing an access token.
    """
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Type of the token (typically 'bearer')")

# You might add other auth-related models here later, e.g., for password reset requests.