import os
from supabase import create_client

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_ROLE_KEY"),
)


async def get_user_from_token(token: str):
    """
    Verify the Supabase JWT and return the user record.
    Raises an exception if it’s invalid.
    """
    # This calls Supabase’s /auth/v1/user endpoint under the hood
    result = await supabase.auth.get_user(token)
    if result.error or not result.data:
        return None
    return result.data.user
