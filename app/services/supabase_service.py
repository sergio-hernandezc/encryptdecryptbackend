import os
from supabase import create_client

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_KEY"),
)


def get_user_from_token(token: str):
    """
    Verify the Supabase JWT and return the user record.
    Returns None if invalid.
    """
    try:
        result = supabase.auth.get_user(token)
        if not result or not result.user:
            print(f"Invalid token or no user found")
            return None
            
        return result.user
    except Exception as e:
        print(f"Error verifying token: {str(e)}")
        return None
