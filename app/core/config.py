import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import List, Optional

# Determine the base directory of the project
# This assumes config.py is in app/core/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENV_FILE_PATH = os.path.join(BASE_DIR, ".env")

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables or .env file.
    """
    # --- Core Application Settings ---
    APP_NAME: str = "EncryptDecryptBE API"
    DEBUG: bool = False
    # Secret key is crucial for security (e.g., JWT signing)
    # Generate a strong secret key using: openssl rand -hex 32
    SECRET_KEY: str = "your_default_secret_key_please_change" # CHANGE THIS IN .env
    # Algorithm for JWT token signing
    JWT_ALGORITHM: str = "HS256"
    # Token expiry time in minutes
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # --- CORS Settings ---
    # Origins allowed to make requests to the API
    # Can be a comma-separated string in .env or overridden here
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    # --- Supabase Settings ---
    SUPABASE_URL: Optional[str] = None
    SUPABASE_SERVICE_KEY: Optional[str] = None
    SUPABASE_ANON_KEY: Optional[str] = None


    # --- Database Settings (Example - uncomment and configure if needed) ---
    # DATABASE_URL: Optional[str] = None

    # --- File Storage Settings (Example - configure for user file uploads) ---
    # UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads") # Example local storage

    # Pydantic settings configuration
    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH, # Load from .env file
        env_file_encoding='utf-8',
        case_sensitive=False, # Environment variables are usually uppercase
        extra='ignore' # Ignore extra fields from environment
    )

# Use lru_cache to load settings only once
@lru_cache()
def get_settings() -> Settings:
    """Returns the application settings instance."""
    # Ensure the .env file path is correct if it exists
    # print(f"Loading settings from: {ENV_FILE_PATH}") # Uncomment for debugging
    return Settings()

# Instantiate settings to be easily importable
settings = get_settings()

# Example usage (can be removed later):
# if __name__ == "__main__":
#     print("Loaded Settings:")
#     print(f"  App Name: {settings.APP_NAME}")
#     print(f"  Debug Mode: {settings.DEBUG}")
#     print(f"  Secret Key: {'*' * len(settings.SECRET_KEY) if settings.SECRET_KEY else 'Not Set'}")
#     print(f"  Allowed Origins: {settings.ALLOWED_ORIGINS}")
#     # print(f"  Database URL: {settings.DATABASE_URL}")