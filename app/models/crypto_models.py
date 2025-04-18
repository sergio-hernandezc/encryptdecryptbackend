from pydantic import BaseModel, Field, validator
from typing import Literal, Optional

# --- Password Generation ---

class PasswordGenRequest(BaseModel):
    """Request model for generating a password."""
    length: int = Field(..., ge=8, le=128, description="Desired password length")
    use_uppercase: bool = Field(default=True, description="Include uppercase letters")
    use_lowercase: bool = Field(default=True, description="Include lowercase letters")
    use_numbers: bool = Field(default=True, description="Include numbers")
    use_symbols: bool = Field(default=True, description="Include symbols")

class PasswordGenResponse(BaseModel):
    """Response model containing the generated password."""
    password: str = Field(..., description="The generated password")

# --- Key Generation ---

class KeyGenRequest(BaseModel):
    """Request model for generating cryptographic keys."""
    key_type: Literal['symmetric', 'asymmetric'] = Field(..., description="Type of key to generate")
    algorithm: Literal['AES-128', 'AES-256', '3DES', 'RSA-2048'] = Field(..., description="Algorithm for the key")
    key_name: str = Field(..., min_length=1, max_length=100, description="Base name for the key file(s)")

    @validator('algorithm')
    def check_algorithm_type(cls, algorithm, values):
        key_type = values.get('key_type')
        if key_type == 'symmetric' and algorithm not in ['AES-128', 'AES-256', '3DES']:
            raise ValueError(f"Algorithm {algorithm} is not valid for symmetric key type")
        if key_type == 'asymmetric' and algorithm not in ['RSA-2048']:
            raise ValueError(f"Algorithm {algorithm} is not valid for asymmetric key type")
        return algorithm

# Note: KeyGen response is a FileResponse, so no Pydantic model needed here.

# --- Hashing ---

class HashResponse(BaseModel):
    """Response model containing the calculated hash."""
    hash: str = Field(..., description="Calculated hash value (hex)")

class HashCompareResponse(BaseModel):
    """Response model for comparing two hashes."""
    match: bool = Field(..., description="True if the hashes match, False otherwise")
    hash1: str = Field(..., description="Calculated hash of the first file (hex)")
    hash2: str = Field(..., description="Calculated hash of the second file (hex)")

# --- Diffie-Hellman Key Exchange ---

class DHInitRequest(BaseModel):
    """Request model to initiate Diffie-Hellman key exchange."""
    params_size: Literal[1024, 2048] = Field(..., description="Parameter size in bits for DH")
    key_name: str = Field(..., min_length=1, max_length=100, description="Name to associate with the generated DH parameters and keys")

class DHInitResponse(BaseModel):
    """Response model after initiating DH, providing the public value."""
    public_value: str = Field(..., description="The generated public value (hex encoded)")
    key_name: str = Field(..., description="The key name associated with this exchange")
    # Note: The actual response might be a FileResponse containing the public value

class DHCompleteRequest(BaseModel):
    """Request model to complete the DH key exchange."""
    key_name: str = Field(..., description="The key name associated with the initiated exchange")
    other_party_public_value: str = Field(..., description="The public value received from the other party (hex encoded)")

class DHCompleteResponse(BaseModel):
    """Response model after completing the DH exchange."""
    shared_secret_status: str = Field(..., description="Status message indicating if the shared secret was computed")
    # Optionally include a hash of the secret, but not the secret itself
    shared_secret_hash: Optional[str] = Field(None, description="SHA-256 hash of the computed shared secret (hex)")

# --- General Status ---
class StatusResponse(BaseModel):
    """Generic status response."""
    status: str = Field(..., description="Status message")

# Note: Models for Encrypt/Decrypt requests are not strictly needed here
# as FastAPI handles Form(...) fields with UploadFile directly in endpoints.
# Response models for Encrypt/Decrypt are FileResponse.