import binascii
import io
import os
from typing import Optional, Literal, Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    UploadFile,
    File,
    Form,
    Response,
)
from fastapi.responses import FileResponse, JSONResponse
from starlette.datastructures import Headers # To set custom headers

# Models
from app.models.crypto_models import (
    PasswordGenRequest, PasswordGenResponse,
    KeyGenRequest,
    HashResponse, HashCompareResponse,
    DHInitRequest, DHInitResponse,
    DHCompleteRequest, DHCompleteResponse,
    StatusResponse
)
# Services
from app.services import crypto_service
# Placeholder for authentication dependency
# from app.services.auth_service import get_current_active_user # Assuming this function exists

router = APIRouter()

# --- Helper Functions ---

async def _read_file_content(file: UploadFile) -> bytes:
    """Reads the content of an UploadFile."""
    try:
        content = await file.read()
        return content
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to read file: {file.filename}. Error: {e}")
    finally:
        await file.close()

def _hex_to_bytes(hex_string: Optional[str], expected_bytes: Optional[int] = None, field_name: str = "Hex value") -> Optional[bytes]:
    """Converts a hex string to bytes, with optional length validation."""
    if hex_string is None:
        return None
    try:
        byte_data = binascii.unhexlify(hex_string)
        if expected_bytes is not None and len(byte_data) != expected_bytes:
            raise ValueError(f"Expected {expected_bytes} bytes, but got {len(byte_data)}")
        return byte_data
    except (binascii.Error, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid hex format or length for {field_name}: {e}")

# --- Placeholder Authentication Dependency ---
# Replace with actual implementation later
async def get_current_active_user_placeholder():
    # print("Warning: Using placeholder authentication!") # Uncomment for debugging
    # return {"username": "testuser", "disabled": False} # Simulate logged-in user
    # For now, let's skip auth requirement by returning None or just passing
    pass

# --- Endpoints ---

@router.post(
    "/generate/password",
    response_model=PasswordGenResponse,
    summary="Generate a secure random password",
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def generate_password_endpoint(request: PasswordGenRequest):
    """Generates a password based on the provided criteria."""
    try:
        password = crypto_service.generate_password(
            length=request.length,
            use_uppercase=request.use_uppercase,
            use_lowercase=request.use_lowercase,
            use_numbers=request.use_numbers,
            use_symbols=request.use_symbols
        )
        return PasswordGenResponse(password=password)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        # Log the exception in a real app
        print(f"Error generating password: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate password.")

@router.post(
    "/generate/key",
    summary="Generate a cryptographic key or key pair",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def generate_key_endpoint(request: KeyGenRequest):
    """
    Generates a symmetric key or an asymmetric key pair (RSA).
    Returns the key(s) as downloadable file(s).
    For asymmetric keys, currently returns the private key.
    """
    try:
        # Debug request data
        print(f"DEBUG - Key generation request received: {request.dict()}")
        print(f"DEBUG - Key type: {request.key_type}, Algorithm: {request.algorithm}, Key name: {request.key_name}")
        
        # Call the service function with detailed error trapping
        try:
            key_materials = crypto_service.generate_key(request.key_type, request.algorithm)
            print(f"DEBUG - Key materials returned: {len(key_materials)} entries")
            for key_name in key_materials.keys():
                print(f"DEBUG - Generated key with name: {key_name}")
        except Exception as service_error:
            import traceback
            error_traceback = traceback.format_exc()
            print(f"DEBUG - Error in crypto_service.generate_key: {str(service_error)}")
            print(f"DEBUG - Traceback from generate_key: {error_traceback}")
            raise  # Re-raise to be caught by the outer try-except

        if not key_materials:
            print("DEBUG - Key materials dictionary is empty")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key generation failed unexpectedly.")

        # Debug key materials
        print(f"DEBUG - Key materials keys: {list(key_materials.keys())}")
        
        # For now, return the first key generated (e.g., private key for RSA)
        # A better approach might be to zip multiple files or have separate endpoints
        first_filename_base = list(key_materials.keys())[0].split('.')[0] # e.g., "rsa_private"
        download_filename = f"{request.key_name}_{first_filename_base}.key" # e.g., "my_key_rsa_private.key"
        if '.pem' in list(key_materials.keys())[0]:
            download_filename = f"{request.key_name}_{first_filename_base}.pem" # Use .pem for PEM files

        key_bytes = list(key_materials.values())[0]
        
        # Debug response preparation
        print(f"DEBUG - Sending key with filename: {download_filename}, size: {len(key_bytes)} bytes")

        # Use StreamingResponse or FileResponse. StreamingResponse is generally better for large files.
        # For keys, FileResponse from bytes is fine.
        return Response(
            content=key_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )

    except ValueError as e:
        print(f"DEBUG - ValueError in key generation endpoint: {str(e)}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        # Log the exception and raise an HTTP exception instead of silently passing
        import traceback
        error_traceback = traceback.format_exc()
        print(f"DEBUG - Unexpected error during key generation: {str(e)}")
        print(f"DEBUG - Error type: {type(e).__name__}")
        print(f"DEBUG - Complete traceback: {error_traceback}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Unexpected error during key generation: {str(e)}"
        )


# --- Symmetric Encryption/Decryption Endpoints ---

@router.post(
    "/encrypt/symmetric",
    summary="Encrypt a file using a symmetric algorithm",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def encrypt_symmetric_endpoint(
    response: Response, # Inject Response object to set headers
    algorithm: Literal['AES-128', 'AES-256', '3DES'] = Form(...),
    mode: Literal['CBC', 'ECB'] = Form(...),
    iv_hex: Optional[str] = Form(None, alias="iv"), # Frontend sends 'iv'
    key_hex: Optional[str] = Form(None, alias="key"), # Frontend sends 'key'
    key_file: Optional[UploadFile] = File(None),
    file: UploadFile = File(...)
):
    """
    Encrypts the uploaded file using the specified symmetric algorithm, mode, and key.
    - Key can be provided as a hex string, uploaded file, or auto-generated.
    - IV must be provided for CBC mode (hex format).
    - Returns the encrypted file for download.
    - If key/IV are auto-generated, they might be included in response headers (implementation specific).
    """
    input_data = await _read_file_content(file)
    key_bytes: Optional[bytes] = None
    iv_bytes: Optional[bytes] = None
    auto_generated_key: Optional[bytes] = None
    auto_generated_iv: Optional[bytes] = None

    # Determine IV
    iv_bytes_required = (mode == 'CBC')
    block_size_bytes = 16 if 'AES' in algorithm else 8 # AES=16, 3DES=8

    if iv_bytes_required:
        if iv_hex:
            iv_bytes = _hex_to_bytes(iv_hex, expected_bytes=block_size_bytes, field_name="IV")
        else:
            # Requirement is user provides IV for CBC, so raise error if missing
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IV is required for CBC mode.")
            # If auto-generation was allowed:
            # iv_bytes = os.urandom(block_size_bytes)
            # auto_generated_iv = iv_bytes
    elif iv_hex:
         # IV provided but not needed (e.g., for ECB) - could warn or ignore
         pass

    # Determine Key (Priority: File > Hex String > Auto-generate)
    key_size_bytes = 0
    if algorithm == 'AES-128': key_size_bytes = 16
    elif algorithm == 'AES-256': key_size_bytes = 32
    elif algorithm == '3DES': key_size_bytes = 24

    if key_file:
        key_bytes_from_file = await _read_file_content(key_file)
        if len(key_bytes_from_file) != key_size_bytes:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Key file content size ({len(key_bytes_from_file)} bytes) does not match required size for {algorithm} ({key_size_bytes} bytes).")
        key_bytes = key_bytes_from_file
    elif key_hex:
        key_bytes = _hex_to_bytes(key_hex, expected_bytes=key_size_bytes, field_name="Key")
    else:
        # Auto-generate key if none provided
        key_bytes = os.urandom(key_size_bytes)
        auto_generated_key = key_bytes

    if not key_bytes:
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Encryption key is required.") # Should not happen with auto-gen

    try:
        ciphertext = crypto_service.encrypt_symmetric(
            algorithm=algorithm,
            mode=mode,
            key=key_bytes,
            iv=iv_bytes,
            data=input_data
        )

        # Set headers if key/IV were auto-generated (example)
        custom_headers = {}
        if auto_generated_key:
            custom_headers["X-Generated-Key-Hex"] = binascii.hexlify(auto_generated_key).decode()
        # if auto_generated_iv:
        #     custom_headers["X-Generated-IV-Hex"] = binascii.hexlify(auto_generated_iv).decode()

        # Determine download filename
        base, ext = os.path.splitext(file.filename)
        download_filename = f"{base}_encrypted{ext if ext else '.bin'}"

        return Response(
            content=ciphertext,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename=\"{download_filename}\"",
                **custom_headers
            }
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Encryption error: {e}")
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during symmetric encryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to encrypt file.")

@router.post(
    "/decrypt/symmetric",
    summary="Decrypt a file using a symmetric algorithm",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def decrypt_symmetric_endpoint(
    algorithm: Literal['AES-128', 'AES-256', '3DES'] = Form(...),
    mode: Literal['CBC', 'ECB'] = Form(...),
    iv_hex: Optional[str] = Form(None, alias="iv"), # Required for CBC
    key_hex: Optional[str] = Form(None, alias="key"),
    key_file: Optional[UploadFile] = File(None),
    file: UploadFile = File(...)
):
    """
    Decrypts the uploaded file using the specified symmetric algorithm, mode, key, and IV.
    - Key must be provided either as a hex string or an uploaded file.
    - IV must be provided for CBC mode (hex format).
    - Returns the decrypted file for download.
    """
    print(f"DEBUG - decrypt_symmetric_endpoint called with algorithm={algorithm}, mode={mode}, file={file.filename}")
    
    try:
        # Read the encrypted file content
        ciphertext = await _read_file_content(file)
        print(f"DEBUG - Read encrypted file: {file.filename}, size: {len(ciphertext)} bytes")
        
        key_bytes: Optional[bytes] = None
        iv_bytes: Optional[bytes] = None

        # Determine IV
        iv_bytes_required = (mode == 'CBC')
        block_size_bytes = 16 if 'AES' in algorithm else 8
        print(f"DEBUG - IV required: {iv_bytes_required}, block size: {block_size_bytes} bytes")

        if iv_bytes_required:
            if not iv_hex:
                print("DEBUG - CBC mode but no IV provided")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IV (hex) is required for CBC mode decryption.")
            try:
                iv_bytes = _hex_to_bytes(iv_hex, expected_bytes=block_size_bytes, field_name="IV")
                print(f"DEBUG - IV parsed successfully, size: {len(iv_bytes)} bytes")
            except Exception as e:
                print(f"DEBUG - Error parsing IV: {str(e)}")
                raise
        elif iv_hex:
            # IV provided but not needed (e.g., for ECB) - ignore
            print("DEBUG - IV provided but not needed for ECB mode")
            pass

        # Determine Key (Priority: File > Hex String)
        key_size_bytes = 0
        if algorithm == 'AES-128': key_size_bytes = 16
        elif algorithm == 'AES-256': key_size_bytes = 32
        elif algorithm == '3DES': key_size_bytes = 24
        print(f"DEBUG - Required key size for {algorithm}: {key_size_bytes} bytes")

        if key_file:
            print(f"DEBUG - Using key from file: {key_file.filename}")
            try:
                key_bytes_from_file = await _read_file_content(key_file)
                print(f"DEBUG - Read key file, size: {len(key_bytes_from_file)} bytes")
                if len(key_bytes_from_file) != key_size_bytes:
                    print(f"DEBUG - Key file has wrong size: {len(key_bytes_from_file)} bytes, expected: {key_size_bytes} bytes")
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Key file content size ({len(key_bytes_from_file)} bytes) does not match required size for {algorithm} ({key_size_bytes} bytes).")
                key_bytes = key_bytes_from_file
            except Exception as e:
                print(f"DEBUG - Error reading key file: {str(e)}")
                raise
        elif key_hex:
            print("DEBUG - Using key from hex input")
            try:
                key_bytes = _hex_to_bytes(key_hex, expected_bytes=key_size_bytes, field_name="Key")
                print(f"DEBUG - Key parsed from hex, size: {len(key_bytes)} bytes")
            except Exception as e:
                print(f"DEBUG - Error parsing key hex: {str(e)}")
                raise
        else:
            print("DEBUG - No key provided")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Decryption key (hex string or file) is required.")

        if not key_bytes:
             print("DEBUG - Key bytes is None after processing")
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Decryption key is required.") # Should not happen

        # Call decrypt_symmetric function
        print("DEBUG - Calling decrypt_symmetric service function")
        try:
            plaintext = crypto_service.decrypt_symmetric(
                algorithm=algorithm,
                mode=mode,
                key=key_bytes,
                iv=iv_bytes,
                ciphertext=ciphertext
            )
            print(f"DEBUG - Decryption successful, plaintext size: {len(plaintext)} bytes")
        except ValueError as e:
            print(f"DEBUG - ValueError from decrypt_symmetric: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Decryption error: {e}")
        except Exception as e:
            print(f"DEBUG - Unexpected error from decrypt_symmetric: {str(e)}")
            import traceback
            print(f"DEBUG - Traceback: {traceback.format_exc()}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to decrypt file: {str(e)}")

        # Determine download filename
        base, ext = os.path.splitext(file.filename)
        if base.endswith('_encrypted'):
            base = base[:-10] # Remove '_encrypted' suffix if present
        download_filename = f"{base}_decrypted{ext if ext else '.txt'}"
        print(f"DEBUG - Download filename: {download_filename}")

        # Create response with decrypted content
        print(f"DEBUG - Creating response with {len(plaintext)} bytes of data")
        try:
            response = Response(
                content=plaintext,
                media_type="application/octet-stream", # Or try to guess based on original extension
                headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
            )
            print("DEBUG - Response created successfully")
            return response
        except Exception as e:
            print(f"DEBUG - Error creating response: {str(e)}")
            import traceback
            print(f"DEBUG - Traceback: {traceback.format_exc()}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error creating response: {str(e)}")

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log the exception in a real app
        print(f"DEBUG - Unhandled exception in decrypt_symmetric_endpoint: {str(e)}")
        import traceback
        print(f"DEBUG - Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to decrypt file: {str(e)}")


# --- Asymmetric Encryption/Decryption Endpoints ---

@router.post(
    "/encrypt/asymmetric",
    summary="Encrypt a file using an asymmetric algorithm (RSA)",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def encrypt_asymmetric_endpoint(
    algorithm: Literal['RSA-2048'] = Form(...),
    public_key_file: UploadFile = File(..., alias="publicKeyFile"), # Match frontend name if needed
    file: UploadFile = File(...)
):
    """
    Encrypts the uploaded file using the recipient's RSA public key.
    - Requires RSA-2048 algorithm.
    - Public key must be provided as an uploaded PEM file.
    - Returns the encrypted file for download.
    """
    input_data = await _read_file_content(file)
    public_key_bytes = await _read_file_content(public_key_file)

    try:
        ciphertext = crypto_service.encrypt_asymmetric(
            algorithm=algorithm,
            public_key_bytes=public_key_bytes,
            data=input_data
        )

        # Determine download filename
        base, ext = os.path.splitext(file.filename)
        download_filename = f"{base}_encrypted_asym{ext if ext else '.bin'}"

        return Response(
            content=ciphertext,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Asymmetric encryption error: {e}")
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during asymmetric encryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to encrypt file.")

@router.post(
    "/decrypt/asymmetric",
    summary="Decrypt a file using an asymmetric algorithm (RSA)",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def decrypt_asymmetric_endpoint(
    algorithm: Literal['RSA-2048'] = Form(...),
    private_key_file: UploadFile = File(..., alias="privateKeyFile"), # Match frontend name if needed
    file: UploadFile = File(...)
):
    """
    Decrypts the uploaded file using the recipient's RSA private key.
    - Requires RSA-2048 algorithm.
    - Private key must be provided as an uploaded PEM file (unencrypted).
    - Returns the decrypted file for download.
    """
    ciphertext = await _read_file_content(file)
    private_key_bytes = await _read_file_content(private_key_file)

    try:
        plaintext = crypto_service.decrypt_asymmetric(
            algorithm=algorithm,
            private_key_bytes=private_key_bytes,
            ciphertext=ciphertext
        )

        # Determine download filename
        base, ext = os.path.splitext(file.filename)
        if base.endswith('_encrypted_asym'):
            base = base[:-15] # Remove suffix
        elif base.endswith('_encrypted'): # Handle potential generic suffix too
             base = base[:-10]
        download_filename = f"{base}_decrypted{ext if ext else '.txt'}"

        return Response(
            content=plaintext,
            media_type="application/octet-stream", # Or try to guess
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Asymmetric decryption error: {e}")
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during asymmetric decryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt file.")


# --- Hashing Endpoints ---

@router.post(
    "/hash",
    response_model=HashResponse,
    summary="Calculate the hash of an uploaded file",
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def hash_file_endpoint(
    algorithm: Literal['SHA2-256', 'SHA2-512', 'SHA3-256', 'SHA3-512'] = Form(...),
    file: UploadFile = File(...)
):
    """
    Calculates the hash of the uploaded file using the specified algorithm.
    Returns the calculated hash value in hexadecimal format.
    """
    input_data = await _read_file_content(file)

    try:
        hash_value = crypto_service.calculate_hash(data=input_data, algorithm=algorithm)
        return HashResponse(hash=hash_value)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Hashing error: {e}")
    except Exception as e:
        # Log the exception
        print(f"Error during hashing: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to hash file.")

@router.post(
    "/hash/compare",
    response_model=HashCompareResponse,
    summary="Compare the hashes of two uploaded files",
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def compare_hashes_endpoint(
    algorithm: Literal['SHA2-256', 'SHA2-512', 'SHA3-256', 'SHA3-512'] = Form(...),
    file1: UploadFile = File(..., alias="file1"),
    file2: UploadFile = File(..., alias="file2")
):
    """
    Calculates and compares the hashes of two uploaded files using the specified algorithm.
    Returns whether the hashes match and the calculated hashes.
    """
    # Read files concurrently if possible (using asyncio.gather), but sequential is simpler for now
    try:
        data1 = await _read_file_content(file1)
        data2 = await _read_file_content(file2)
    except HTTPException as e:
        # Re-raise HTTPException from _read_file_content
        raise e
    except Exception as e:
        # Catch other potential read errors
        print(f"Error reading files for hash comparison: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to read one or both files for comparison.")

    try:
        hash1 = crypto_service.calculate_hash(data=data1, algorithm=algorithm)
        hash2 = crypto_service.calculate_hash(data=data2, algorithm=algorithm)
        match = (hash1 == hash2)
        return HashCompareResponse(match=match, hash1=hash1, hash2=hash2)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Hashing error: {e}")
    except Exception as e:
        # Log the exception
        print(f"Error during hash comparison: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to compare file hashes.")


# --- Diffie-Hellman Endpoints ---
# Note: These endpoints manage state in memory (_dh_contexts in crypto_service).
# This is NOT suitable for production. Use a persistent store (DB, cache) in a real app.

@router.post(
    "/key-exchange/dh/initiate",
    # response_model=DHInitResponse, # Response is actually a file
    summary="Initiate Diffie-Hellman key exchange",
    response_class=Response,
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def dh_initiate_endpoint(request: DHInitRequest):
    """
    Initiates the DH exchange by generating parameters and a key pair.
    Stores the private context associated with `key_name` (in memory - demo only).
    Returns the public value as a downloadable PEM file.
    """
    try:
        public_bytes, _ = crypto_service.initiate_dh_exchange(
            params_size=request.params_size,
            key_name=request.key_name
        )
        # Note: We are not returning the parameters file here for simplicity,
        # assuming standard parameters or pre-sharing.

        download_filename = f"{request.key_name}_dh_public.pem"

        return Response(
            content=public_bytes,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"DH initiation error: {e}")
    except Exception as e:
        # Log the exception
        print(f"Error during DH initiation: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initiate DH exchange.")

@router.post(
    "/key-exchange/dh/complete",
    response_model=DHCompleteResponse,
    summary="Complete Diffie-Hellman key exchange",
    # dependencies=[Depends(get_current_active_user_placeholder)] # Add auth later
)
async def dh_complete_endpoint(request: DHCompleteRequest):
    """
    Completes the DH exchange using the other party's public value.
    Retrieves the stored private context associated with `key_name`.
    Computes the shared secret.
    """
    try:
        # Assuming the other party's public value is provided as a hex string in the request body
        # If it's expected as a file upload, adjust the endpoint signature and reading logic
        other_public_bytes = _hex_to_bytes(request.other_party_public_value, field_name="Other party public value")
        if not other_public_bytes:
             raise ValueError("Other party's public value is required.")

        shared_secret = crypto_service.complete_dh_exchange(
            key_name=request.key_name,
            other_party_public_bytes=other_public_bytes
        )

        # Hash the shared secret for response (don't return raw secret)
        secret_hash = hashlib.sha256(shared_secret).hexdigest()

        return DHCompleteResponse(
            shared_secret_status=f"Shared secret computed successfully for '{request.key_name}'.",
            shared_secret_hash=secret_hash
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"DH completion error: {e}")
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during DH completion: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to complete DH exchange.")


    # Correct except clauses for decrypt_asymmetric_endpoint should already be present from line 379 onwards.
    # This diff removes the misplaced closing parenthesis and the duplicated/incorrectly formatted except blocks.
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during asymmetric decryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt file.")

    try:
        plaintext = crypto_service.decrypt_symmetric(
            algorithm=algorithm,
            mode=mode,
            key=key_bytes,
            iv=iv_bytes,
            ciphertext=ciphertext
        )

        # Determine download filename
        base, ext = os.path.splitext(file.filename)
        if base.endswith('_encrypted'):
            base = base[:-10] # Remove '_encrypted' suffix if present
        download_filename = f"{base}_decrypted{ext if ext else '.txt'}"

        return Response(
            content=plaintext,
            media_type="application/octet-stream", # Or try to guess based on original extension
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )

    except ValueError as e:
        # Specific error from decrypt_symmetric for bad key/IV/padding
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Decryption error: {e}")
    except Exception as e:
        # Log the exception in a real app
        print(f"Error during symmetric decryption: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to decrypt file.")

        # Log the exception in a real app
        print(f"Error generating key: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate key.")

# --- Symmetric Encryption/Decryption Endpoints ---
# (To be implemented next)

# --- Asymmetric Encryption/Decryption Endpoints ---
# (To be implemented)

# --- Hashing Endpoints ---
# (To be implemented)

# --- Diffie-Hellman Endpoints ---
# (To be implemented)