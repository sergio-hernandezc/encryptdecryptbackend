# EncryptDecryptBE - Backend API Service

This document outlines the plan for the Python FastAPI backend service for cryptographic operations, designed to support the `frontend` application and be deployable on Google Cloud Run.

## 1. Directory Structure

```
EncryptDecryptBE/
├── app/               # Main application source code
│   ├── __init__.py
│   ├── main.py        # FastAPI app instantiation, middleware, routers
│   ├── api/           # API endpoint definitions (routers)
│   │   ├── __init__.py
│   │   └── endpoints/ # Endpoint modules
│   │       ├── __init__.py
│   │       ├── auth.py
│   │       ├── crypto.py
│   │       └── user_files.py
│   ├── core/          # Core logic (e.g., configuration)
│   │   ├── __init__.py
│   │   └── config.py
│   ├── services/      # Business logic layer
│   │   ├── __init__.py
│   │   ├── auth_service.py
│   │   ├── crypto_service.py
│   │   └── user_file_service.py
│   └── models/        # Pydantic models for data validation
│       ├── __init__.py
│       ├── auth_models.py
│       ├── crypto_models.py
│       └── user_file_models.py
├── .env.example       # Example file for environment variables
├── .gitignore         # Specifies intentionally untracked files for Git
├── Dockerfile         # Instructions to build the container image for Cloud Run
├── requirements.txt   # Lists Python package dependencies
└── README.md          # This file
```

## 2. Framework

*   **FastAPI:** Chosen for performance, automatic data validation (Pydantic), dependency injection, and built-in API documentation.

## 3. API Endpoints & Data Models

Authentication is handled separately and required for most crypto operations (via token in header). File uploads use FastAPI's `UploadFile` and form data. File downloads use `FileResponse`.

**Authentication (`/auth`)**

*   `POST /register`: `AuthRequest(username: str, password: str)` -> `TokenResponse(access_token: str, token_type: str)`
*   `POST /login`: `AuthRequest(username: str, password: str)` -> `TokenResponse`
*   *(Potentially others: manage user, delete user)*

**Cryptographic Operations (`/api`)**

*   **Generate Password:**
    *   `POST /generate/password`
    *   Request: `PasswordGenRequest(length: int, use_uppercase: bool, use_lowercase: bool, use_numbers: bool, use_symbols: bool)`
    *   Response: `PasswordGenResponse(password: str)`
*   **Generate Key:**
    *   `POST /generate/key`
    *   Request: `KeyGenRequest(key_type: Literal['symmetric', 'asymmetric'], algorithm: Literal['AES-128', 'AES-256', '3DES', 'RSA-2048'], key_name: str)`
    *   Response: `FileResponse` (e.g., `aes_key.key`, `rsa_public.pem`, `rsa_private.pem`) named using `key_name`.
*   **Encrypt Symmetric:**
    *   `POST /encrypt/symmetric`
    *   Request (Form Data): `algorithm: Literal['AES-128', 'AES-256', '3DES']`, `mode: Literal['CBC', 'ECB']`, `iv: Optional[str]` (Required if mode='CBC', hex), `key: Optional[str]` (Hex), `key_file: Optional[UploadFile]`, `file: UploadFile`. (Backend handles key precedence: file > string > auto-generate).
    *   Response: `FileResponse` (encrypted data). Include auto-generated key/IV in headers if applicable.
*   **Decrypt Symmetric:**
    *   `POST /decrypt/symmetric`
    *   Request (Form Data): `algorithm: Literal['AES-128', 'AES-256', '3DES']`, `mode: Literal['CBC', 'ECB']`, `iv: str` (Required if mode='CBC', hex), `key: Optional[str]` (Hex), `key_file: Optional[UploadFile]`, `file: UploadFile`. (Backend handles key precedence: file > string).
    *   Response: `FileResponse` (decrypted data).
*   **Encrypt Asymmetric:**
    *   `POST /encrypt/asymmetric`
    *   Request (Form Data): `algorithm: Literal['RSA-2048']`, `public_key_file: UploadFile`, `file: UploadFile`.
    *   Response: `FileResponse` (encrypted data).
*   **Decrypt Asymmetric:**
    *   `POST /decrypt/asymmetric`
    *   Request (Form Data): `algorithm: Literal['RSA-2048']`, `private_key_file: UploadFile`, `file: UploadFile`.
    *   Response: `FileResponse` (decrypted data).
*   **Hash File:**
    *   `POST /hash`
    *   Request (Form Data): `algorithm: Literal['SHA2-256', 'SHA2-512', 'SHA3-256', 'SHA3-512']`, `file: UploadFile`.
    *   Response: `HashResponse(hash: str)`
*   **Compare Hashes:**
    *   `POST /hash/compare`
    *   Request (Form Data): `algorithm: Literal['SHA2-256', 'SHA2-512', 'SHA3-256', 'SHA3-512']`, `file1: UploadFile`, `file2: UploadFile`.
    *   Response: `HashCompareResponse(match: bool, hash1: str, hash2: str)`
*   **Generate & Share Keys (DH):**
    *   `POST /key-exchange/dh/initiate`
    *   Request: `DHInitRequest(params_size: Literal[1024, 2048], key_name: str)`
    *   Response: `DHInitResponse(public_value: str, key_name: str)` (Backend saves private components associated with `key_name`). Returns public value as file via `FileResponse`.
    *   `POST /key-exchange/dh/complete`
    *   Request: `DHCompleteRequest(key_name: str, other_party_public_value: str)`
    *   Response: `DHCompleteResponse(shared_secret_status: str)` (e.g., "Computed and saved"). Returns shared secret hash/status, potentially saves secret associated with `key_name`.

**User File Management (`/api/user`)** (Requires Authentication)

*   `POST /files`: Request (Form Data): `file_type: Literal['key', 'document']`, `name: str`, `file: UploadFile` -> `UserFileResponse`
*   `GET /files`: -> `List[UserFileResponse]`
*   `GET /files/{file_id}`: -> `FileResponse`
*   `DELETE /files/{file_id}`: -> `StatusResponse(status: str)`

## 4. Frontend State Requirements Summary

The frontend needs to manage state for:
*   Selected operation.
*   Authentication token.
*   Loading/Error/Result states.
*   Inputs specific to each operation (algorithms, modes, keys, IVs, files, lengths, options, names) as detailed in the API endpoints.
*   File objects for uploads.

## 5. Next Steps

Implement the FastAPI application structure, models, services, and endpoints according to this plan.