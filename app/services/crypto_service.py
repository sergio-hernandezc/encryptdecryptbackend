import os
import secrets
import string
import hashlib
from typing import Optional, Tuple, Dict, Literal, Union
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Example KDF if needed later
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidKey, InvalidTag # Import specific exceptions

# --- Password Generation ---

def generate_password(
    length: int,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_symbols: bool
) -> str:
    """Generates a secure random password based on specified criteria."""
    character_set = ""
    if use_uppercase:
        character_set += string.ascii_uppercase
    if use_lowercase:
        character_set += string.ascii_lowercase
    if use_numbers:
        character_set += string.digits
    if use_symbols:
        character_set += string.punctuation

    if not character_set:
        raise ValueError("At least one character type must be selected for password generation.")

    # Ensure the password meets complexity requirements if all types are selected
    password_chars = []
    if use_uppercase:
        password_chars.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        password_chars.append(secrets.choice(string.ascii_lowercase))
    if use_numbers:
        password_chars.append(secrets.choice(string.digits))
    if use_symbols:
        password_chars.append(secrets.choice(string.punctuation))

    # Fill the rest of the password length
    remaining_length = length - len(password_chars)
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(character_set))

    # Shuffle the characters to avoid predictable patterns
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)

# --- Key Generation ---
# (To be implemented next)

# --- Symmetric Encryption/Decryption ---
# (To be implemented)

def generate_key(key_type: Literal['symmetric', 'asymmetric'], algorithm: Literal['AES-128', 'AES-256', '3DES', 'RSA-2048']) -> Dict[str, bytes]:
    """Generates cryptographic keys based on type and algorithm.

    Returns:
        A dictionary where keys are suggested filenames (e.g., 'private.pem', 'public.pem', 'symmetric.key')
        and values are the key material in bytes.
    """
    key_material = {}

    if key_type == 'symmetric':
        key_bytes: Optional[bytes] = None
        filename = "symmetric.key"
        if algorithm == 'AES-128':
            key_bytes = os.urandom(16) # 128 bits
            filename = "aes_128.key"
        elif algorithm == 'AES-256':
            key_bytes = os.urandom(32) # 256 bits
            filename = "aes_256.key"
        elif algorithm == '3DES':
            # 3DES uses 16 or 24 bytes. We'll use 24 for Triple DES (3-key).
            key_bytes = os.urandom(24)
            filename = "3des.key"
        else:
            raise ValueError(f"Unsupported symmetric algorithm: {algorithm}")
        if key_bytes:
            key_material[filename] = key_bytes

    elif key_type == 'asymmetric':
        if algorithm == 'RSA-2048':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Serialize private key to PEM format (unencrypted)
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            key_material["rsa_private.pem"] = pem_private

            # Serialize public key to PEM format
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_material["rsa_public.pem"] = pem_public
        else:
            raise ValueError(f"Unsupported asymmetric algorithm: {algorithm}")

    else:
        raise ValueError(f"Unsupported key type: {key_type}")


# --- Symmetric Encryption/Decryption ---

def _get_symmetric_cipher(algorithm_name: Literal['AES-128', 'AES-256', '3DES'], mode_name: Literal['CBC', 'ECB'], key: bytes, iv: Optional[bytes]):
    """Helper to create a symmetric cipher context."""
    algo = None
    block_size = 0
    if algorithm_name == 'AES-128':
        if len(key) != 16:
            raise ValueError("Invalid key size for AES-128. Must be 16 bytes.")
        algo = algorithms.AES(key)
        block_size = 16 # AES block size is 128 bits (16 bytes)
    elif algorithm_name == 'AES-256':
        if len(key) != 32:
            raise ValueError("Invalid key size for AES-256. Must be 32 bytes.")
        algo = algorithms.AES(key)
        block_size = 16
    elif algorithm_name == '3DES':
        if len(key) != 24: # Assuming 3-key Triple DES
            raise ValueError("Invalid key size for 3DES. Must be 24 bytes.")
        algo = algorithms.TripleDES(key)
        block_size = 8 # 3DES block size is 64 bits (8 bytes)
    else:
        raise ValueError(f"Unsupported symmetric algorithm: {algorithm_name}")

    mode = None
    if mode_name == 'CBC':
        if not iv or len(iv) * 8 != algo.block_size:
             raise ValueError(f"Invalid IV size for {algorithm_name} {mode_name}. Must be {algo.block_size // 8} bytes.")
        mode = modes.CBC(iv)
    elif mode_name == 'ECB':
        # IV is not used in ECB mode
        mode = modes.ECB()
    else:
        raise ValueError(f"Unsupported block mode: {mode_name}")

    return Cipher(algo, mode, backend=default_backend()), block_size

def encrypt_symmetric(
    algorithm: Literal['AES-128', 'AES-256', '3DES'],
    mode: Literal['CBC', 'ECB'],
    key: bytes,
    iv: Optional[bytes], # Required for CBC
    data: bytes
) -> bytes:
    """Encrypts data using a symmetric algorithm."""
    cipher, block_size_bytes = _get_symmetric_cipher(algorithm, mode, key, iv)
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    padder = sym_padding.PKCS7(block_size_bytes * 8).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_symmetric(
    algorithm: Literal['AES-128', 'AES-256', '3DES'],
    mode: Literal['CBC', 'ECB'],
    key: bytes,
    iv: Optional[bytes], # Required for CBC
    ciphertext: bytes
) -> bytes:
    """Decrypts data using a symmetric algorithm."""
    cipher, block_size_bytes = _get_symmetric_cipher(algorithm, mode, key, iv)
    decryptor = cipher.decryptor()

    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(block_size_bytes * 8).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except (ValueError, InvalidTag) as e:
        # ValueError can be raised by unpadder if padding is incorrect
        # InvalidTag might be raised by authenticated modes (not used here, but good practice)
        raise ValueError("Decryption failed. Incorrect key, IV, or corrupted data.") from e


# --- Asymmetric Encryption/Decryption ---

def _load_public_key(key_bytes: bytes) -> rsa.RSAPublicKey:
    """Loads an RSA public key from PEM formatted bytes."""
    try:
        public_key = serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Loaded key is not an RSA public key.")
        # Optional: Check key size if needed
        # if public_key.key_size != 2048:
        #     raise ValueError("Public key size must be 2048 bits.")
        return public_key
    except Exception as e:
        raise ValueError("Failed to load public key. Ensure it is valid PEM format.") from e

def _load_private_key(key_bytes: bytes) -> rsa.RSAPrivateKey:
    """Loads an RSA private key from PEM formatted bytes (unencrypted)."""
    try:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None, # Assuming key is not password-protected
            backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Loaded key is not an RSA private key.")
        # Optional: Check key size if needed
        # if private_key.key_size != 2048:
        #     raise ValueError("Private key size must be 2048 bits.")
        return private_key
    except Exception as e:
        raise ValueError("Failed to load private key. Ensure it is valid PEM format and not encrypted.") from e

def encrypt_asymmetric(
    algorithm: Literal['RSA-2048'],
    public_key_bytes: bytes,
    data: bytes
) -> bytes:
    """Encrypts data using RSA public key with OAEP padding."""
    if algorithm != 'RSA-2048':
        raise ValueError(f"Unsupported asymmetric algorithm: {algorithm}")

    public_key = _load_public_key(public_key_bytes)

    # OAEP padding is recommended for RSA encryption
    oaep_padding = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    # Check data size limit for RSA encryption
    # Max data size = key_size_bytes - 2 * hash_size_bytes - 2
    max_data_size = (public_key.key_size // 8) - (2 * hashes.SHA256.digest_size) - 2
    if len(data) > max_data_size:
        raise ValueError(f"Data size ({len(data)} bytes) exceeds maximum allowed for RSA-2048 with OAEP padding ({max_data_size} bytes).")

    ciphertext = public_key.encrypt(
        data,
        oaep_padding
    )
    return ciphertext

def decrypt_asymmetric(
    algorithm: Literal['RSA-2048'],
    private_key_bytes: bytes,
    ciphertext: bytes
) -> bytes:
    """Decrypts data using RSA private key with OAEP padding."""
    if algorithm != 'RSA-2048':
        raise ValueError(f"Unsupported asymmetric algorithm: {algorithm}")

    private_key = _load_private_key(private_key_bytes)

    # OAEP padding must match the one used for encryption
    oaep_padding = asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            oaep_padding
        )
        return plaintext
    except ValueError as e:
        # This exception is typically raised by the padding verification if decryption fails
        raise ValueError("Decryption failed. Incorrect private key or corrupted data.") from e
    except Exception as e:
        # Catch other potential errors during decryption
        raise RuntimeError(f"An unexpected error occurred during decryption: {e}") from e




# --- Hashing ---

def calculate_hash(data: bytes, algorithm: Literal['SHA2-256', 'SHA2-512', 'SHA3-256', 'SHA3-512']) -> str:
    """Calculates the hash of the given data using the specified algorithm."""
    hasher = None
    if algorithm == 'SHA2-256':
        hasher = hashlib.sha256()
    elif algorithm == 'SHA2-512':
        hasher = hashlib.sha512()
    elif algorithm == 'SHA3-256':
        hasher = hashlib.sha3_256()
    elif algorithm == 'SHA3-512':
        hasher = hashlib.sha3_512()
    else:
        # This case should ideally be prevented by Pydantic validation in the endpoint
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


# --- Diffie-Hellman ---

# In-memory storage for DH contexts (Replace with persistent storage in production)
_dh_contexts: Dict[str, Dict] = {}

def initiate_dh_exchange(params_size: Literal[1024, 2048], key_name: str) -> Tuple[bytes, bytes]:
    """Initiates a Diffie-Hellman key exchange.

    Generates parameters and a private/public key pair.
    Stores the private key and parameters temporarily associated with key_name.

    Returns:
        A tuple containing (public_value_bytes, parameters_bytes).
    """
    if key_name in _dh_contexts:
        # Simple check to prevent overwriting, needs better handling in production
        raise ValueError(f"DH context for key name '{key_name}' already exists.")

    # Generate DH parameters (can be slow, especially for 2048)
    # Pre-generating parameters or using standard groups (like RFC 3526) is often better
    parameters = dh.generate_parameters(generator=2, key_size=params_size, backend=default_backend())

    # Generate private key
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Serialize public key and parameters for transmission/storage
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    params_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

    # Store context (private key and parameters) - SIMULATION
    _dh_contexts[key_name] = {
        "private_key": private_key,
        "parameters": parameters
    }

    # Return public value bytes (to be sent to the other party)
    # and parameter bytes (needed by the other party if they don't have them)
    return public_bytes, params_bytes

def complete_dh_exchange(key_name: str, other_party_public_bytes: bytes) -> bytes:
    """Completes the Diffie-Hellman key exchange using the other party's public key.

    Retrieves the stored private key and parameters.
    Computes the shared secret.

    Returns:
        The computed shared secret as bytes.
    """
    if key_name not in _dh_contexts:
        raise ValueError(f"No DH context found for key name '{key_name}'. Initiate first.")

    context = _dh_contexts[key_name]
    private_key: dh.DHPrivateKey = context["private_key"]
    parameters: dh.DHParameters = context["parameters"]

    try:
        # Load the other party's public key
        other_public_key = serialization.load_pem_public_key(
            other_party_public_bytes,
            backend=default_backend()
        )
        if not isinstance(other_public_key, dh.DHPublicKey):
            raise ValueError("Provided key is not a valid DH public key.")

        # Ensure the public key uses the same parameters (basic check)
        # A more robust check might compare parameter numbers (p, g)
        if other_public_key.parameters().parameter_numbers() != parameters.parameter_numbers():
             raise ValueError("Other party's public key uses different DH parameters.")

        # Compute the shared key
        shared_key = private_key.exchange(other_public_key)

        # Clean up the stored context after exchange (optional, depends on desired flow)
        # del _dh_contexts[key_name]

        # It's common practice to run the shared key through a KDF (Key Derivation Function)
        # like HKDF or PBKDF2 to get a key of a specific length suitable for symmetric encryption.
        # For now, we return the raw shared key.
        return shared_key

    except Exception as e:
        raise ValueError(f"Failed to complete DH exchange: {e}") from e


    hasher.update(data)
    return hasher.hexdigest()

# --- Hashing ---
# (To be implemented)

# --- Diffie-Hellman ---
# (To be implemented)

# --- Helper Functions ---
# (e.g., hex encoding/decoding, file reading)