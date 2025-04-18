import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Literal
from fastapi import UploadFile

from app.models.user_file_models import UserFileResponse
from app.core.config import settings # Might be needed for upload directory

# --- In-Memory Storage Simulation (NOT FOR PRODUCTION) ---
# Structure: { "username": { "file_id": { metadata + content } } }
_user_files_db: Dict[str, Dict[str, Dict]] = {}

# Example: Configure upload directory if using local storage
# UPLOAD_DIR = settings.UPLOAD_DIR
# os.makedirs(UPLOAD_DIR, exist_ok=True)

async def save_user_file(
    username: str,
    file_type: Literal['key', 'document'],
    name: str,
    file: UploadFile
) -> UserFileResponse:
    """Saves an uploaded file for a specific user (In-Memory Simulation)."""
    file_id = str(uuid.uuid4())
    content = await file.read()
    created_at = datetime.now(timezone.utc)

    if username not in _user_files_db:
        _user_files_db[username] = {}

    # Check for duplicate names for the same user (optional)
    # for existing_file in _user_files_db[username].values():
    #     if existing_file["metadata"]["name"] == name:
    #         raise ValueError(f"A file with the name '{name}' already exists for this user.")

    file_metadata = UserFileResponse(
        id=file_id,
        name=name,
        file_type=file_type,
        created_at=created_at
        # Add size, content_type if needed:
        # size=len(content),
        # content_type=file.content_type
    )

    _user_files_db[username][file_id] = {
        "metadata": file_metadata.model_dump(), # Store as dict
        "content": content
    }

    print(f"Simulated saving file '{name}' (ID: {file_id}) for user '{username}'.") # Debug logging
    return file_metadata # Return the Pydantic model instance

async def list_user_files(username: str) -> List[UserFileResponse]:
    """Lists all stored files for a specific user (In-Memory Simulation)."""
    user_store = _user_files_db.get(username, {})
    # Convert stored dict metadata back to Pydantic models
    return [UserFileResponse(**file_data["metadata"]) for file_data in user_store.values()]

async def get_user_file(username: str, file_id: str) -> Optional[Tuple[UserFileResponse, bytes]]:
    """Retrieves a specific file's metadata and content for a user (In-Memory Simulation)."""
    user_store = _user_files_db.get(username, {})
    file_data = user_store.get(file_id)
    if file_data:
        metadata = UserFileResponse(**file_data["metadata"])
        content = file_data["content"]
        return metadata, content
    return None

async def delete_user_file(username: str, file_id: str) -> bool:
    """Deletes a specific file for a user (In-Memory Simulation)."""
    user_store = _user_files_db.get(username)
    if user_store and file_id in user_store:
        del user_store[file_id]
        print(f"Simulated deleting file ID: {file_id} for user '{username}'.") # Debug logging
        return True
    return False