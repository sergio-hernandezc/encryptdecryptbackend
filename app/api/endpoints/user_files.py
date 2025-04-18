import os
from typing import List, Literal
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

# Models
from app.models.user_file_models import UserFileResponse
from app.models.crypto_models import StatusResponse # Re-use for simple status messages
# Services
from app.services import user_file_service
# Placeholder for authentication dependency
# Import the actual authentication dependency
from app.api.endpoints.auth import get_current_user_id

router = APIRouter()

# Removed placeholder authentication dependency

# --- Endpoints ---

@router.post(
    "/files",
    response_model=UserFileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and save a user file (key or document)",
    dependencies=[Depends(get_current_user_id)] # Enforce authentication
)
async def upload_user_file(
    file_type: Literal['key', 'document'] = Form(...),
    name: str = Form(...),
    file: UploadFile = File(...),
    current_user_id: str = Depends(get_current_user_id) # Get authenticated user ID
):
    """
    Saves an uploaded file associated with the authenticated user.
    - **file_type**: Specify 'key' or 'document'.
    - **name**: A user-defined name for the file.
    - **file**: The file to upload.

    *Note: Uses in-memory storage simulation.*
    """
    # Removed username extraction logic

    try:
        # Pass user_id instead of username to the service
        file_metadata = await user_file_service.save_user_file(
            user_id=current_user_id, # NOTE: user_file_service needs update to accept user_id
            file_type=file_type,
            name=name,
            file=file
        )
        return file_metadata
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        print(f"Error saving user file: {e}") # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to save user file.")

@router.get(
    "/files",
    response_model=List[UserFileResponse],
    summary="List all files saved by the authenticated user",
    dependencies=[Depends(get_current_user_id)]
)
async def list_user_files_endpoint(
    current_user_id: str = Depends(get_current_user_id) # Get authenticated user ID
):
    """
    Retrieves a list of metadata for all files saved by the currently authenticated user.

    *Note: Uses in-memory storage simulation.*
    """
    # Removed username extraction logic

    try:
        # Pass user_id instead of username to the service
        files = await user_file_service.list_user_files(user_id=current_user_id) # NOTE: user_file_service needs update to accept user_id
        return files
    except Exception as e:
        print(f"Error listing user files: {e}") # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list user files.")

@router.get(
    "/files/{file_id}",
    summary="Download a specific user file",
    response_class=Response, # Direct file download
    dependencies=[Depends(get_current_user_id)]
)
async def download_user_file(
    file_id: str,
    current_user_id: str = Depends(get_current_user_id) # Get authenticated user ID
):
    """
    Downloads a specific file previously saved by the authenticated user.

    *Note: Uses in-memory storage simulation.*
    """
    # Removed username extraction logic

    try:
        # Pass user_id instead of username to the service
        file_info = await user_file_service.get_user_file(user_id=current_user_id, file_id=file_id) # NOTE: user_file_service needs update to accept user_id
        if not file_info:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found or access denied.")

        metadata, content = file_info
        # Use metadata.name for the download filename
        download_filename = metadata.name
        # Try to determine media type (optional, fallback to octet-stream)
        media_type = "application/octet-stream"
        # if metadata.content_type:
        #     media_type = metadata.content_type

        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
        )
    except HTTPException:
        raise # Re-raise specific HTTP exceptions
    except Exception as e:
        print(f"Error downloading user file {file_id}: {e}") # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to download user file.")


@router.delete(
    "/files/{file_id}",
    response_model=StatusResponse,
    summary="Delete a specific user file",
    dependencies=[Depends(get_current_user_id)]
)
async def delete_user_file_endpoint(
    file_id: str,
    current_user_id: str = Depends(get_current_user_id) # Get authenticated user ID
):
    """
    Deletes a specific file previously saved by the authenticated user.

    *Note: Uses in-memory storage simulation.*
    """
    # Removed username extraction logic

    try:
        # Pass user_id instead of username to the service
        deleted = await user_file_service.delete_user_file(user_id=current_user_id, file_id=file_id) # NOTE: user_file_service needs update to accept user_id
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found or access denied.")
        return StatusResponse(status=f"File '{file_id}' deleted successfully.")
    except HTTPException:
        raise # Re-raise specific HTTP exceptions
    except Exception as e:
        print(f"Error deleting user file {file_id}: {e}") # Log error
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete user file.")