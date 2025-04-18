from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime

class UserFileResponse(BaseModel):
    """
    Response model representing metadata for a user's stored file.
    """
    id: str = Field(..., description="Unique identifier for the stored file")
    name: str = Field(..., description="User-defined name for the file")
    file_type: Literal['key', 'document'] = Field(..., description="Type of the stored file")
    created_at: datetime = Field(..., description="Timestamp when the file was uploaded")
    # Add other relevant metadata if needed, e.g., size, content_type

    class Config:
        # If using an ORM like SQLAlchemy, this helps Pydantic work with it.
        # Remove or adjust if not using an ORM.
        from_attributes = True

# Note: Request for uploading uses Form data with UploadFile, so no specific Pydantic model needed here.