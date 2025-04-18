# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Set environment variables
# Prevents Python from writing pyc files to disc (equivalent to python -B)
ENV PYTHONDONTWRITEBYTECODE 1
# Prevents Python from buffering stdout and stderr (equivalent to python -u)
ENV PYTHONUNBUFFERED 1

# Install system dependencies if needed (e.g., for certain crypto libraries)
# RUN apt-get update && apt-get install -y --no-install-recommends some-package && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
# Copy only the requirements file first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY ./app /app/app

# Expose the port the app runs on
# Google Cloud Run expects the container to listen on the port specified by the PORT env var (default 8080)
# Uvicorn will be configured to listen on this port.
EXPOSE 8080

# Define the command to run the application
# Use the PORT environment variable provided by Cloud Run, default to 8080
# Use 0.0.0.0 to listen on all available network interfaces
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}