from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import API routers
from app.api.endpoints import auth, crypto, user_files # key_exchange is within crypto.py now

# Define allowed origins for CORS (adjust as needed for production)
# In development, you might allow your frontend's local development server
origins = [
    "http://localhost:3000",  # Default Next.js dev port
    "http://127.0.0.1:3000",
    "https://encryptdecrypt-frontend.vercel.app",
    "https://encryptdecrypt-frontend-git-main-sergio-hernandezcs-projects.vercel.app",
    # Add your deployed frontend URL here for production
]

# Create the FastAPI app instance
app = FastAPI(
    title="EncryptDecryptBE API",
    description="API service for cryptographic operations.",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)

# Include the API routers
app.include_router(auth.router, prefix="/api", tags=["User Management"])
app.include_router(crypto.router, prefix="/api", tags=["Cryptographic Operations & Key Exchange"])
# Note: DH endpoints are included within the crypto router with prefix /api/key-exchange/dh/*
app.include_router(user_files.router, prefix="/api/user", tags=["User Files"])


# Root endpoint for basic health check
@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the EncryptDecryptBE API!"}

# Add startup/shutdown events if needed later
# @app.on_event("startup")
# async def startup_event():
#     # Initialize database connections, etc.
#     pass

# @app.on_event("shutdown")
# async def shutdown_event():
#     # Close database connections, etc.
#     pass