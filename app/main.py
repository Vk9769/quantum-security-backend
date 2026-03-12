from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Import API router
from app.api.v1.router import router


# -----------------------------------------------------
# Logging Configuration
# -----------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# -----------------------------------------------------
# Create FastAPI App
# -----------------------------------------------------

app = FastAPI(
    title="Quantum Security Scanner",
    description="Enterprise Quantum-Ready Security Scanning Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


# -----------------------------------------------------
# CORS Configuration
# (Required for React / Frontend Dashboard)
# -----------------------------------------------------

origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------
# Startup Event
# -----------------------------------------------------

@app.on_event("startup")
async def startup_event():
    logger.info("Quantum Security Scanner API starting...")


# -----------------------------------------------------
# Shutdown Event
# -----------------------------------------------------

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Quantum Security Scanner API shutting down...")


# -----------------------------------------------------
# Root Endpoint
# -----------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "Quantum Security Scanner API",
        "status": "running",
        "version": "1.0"
    }


# -----------------------------------------------------
# Health Check Endpoint
# -----------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# -----------------------------------------------------
# Include API Router
# -----------------------------------------------------

app.include_router(router, prefix="/api/v1", tags=["API v1"])