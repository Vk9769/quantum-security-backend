from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import logging
import threading

from app.utils.log_streamer import setup_logger, set_main_loop
from app.workers.log_consumer import start_log_consumer
from app.workers.worker_manager import worker_manager

# Load environment variables
load_dotenv()

# Import API router
from app.api.v1.router import router

# -----------------------------------------------------
# Logging Configuration
# -----------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s"
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

# Disable uvicorn default logs
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn.error").disabled = True
logging.getLogger("uvicorn").disabled = True

setup_logger()

# -----------------------------------------------------
# CORS Configuration
# -----------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "http://localhost:8000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------
# Startup Event
# -----------------------------------------------------
from app.db.postgres import Base, engine
from app.models import user, organization
from app.services.graph_service import GraphService

@app.on_event("startup")
async def startup_event():
    import asyncio

    set_main_loop(asyncio.get_running_loop())

    threading.Thread(
        target=start_log_consumer,
        daemon=True
    ).start()

    logger.info("Quantum Security Scanner API starting...")

    # Create tables automatically
    Base.metadata.create_all(bind=engine)

    # Test Neo4j connection
    try:
        graph = GraphService()
        logger.info("Neo4j connection initialized")
        graph.close()
    except Exception as e:
        logger.error(f"Neo4j connection failed: {e}")

    # Workers are NOT auto-started here
    # They will start automatically on first /scan/start request

# -----------------------------------------------------
# Shutdown Event
# -----------------------------------------------------
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Quantum Security Scanner API shutting down...")
    worker_manager.stop_all_workers()

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

# Optional worker status endpoint
@app.get("/worker-status")
def worker_status():
    return worker_manager.get_worker_status()

# -----------------------------------------------------
# Include API Router
# -----------------------------------------------------
app.include_router(router, prefix="/api/v1", tags=["API v1"])