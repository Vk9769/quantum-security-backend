import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# -------------------------------------------------------
# Load environment variables
# -------------------------------------------------------
load_dotenv()

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "security_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "admin")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "admin")

# -------------------------------------------------------
# Database URL
# -------------------------------------------------------
DATABASE_URL = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)

# -------------------------------------------------------
# SQLAlchemy Engine
# -------------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=False
)

# -------------------------------------------------------
# Session Factory
# -------------------------------------------------------
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# -------------------------------------------------------
# Base Model for ORM
# -------------------------------------------------------
Base = declarative_base()

# IMPORTANT:
# Force-load model registry so SQLAlchemy relationships
# like relationship("AssetFingerprint") can resolve.
import app.models  # noqa: E402,F401

# -------------------------------------------------------
# Dependency for FastAPI
# -------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------------
# Database Connection Test
# -------------------------------------------------------
def test_connection():
    try:
        with engine.connect() as connection:
            print("PostgreSQL connection successful")
    except SQLAlchemyError as e:
        print("Database connection failed:", str(e))


# Run connection test if file executed directly
if __name__ == "__main__":
    test_connection()