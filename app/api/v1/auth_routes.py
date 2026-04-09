from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import uuid4

from app.db.postgres import get_db
from app.core.auth import hash_password, verify_password, create_access_token
from app.models.user import User
from app.models.organization import Organization

# ✅ NEW IMPORT (OTP Redis)
from app.db.redis import get_redis_client

router = APIRouter()


# ==========================================
# COMPANY REGISTER (WITH OTP VERIFICATION)
# ==========================================

@router.post("/company/register")
def register_company(data: dict, db: Session = Depends(get_db)):

    # ==========================
    # ✅ OTP VERIFICATION (NEW)
    # ==========================
    redis = get_redis_client()

    key = f"otp:{data['admin_email']}"
    stored_otp = redis.get(key)

    if not stored_otp:
        raise HTTPException(status_code=400, detail="OTP expired")

    if isinstance(stored_otp, bytes):
        stored_otp = stored_otp.decode()

    if stored_otp != data.get("otp"):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # delete OTP after success
    redis.delete(key)

    # ==========================
    # EXISTING LOGIC (UNCHANGED)
    # ==========================

    # Check if email already exists
    existing_user = db.query(User).filter(User.email == data["admin_email"]).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create organization
    org = Organization(
        id=uuid4(),
        name=data["company_name"],
        industry=data["industry"],
        country=data["country"]
    )

    db.add(org)

    # Create admin user
    admin = User(
        id=uuid4(),
        organization_id=org.id,
        name=data["admin_name"],
        email=data["admin_email"],
        role="admin",
        password_hash=hash_password(data["password"])
    )

    db.add(admin)

    db.commit()

    return {
        "message": "Company registered successfully"
    }


# ==========================================
# LOGIN (UNCHANGED)
# ==========================================

@router.post("/login")
def login(data: dict, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.email == data["email"]).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email")

    if not verify_password(data["password"], user.password_hash):
        raise HTTPException(status_code=401, detail="Wrong password")

    token = create_access_token({
        "user_id": str(user.id),
        "organization_id": str(user.organization_id),
        "role": user.role
    })

    return {
        "token": token,
        "user_id": str(user.id),
        "organization_id": str(user.organization_id),
        "role": user.role
    }