from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import random

from app.db.redis import get_redis_client
from app.utils.email_utils import send_email

router = APIRouter()

OTP_EXPIRY = 300  # 5 minutes


# ===============================
# SCHEMAS
# ===============================
class OTPRequest(BaseModel):
    email: str


class OTPVerify(BaseModel):
    email: str
    otp: str


# ===============================
# SEND OTP
# ===============================
@router.post("/send-otp")
def send_otp(data: OTPRequest):

    redis = get_redis_client()

    otp = str(random.randint(100000, 999999))
    key = f"otp:{data.email}"

    # Store OTP
    try:
        redis.setex(key, OTP_EXPIRY, otp)
    except Exception as e:
        print("❌ Redis error:", e)
        raise HTTPException(status_code=500, detail="Redis error")

    # Debug log
    print(f"🔐 OTP for {data.email}: {otp}")

    # ✅ IMPORTANT FIX → send to user email
    try:
        send_email(data.email, otp)
    except Exception as e:
        print("❌ Email failed:", e)
        # Don't block user

    return {"message": "OTP sent successfully"}


# ===============================
# VERIFY OTP
# ===============================
@router.post("/verify-otp")
def verify_otp(data: OTPVerify):

    redis = get_redis_client()
    key = f"otp:{data.email}"

    stored_otp = redis.get(key)

    if not stored_otp:
        raise HTTPException(status_code=400, detail="OTP expired")

    if isinstance(stored_otp, bytes):
        stored_otp = stored_otp.decode()

    if stored_otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    redis.delete(key)

    return {"message": "OTP verified successfully"}