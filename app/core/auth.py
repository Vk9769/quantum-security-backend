from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET = "quantum-secret"


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict):

    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=8)

    token = jwt.encode(payload, SECRET, algorithm="HS256")

    return token