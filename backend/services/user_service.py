import os
import bcrypt as bcrypt_lib
from sqlalchemy.orm import Session
from models.user import User
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError

SECRET_KEY = os.getenv("SECRET_KEY", "linshi-secret-key-change-in-production-256bits")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

def hash_password(password: str) -> str:
    return bcrypt_lib.hashpw(password.encode("utf-8"), bcrypt_lib.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt_lib.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_initial_admin(db: Session):
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    existing = db.query(User).filter(User.username == admin_username).first()
    if existing:
        return
    admin = User(
        username=admin_username,
        email=os.getenv("ADMIN_EMAIL", "admin@company.local"),
        hashed_password=hash_password(os.getenv("ADMIN_PASSWORD", "admin123")),
        role="admin",
        is_active=True
    )
    db.add(admin)
    db.commit()
    print(f"[+] Admin '{admin_username}' created successfully")
