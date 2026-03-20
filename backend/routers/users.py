from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db
from models.user import User
from routers.auth import get_current_user, require_admin
from services.user_service import hash_password

router = APIRouter()

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None

@router.get("/")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    users = db.query(User).all()
    return [_user_dict(u) for u in users]

@router.post("/")
def create_user(data: UserCreate, db: Session = Depends(get_db),
                current_user: User = Depends(require_admin)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Пользователь уже существует")
    user = User(username=data.username, email=data.email,
                hashed_password=hash_password(data.password), role=data.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_dict(user)

@router.put("/{user_id}")
def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db),
                current_user: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    if data.email: user.email = data.email
    if data.role: user.role = data.role
    if data.is_active is not None: user.is_active = data.is_active
    if data.password: user.hashed_password = hash_password(data.password)
    db.commit()
    return _user_dict(user)

@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(require_admin)):
    if user_id == current_user.id:
        raise HTTPException(400, "Нельзя удалить себя")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    db.delete(user)
    db.commit()
    return {"message": "Пользователь удалён"}

def _user_dict(u: User):
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login": u.last_login.isoformat() if u.last_login else None}
