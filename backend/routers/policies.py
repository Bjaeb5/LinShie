from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from database import get_db
from models.policy import Policy
from models.host import Host
from models.user import User
from routers.auth import get_current_user, require_admin
from services.policy_engine import apply_policy_to_host

router = APIRouter()

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str  # password, ssh, firewall, audit, updates
    rules: Dict[str, Any] = {}

class PolicyApply(BaseModel):
    host_ids: List[int]

@router.get("/")
def list_policies(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return [_policy_dict(p) for p in db.query(Policy).filter(Policy.is_active == True).all()]

@router.post("/")
def create_policy(data: PolicyCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_admin)):
    policy = Policy(**data.dict(), created_by=current_user.id)
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return _policy_dict(policy)

@router.put("/{policy_id}")
def update_policy(policy_id: int, data: PolicyCreate, db: Session = Depends(get_db),
                  current_user: User = Depends(require_admin)):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(404, "Политика не найдена")
    for k, v in data.dict().items():
        setattr(policy, k, v)
    db.commit()
    return _policy_dict(policy)

@router.delete("/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db),
                  current_user: User = Depends(require_admin)):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(404, "Политика не найдена")
    policy.is_active = False
    db.commit()
    return {"message": "Политика удалена"}

@router.post("/{policy_id}/apply")
def apply_policy(policy_id: int, req: PolicyApply, db: Session = Depends(get_db),
                 current_user: User = Depends(require_admin)):
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(404, "Политика не найдена")
    results = []
    for host_id in req.host_ids:
        host = db.query(Host).filter(Host.id == host_id).first()
        if not host:
            results.append({"host_id": host_id, "success": False, "error": "Хост не найден"})
            continue
        if not host.ssh_password and not host.ssh_key:
            results.append({"host_id": host_id, "success": False, "error": "Нет SSH-учётных данных"})
            continue
        result = apply_policy_to_host(
            host.ip_address, host.port, host.ssh_username,
            host.ssh_password, policy.category, policy.rules
        )
        results.append({"host_id": host_id, "host_name": host.name, **result})
    return {"policy": policy.name, "results": results}

@router.get("/templates")
def policy_templates(current_user: User = Depends(get_current_user)):
    return [
        {"category": "password", "name": "Политика паролей CIS L1",
         "rules": {"min_length": 12, "max_age": 90, "min_age": 1}},
        {"category": "ssh", "name": "Политика SSH (строгая)",
         "rules": {"permit_root": "no", "password_auth": "no", "max_auth_tries": 4, "idle_timeout": 300}},
        {"category": "firewall", "name": "Базовый фаервол",
         "rules": {"allowed_ports": ["22", "80", "443"]}},
        {"category": "audit", "name": "Аудит системных событий",
         "rules": {}},
        {"category": "updates", "name": "Автообновления безопасности",
         "rules": {}},
    ]

def _policy_dict(p: Policy):
    return {"id": p.id, "name": p.name, "description": p.description,
            "category": p.category, "rules": p.rules, "is_active": p.is_active,
            "created_at": p.created_at.isoformat() if p.created_at else None}
