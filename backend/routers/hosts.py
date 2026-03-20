from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db
from models.host import Host
from models.scan import ScanResult
from models.user import User
from routers.auth import get_current_user
from tasks import run_remote_scan
from datetime import datetime

router = APIRouter()

class HostCreate(BaseModel):
    name: str
    ip_address: str
    port: int = 22
    ssh_username: str = "root"
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    description: Optional[str] = None

class HostUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    description: Optional[str] = None

@router.get("/")
def list_hosts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    hosts = db.query(Host).filter(Host.is_active == True).all()
    return [_host_dict(h) for h in hosts]

@router.post("/")
def create_host(data: HostCreate, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    host = Host(**data.dict())
    db.add(host)
    db.commit()
    db.refresh(host)
    return _host_dict(host)

@router.put("/{host_id}")
def update_host(host_id: int, data: HostUpdate, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Хост не найден")
    for k, v in data.dict(exclude_none=True).items():
        setattr(host, k, v)
    db.commit()
    return _host_dict(host)

@router.delete("/{host_id}")
def delete_host(host_id: int, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Хост не найден")
    host.is_active = False
    db.commit()
    return {"message": "Хост удалён"}

@router.post("/{host_id}/scan")
def scan_host(host_id: int, db: Session = Depends(get_db),
              current_user: User = Depends(get_current_user)):
    host = db.query(Host).filter(Host.id == host_id).first()
    if not host:
        raise HTTPException(404, "Хост не найден")
    scan = ScanResult(host_id=host_id, scan_type="remote", status="running",
                      initiated_by=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    run_remote_scan.delay(scan.id, host_id)
    return {"scan_id": scan.id, "status": "running"}

@router.get("/{host_id}/scans")
def host_scans(host_id: int, db: Session = Depends(get_db),
               current_user: User = Depends(get_current_user)):
    scans = db.query(ScanResult).filter(ScanResult.host_id == host_id).order_by(
        ScanResult.started_at.desc()).limit(10).all()
    return [{"id": s.id, "score": s.score, "status": s.status,
             "started_at": s.started_at.isoformat() if s.started_at else None} for s in scans]

def _host_dict(h: Host):
    return {"id": h.id, "name": h.name, "ip_address": h.ip_address, "port": h.port,
            "ssh_username": h.ssh_username, "description": h.description,
            "is_active": h.is_active, "last_score": h.last_score,
            "last_scan": h.last_scan.isoformat() if h.last_scan else None,
            "created_at": h.created_at.isoformat() if h.created_at else None}
