from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from database import get_db
from models.scan import ScanResult
from models.user import User
from routers.auth import get_current_user
from tasks import run_local_scan
from datetime import datetime

router = APIRouter()

@router.post("/local")
def start_local_scan(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = ScanResult(scan_type="local", status="running", initiated_by=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    run_local_scan.delay(scan.id)
    return {"scan_id": scan.id, "status": "running", "message": "Сканирование запущено"}

@router.get("/")
def list_scans(skip: int = 0, limit: int = 20, db: Session = Depends(get_db),
               current_user: User = Depends(get_current_user)):
    scans = db.query(ScanResult).order_by(ScanResult.started_at.desc()).offset(skip).limit(limit).all()
    return [_scan_to_dict(s) for s in scans]

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db),
             current_user: User = Depends(get_current_user)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Сканирование не найдено")
    return _scan_to_dict(scan, include_findings=True)

@router.get("/stats/summary")
def scan_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from sqlalchemy import func
    total = db.query(ScanResult).count()
    last = db.query(ScanResult).filter(ScanResult.status == "completed").order_by(ScanResult.started_at.desc()).first()
    avg_score = db.query(func.avg(ScanResult.score)).filter(ScanResult.status == "completed").scalar()
    return {
        "total_scans": total,
        "last_score": last.score if last else None,
        "avg_score": round(float(avg_score), 1) if avg_score else None,
        "last_scan_time": last.completed_at.isoformat() if last and last.completed_at else None,
    }

def _scan_to_dict(s: ScanResult, include_findings=False):
    d = {
        "id": s.id, "host_id": s.host_id, "scan_type": s.scan_type,
        "status": s.status, "score": s.score, "total_checks": s.total_checks,
        "passed": s.passed, "failed": s.failed, "warnings": s.warnings,
        "critical_count": s.critical_count, "high_count": s.high_count,
        "medium_count": s.medium_count, "low_count": s.low_count,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "error_message": s.error_message,
    }
    if include_findings:
        d["findings"] = s.findings or []
    return d
