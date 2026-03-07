from celery import shared_task
from celery_app import celery_app
from database import SessionLocal
from models.scan import ScanResult
from models.host import Host
from checks.scanner import run_all_checks, calculate_score
from services.remote_scanner import scan_remote_host
from datetime import datetime

@celery_app.task(bind=True)
def run_local_scan(self, scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if not scan:
            return
        findings = run_all_checks()
        score = calculate_score(findings)
        scan.findings = findings
        scan.score = score
        scan.total_checks = len(findings)
        scan.passed = sum(1 for f in findings if f["status"] == "pass")
        scan.failed = sum(1 for f in findings if f["status"] == "fail")
        scan.warnings = sum(1 for f in findings if f["status"] == "warning")
        scan.critical_count = sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "critical")
        scan.high_count = sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "high")
        scan.medium_count = sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "medium")
        scan.low_count = sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "low")
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            db.commit()
    finally:
        db.close()

@celery_app.task(bind=True)
def run_remote_scan(self, scan_id: int, host_id: int):
    db = SessionLocal()
    try:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        host = db.query(Host).filter(Host.id == host_id).first()
        if not scan or not host:
            return
        
        result = scan_remote_host(
            ip=host.ip_address,
            port=host.port,
            username=host.ssh_username,
            password=host.ssh_password,
            ssh_key=host.ssh_key
        )
        
        if result["success"]:
            findings = result["checks"]
            score = calculate_score(findings)
            scan.findings = findings
            scan.score = score
            scan.total_checks = len(findings)
            scan.passed = sum(1 for f in findings if f["status"] == "pass")
            scan.failed = sum(1 for f in findings if f["status"] == "fail")
            scan.warnings = sum(1 for f in findings if f["status"] == "warning")
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            host.last_scan = datetime.utcnow()
            host.last_score = score
        else:
            scan.status = "failed"
            scan.error_message = result["error"]
        db.commit()
    except Exception as e:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.error_message = str(e)
            db.commit()
    finally:
        db.close()
