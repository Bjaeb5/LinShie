"""
Multi-OS Security Scan Router
POST /api/os-scan/start   — Запустить сканирование хоста
GET  /api/os-scan/{id}    — Получить результаты
GET  /api/os-scan/        — Список сканирований
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from database import get_db
from models.scan import ScanResult
from models.user import User
from routers.auth import get_current_user
import json, asyncio, time, uuid
from datetime import datetime

router = APIRouter(prefix="/api/os-scan", tags=["os-scan"])

# In-memory storage for running scans (in production use Redis)
_running_scans: dict = {}


class OSScanRequest(BaseModel):
    os_type: str          # linux | windows | macos
    scan_type: str        # local | remote
    host: Optional[str] = None
    port: Optional[int] = 22
    username: Optional[str] = None
    password: Optional[str] = None
    ssh_key: Optional[str] = None


class OSScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    os_type: str
    host: str
    started_at: str
    findings: Optional[List] = None
    score: Optional[int] = None
    stats: Optional[dict] = None
    error: Optional[str] = None


def _make_run_cmd(ssh_client=None):
    """Returns a run_cmd function - either local subprocess or SSH"""
    if ssh_client is None:
        import subprocess
        def run_local(cmd: str) -> str:
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                return r.stdout.strip()
            except Exception:
                return ""
        return run_local
    else:
        def run_remote(cmd: str) -> str:
            try:
                stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=15)
                return stdout.read().decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
        return run_remote


def _do_scan(scan_id: str, request: OSScanRequest):
    """Background scanning task"""
    _running_scans[scan_id]["status"] = "running"
    _running_scans[scan_id]["progress"] = 5

    ssh_client = None
    try:
        # Connect SSH for remote scan
        if request.scan_type == "remote" and request.host:
            import paramiko
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {
                "hostname": request.host,
                "port": request.port or 22,
                "username": request.username,
                "timeout": 10,
            }
            if request.ssh_key:
                import io
                key = paramiko.RSAKey.from_private_key(io.StringIO(request.ssh_key))
                connect_kwargs["pkey"] = key
            elif request.password:
                connect_kwargs["password"] = request.password

            ssh_client.connect(**connect_kwargs)
            _running_scans[scan_id]["progress"] = 15

        run_cmd = _make_run_cmd(ssh_client)
        _running_scans[scan_id]["progress"] = 20

        # Select scanner by OS
        from checks.os_scanner import LinuxScanner, MacOSScanner, WindowsScanner, calculate_score

        if request.os_type == "linux":
            scanner = LinuxScanner(run_cmd)
        elif request.os_type == "macos":
            scanner = MacOSScanner(run_cmd)
        elif request.os_type == "windows":
            scanner = WindowsScanner(run_cmd)
        else:
            raise ValueError(f"Unknown OS type: {request.os_type}")

        _running_scans[scan_id]["progress"] = 30

        findings = scanner.scan()
        _running_scans[scan_id]["progress"] = 85

        score = calculate_score(findings)

        # Stats
        stats = {
            "total": len(findings),
            "passed": sum(1 for f in findings if f["status"] == "pass"),
            "failed": sum(1 for f in findings if f["status"] == "fail"),
            "warnings": sum(1 for f in findings if f["status"] == "warning"),
            "info": sum(1 for f in findings if f["status"] == "info"),
            "critical": sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["status"] == "fail" and f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["status"] in ["fail","warning"] and f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        }

        # Group by category
        categories = {}
        for f in findings:
            cat = f.get("category", "general")
            if cat not in categories:
                categories[cat] = {"passed": 0, "failed": 0, "warnings": 0}
            if f["status"] == "pass":
                categories[cat]["passed"] += 1
            elif f["status"] == "fail":
                categories[cat]["failed"] += 1
            elif f["status"] == "warning":
                categories[cat]["warnings"] += 1

        stats["categories"] = categories

        _running_scans[scan_id].update({
            "status": "completed",
            "progress": 100,
            "findings": findings,
            "score": score,
            "stats": stats,
            "completed_at": datetime.utcnow().isoformat(),
        })

    except Exception as e:
        _running_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "error": str(e),
        })
    finally:
        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass


@router.post("/start")
async def start_os_scan(
    request: OSScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    scan_id = str(uuid.uuid4())[:8]
    _running_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "starting",
        "progress": 0,
        "os_type": request.os_type,
        "host": request.host or "localhost",
        "started_at": datetime.utcnow().isoformat(),
        "findings": None,
        "score": None,
        "stats": None,
        "error": None,
    }
    background_tasks.add_task(_do_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "starting"}


@router.get("/{scan_id}")
async def get_os_scan(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = _running_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/")
async def list_os_scans(current_user: User = Depends(get_current_user)):
    scans = list(_running_scans.values())
    scans.sort(key=lambda x: x.get("started_at",""), reverse=True)
    # Return without findings to keep response small
    return [
        {k: v for k, v in s.items() if k != "findings"}
        for s in scans[:20]
    ]


# ── Real simulation endpoint ──────────────────────────────────────────────────

SIMULATION_CHECKS = {
    "sim_bruteforce": [
        {"label": "MaxAuthTries ≤ 4",           "cmd": "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'",   "fix": "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl restart sshd"},
        {"label": "PasswordAuthentication no",  "cmd": "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", "fix": "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd"},
        {"label": "Fail2Ban активен",            "cmd": "systemctl is-active fail2ban 2>/dev/null || echo inactive",                      "fix": "apt-get install -y fail2ban && systemctl enable --now fail2ban"},
        {"label": "Нет пустых паролей",          "cmd": "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null | wc -l",              "fix": "passwd -l $(awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null | head -1)"},
        {"label": "PermitRootLogin no",          "cmd": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", "fix": "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"},
    ],
    "sim_ddos": [
        {"label": "SYN cookies включены",         "cmd": "sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo 0",   "fix": "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf"},
        {"label": "Фаервол активен (UFW)",        "cmd": "ufw status 2>/dev/null | head -1 || echo inactive",          "fix": "ufw --force enable && ufw default deny incoming && ufw allow ssh"},
        {"label": "IP Forwarding выключен",       "cmd": "sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 1",        "fix": "sysctl -w net.ipv4.ip_forward=0"},
        {"label": "ICMP redirects отключены",     "cmd": "sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 1", "fix": "sysctl -w net.ipv4.conf.all.accept_redirects=0"},
        {"label": "Нет опасных открытых портов",  "cmd": "ss -tlnp 2>/dev/null | grep -cE ':(6379|27017|9200|11211)\\b' || echo 0", "fix": "ufw deny 6379 && ufw deny 27017 && ufw deny 9200"},
    ],
    "sim_privesc": [
        {"label": "SUID файлов < 15",             "cmd": "find / -perm -4000 -type f 2>/dev/null | grep -v '/proc\\|/snap' | wc -l", "fix": "find / -perm -4000 -type f 2>/dev/null | grep -v '/proc|/snap'"},
        {"label": "AppArmor активен",             "cmd": "systemctl is-active apparmor 2>/dev/null || echo inactive", "fix": "apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor"},
        {"label": "Нет world-writable системных", "cmd": "find /etc /bin /usr/bin -perm -o+w -type f 2>/dev/null | wc -l", "fix": "find /etc /bin /usr/bin -perm -o+w -type f 2>/dev/null | xargs chmod o-w"},
        {"label": "Только root с UID 0",          "cmd": "awk -F: '($3==0){print $1}' /etc/passwd | grep -vc '^root$' || echo 0", "fix": "awk -F: '($3==0)' /etc/passwd"},
        {"label": "Мало обновлений",              "cmd": "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || echo 0", "fix": "apt-get update && apt-get upgrade -y"},
    ],
    "sim_persistence": [
        {"label": "Auditd активен",               "cmd": "systemctl is-active auditd 2>/dev/null || echo inactive",   "fix": "apt-get install -y auditd && systemctl enable --now auditd"},
        {"label": "Нет лишних cron задач",        "cmd": "crontab -l 2>/dev/null | grep -cvE '^#|^$' || echo 0",     "fix": "crontab -l"},
        {"label": "Права /etc/crontab = 600",     "cmd": "stat -c %a /etc/crontab 2>/dev/null || echo 644",           "fix": "chmod 600 /etc/crontab && chown root:root /etc/crontab"},
        {"label": "Нет посторонних authorized_keys root", "cmd": "cat /root/.ssh/authorized_keys 2>/dev/null | grep -cv '^#\\|^$' || echo 0", "fix": "cat /root/.ssh/authorized_keys"},
        {"label": "rsyslog активен",              "cmd": "systemctl is-active rsyslog 2>/dev/null || echo inactive",  "fix": "apt-get install -y rsyslog && systemctl enable --now rsyslog"},
    ],
    "sim_network": [
        {"label": "SSH Protocol 2",               "cmd": "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", "fix": "echo 'Protocol 2' >> /etc/ssh/sshd_config"},
        {"label": "Нет слабых SSH шифров",        "cmd": "grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo ok", "fix": "echo 'Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com' >> /etc/ssh/sshd_config"},
        {"label": "Telnet не запущен",            "cmd": "systemctl is-active telnet 2>/dev/null; systemctl is-active telnetd 2>/dev/null | tail -1", "fix": "systemctl disable --now telnet 2>/dev/null; apt-get remove -y telnet"},
        {"label": "SSH таймаут настроен",         "cmd": "grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'", "fix": "echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config"},
        {"label": "ASLR включён (=2)",            "cmd": "sysctl -n kernel.randomize_va_space 2>/dev/null || echo 0", "fix": "sysctl -w kernel.randomize_va_space=2"},
    ],
    "sim_crypto": [
        {"label": "Нет слабых MAC алгоритмов SSH","cmd": "grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo ok", "fix": "echo 'MACs hmac-sha2-512,hmac-sha2-256' >> /etc/ssh/sshd_config"},
        {"label": "Swap отсутствует/зашифрован",  "cmd": "cat /proc/swaps 2>/dev/null | tail -n +2 | wc -l || echo 0", "fix": "swapoff -a # или настройте шифрование swap"},
        {"label": "Права /etc/shadow корректны",  "cmd": "stat -c %a /etc/shadow 2>/dev/null || echo 777",             "fix": "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"},
        {"label": "Права /etc/passwd корректны",  "cmd": "stat -c %a /etc/passwd 2>/dev/null || echo 777",             "fix": "chmod 644 /etc/passwd"},
        {"label": "PASS_MIN_LEN ≥ 12",            "cmd": "grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}'", "fix": "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs"},
    ],
    "sim_webshell": [
        {"label": "/tmp с noexec",                "cmd": "mount | grep '/tmp' | grep -c noexec || echo 0",             "fix": "mount -o remount,noexec /tmp"},
        {"label": "AppArmor для веб-сервера",     "cmd": "aa-status 2>/dev/null | grep -cE 'nginx|apache' || echo 0", "fix": "aa-enforce /etc/apparmor.d/usr.sbin.nginx 2>/dev/null"},
        {"label": "Нет world-writable в /var/www","cmd": "find /var/www 2>/dev/null -perm -o+w -type f | wc -l || echo 0", "fix": "find /var/www -perm -o+w -type f | xargs chmod o-w"},
        {"label": "Auditd мониторит /var/www",    "cmd": "auditctl -l 2>/dev/null | grep -c 'var/www' || echo 0",     "fix": "auditctl -w /var/www -p wa -k webshell"},
        {"label": "Sticky bit на /tmp",           "cmd": "stat -c %a /tmp 2>/dev/null | head -c1",                    "fix": "chmod +t /tmp"},
    ],
    "sim_ransomware": [
        {"label": "Auditd мониторит изменения",   "cmd": "auditctl -l 2>/dev/null | grep -c ' wa ' || echo 0",        "fix": "auditctl -w /home -p wa -k ransomware"},
        {"label": "AppArmor активен",             "cmd": "systemctl is-active apparmor 2>/dev/null || echo inactive", "fix": "systemctl enable --now apparmor"},
        {"label": "ClamAV установлен",            "cmd": "which clamscan 2>/dev/null | wc -l",                        "fix": "apt-get install -y clamav && freshclam"},
        {"label": "Нет подозрительных процессов", "cmd": "ps aux 2>/dev/null | grep -cE 'openssl enc|gpg --batch' | grep -v grep || echo 0", "fix": "ps aux | grep -E 'crypt|encode'"},
        {"label": "Права домашних директорий",    "cmd": "find /home -maxdepth 1 -type d -perm /o+rwx 2>/dev/null | wc -l || echo 0", "fix": "chmod 700 /home/*"},
    ],
}

def _evaluate(check_id: str, label: str, value: str) -> bool:
    """Evaluate whether a check value is passing."""
    v = value.strip().lower()
    if "maxtries" in label.lower() or "maxauthtries" in label.lower():
        try: return 0 < int(v) <= 4
        except: return False
    if "passwordauthentication" in label.lower():
        return v == "no"
    if "fail2ban" in label.lower() or "auditd" in label.lower() or "apparmor" in label.lower() or "rsyslog" in label.lower():
        return v == "active"
    if "пустых паролей" in label.lower() or "empty" in label.lower():
        try: return int(v) == 0
        except: return False
    if "permitrootlogin" in label.lower():
        return v == "no"
    if "syn cookie" in label.lower():
        return v == "1"
    if "фаервол" in label.lower() or "firewall" in label.lower():
        return "active" in v
    if "ip forward" in label.lower():
        return v == "0"
    if "icmp redirect" in label.lower():
        return v == "0"
    if "опасных открытых" in label.lower() or "dangerous" in label.lower():
        try: return int(v) == 0
        except: return False
    if "suid" in label.lower():
        try: return int(v) < 15
        except: return False
    if "world-writable" in label.lower():
        try: return int(v) == 0
        except: return False
    if "только root" in label.lower() or "uid 0" in label.lower():
        try: return int(v) == 0
        except: return False
    if "обновлений" in label.lower() or "updates" in label.lower():
        try: return int(v) < 5
        except: return False
    if "cron" in label.lower() and "задач" in label.lower():
        try: return int(v) == 0
        except: return False
    if "authorized_keys" in label.lower():
        try: return int(v) == 0
        except: return False
    if "crontab" in label.lower() and "права" in label.lower():
        return v in ["600", "400"]
    if "protocol" in label.lower():
        return v == "2" or v == ""
    if "шифров" in label.lower() or "cipher" in label.lower() or "mac" in label.lower():
        return "arcfour" not in v and "hmac-md5" not in v and "3des" not in v
    if "telnet" in label.lower():
        return "inactive" in v or v == "" or "not-found" in v
    if "timeout" in label.lower() or "таймаут" in label.lower():
        try: n = int(v); return 0 < n <= 600
        except: return False
    if "aslr" in label.lower():
        return v == "2"
    if "swap" in label.lower():
        try: return int(v) == 0
        except: return False
    if "shadow" in label.lower():
        return v in ["640", "600", "400", "000"]
    if "passwd" in label.lower() and "права" in label.lower():
        return v in ["644", "444"]
    if "pass_min_len" in label.lower() or "password" in label.lower() and "length" in label.lower():
        try: return int(v) >= 12
        except: return False
    if "noexec" in label.lower():
        try: return int(v) > 0
        except: return False
    if "sticky" in label.lower():
        return v.startswith("1")
    if "clamav" in label.lower():
        try: return int(v) > 0
        except: return False
    if "подозрительных процессов" in label.lower():
        try: return int(v) == 0
        except: return False
    if "домашних директорий" in label.lower():
        try: return int(v) == 0
        except: return False
    # Default: non-empty and non-zero is ok
    return bool(v) and v not in ["0", "inactive", "not found", ""]


@router.post("/simulate")
async def run_simulation(
    payload: dict,
    current_user: User = Depends(get_current_user),
):
    import subprocess

    sim_id = payload.get("sim_id", "")
    checks_def = SIMULATION_CHECKS.get(sim_id)
    if not checks_def:
        raise HTTPException(status_code=404, detail=f"Unknown simulation: {sim_id}")

    results = []
    for c in checks_def:
        try:
            proc = subprocess.run(
                c["cmd"], shell=True, capture_output=True, text=True, timeout=10
            )
            actual = proc.stdout.strip() or proc.stderr.strip() or "no output"
        except Exception as e:
            actual = f"error: {e}"

        passed = _evaluate(sim_id, c["label"], actual)
        results.append({
            "label": c["label"],
            "passed": passed,
            "actual": actual[:200],
            "fix": c.get("fix", ""),
        })

    passed_count = sum(1 for r in results if r["passed"])
    score = round((passed_count / len(results)) * 100) if results else 0
    status = "protected" if score == 100 else "partial" if score >= 60 else "vulnerable"

    return {"status": status, "score": score, "checks": results}
