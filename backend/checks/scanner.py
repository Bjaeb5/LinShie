import subprocess
import os
import re
import socket
from typing import List, Dict, Any
from datetime import datetime

def run_cmd(cmd: str, shell=True) -> str:
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception:
        return ""

def check(check_id, name, status, severity, description, current, expected, recommendation, cis="", nist=""):
    return {
        "check_id": check_id,
        "name": name,
        "status": status,
        "severity": severity,
        "description": description,
        "current_value": str(current),
        "expected_value": str(expected),
        "recommendation": recommendation,
        "cis_control": cis,
        "nist_control": nist,
        "category": check_id.split("_")[0]
    }

# ─── SSH CHECKS ────────────────────────────────────────────────
def check_ssh_root_login():
    val = run_cmd("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes'")
    status = "pass" if "no" in val.lower() else "fail"
    return check("ssh_root_login", "SSH: Запрет входа root", status, "critical",
        "Прямой вход root по SSH открывает полный доступ злоумышленнику при компрометации пароля.",
        val or "PermitRootLogin yes", "PermitRootLogin no",
        "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.8", "NIST AC-17")

def check_ssh_password_auth():
    val = run_cmd("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'not set'")
    status = "pass" if "no" in val.lower() else "warning"
    return check("ssh_password_auth", "SSH: Аутентификация по паролю", status, "high",
        "Аутентификация по паролю уязвима к брутфорс-атакам. Рекомендуется использовать SSH-ключи.",
        val or "PasswordAuthentication yes", "PasswordAuthentication no",
        "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.11", "NIST IA-5")

def check_ssh_protocol():
    val = run_cmd("grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'Protocol 2 (default)'")
    status = "pass" if "1" not in val else "fail"
    return check("ssh_protocol", "SSH: Версия протокола", status, "critical",
        "SSH Protocol 1 содержит известные уязвимости. Необходимо использовать только Protocol 2.",
        val, "Protocol 2",
        "sudo sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.1", "NIST SC-8")

def check_ssh_max_auth_tries():
    val = run_cmd("grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || echo 'MaxAuthTries 6'")
    num = re.search(r'\d+', val)
    tries = int(num.group()) if num else 6
    status = "pass" if tries <= 4 else "warning"
    return check("ssh_max_auth", "SSH: Максимум попыток входа", status, "medium",
        "Большое количество попыток аутентификации упрощает брутфорс-атаки.",
        val, "MaxAuthTries 4",
        "sudo sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.6", "NIST AC-7")

def check_ssh_empty_passwords():
    val = run_cmd("grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitEmptyPasswords no'")
    status = "pass" if "no" in val.lower() else "fail"
    return check("ssh_empty_pass", "SSH: Запрет пустых паролей", status, "critical",
        "Пустые пароли предоставляют немедленный доступ без аутентификации.",
        val, "PermitEmptyPasswords no",
        "sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.9", "NIST IA-5")

# ─── PASSWORD POLICY ───────────────────────────────────────────
def check_password_min_length():
    val = run_cmd("grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null || echo 'PASS_MIN_LEN 5'")
    num = re.search(r'\d+', val)
    length = int(num.group()) if num else 5
    status = "pass" if length >= 12 else "fail"
    return check("passwd_min_len", "Пароль: Минимальная длина", status, "high",
        "Короткие пароли легко подбираются. Минимальная длина должна быть не менее 12 символов.",
        val, "PASS_MIN_LEN 12",
        "sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs",
        "CIS Ubuntu 22.04 §5.4.1", "NIST IA-5")

def check_password_max_age():
    val = run_cmd("grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null || echo 'PASS_MAX_DAYS 99999'")
    num = re.search(r'\d+', val)
    days = int(num.group()) if num else 99999
    status = "pass" if days <= 90 else "warning"
    return check("passwd_max_age", "Пароль: Срок действия", status, "medium",
        "Бессрочные пароли увеличивают риск при компрометации учётных данных.",
        val, "PASS_MAX_DAYS 90",
        "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs",
        "CIS Ubuntu 22.04 §5.4.1.1", "NIST IA-5")

def check_password_complexity():
    val = run_cmd("grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password 2>/dev/null || echo 'not configured'")
    status = "pass" if "pam_pwquality" in val or "pam_cracklib" in val else "fail"
    return check("passwd_complexity", "Пароль: Требования сложности", status, "high",
        "Без требований сложности пользователи устанавливают слабые пароли.",
        val or "not configured", "pam_pwquality с minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1",
        "sudo apt-get install -y libpam-pwquality && sudo sed -i '/pam_unix.so/i password requisite pam_pwquality.so minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password",
        "CIS Ubuntu 22.04 §5.4.1", "NIST IA-5")

def check_empty_passwords():
    try:
        users_with_empty = run_cmd("sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null || echo ''")
        status = "pass" if not users_with_empty.strip() else "fail"
        return check("passwd_empty", "Пользователи с пустым паролем", status, "critical",
            "Учётные записи без пароля предоставляют немедленный доступ.",
            users_with_empty or "none", "Нет пользователей с пустым паролем",
            "sudo passwd <username>  # Установите пароль для каждого пользователя",
            "CIS Ubuntu 22.04 §6.2.1", "NIST IA-5")
    except:
        return check("passwd_empty", "Пользователи с пустым паролем", "warning", "medium",
            "Не удалось проверить — требуются права root.", "unknown", "none",
            "Запустите: sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow")

# ─── NETWORK CHECKS ────────────────────────────────────────────
def check_firewall_status():
    ufw = run_cmd("ufw status 2>/dev/null || echo 'inactive'")
    iptables = run_cmd("iptables -L -n 2>/dev/null | grep -c ACCEPT || echo '0'")
    status = "pass" if "active" in ufw.lower() else "fail"
    return check("net_firewall", "Фаервол: Статус UFW", status, "critical",
        "Отсутствие фаервола оставляет все порты открытыми для атак.",
        ufw.split('\n')[0], "Status: active",
        "sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw allow 22/tcp && sudo ufw --force enable",
        "CIS Ubuntu 22.04 §3.5.1", "NIST SC-7")

def check_ip_forwarding():
    val = run_cmd("sysctl net.ipv4.ip_forward 2>/dev/null || echo 'net.ipv4.ip_forward = 1'")
    status = "pass" if "= 0" in val else "warning"
    return check("net_ip_forward", "Сеть: IP Forwarding", status, "medium",
        "IP Forwarding включён — хост может работать как маршрутизатор, что нежелательно для серверов.",
        val, "net.ipv4.ip_forward = 0",
        "echo 'net.ipv4.ip_forward = 0' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
        "CIS Ubuntu 22.04 §3.1.1", "NIST CM-7")

def check_tcp_syncookies():
    val = run_cmd("sysctl net.ipv4.tcp_syncookies 2>/dev/null || echo 'net.ipv4.tcp_syncookies = 0'")
    status = "pass" if "= 1" in val else "fail"
    return check("net_syncookies", "Сеть: TCP SYN Cookies", status, "high",
        "TCP SYN cookies защищают от SYN flood DDoS атак.",
        val, "net.ipv4.tcp_syncookies = 1",
        "echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
        "CIS Ubuntu 22.04 §3.3.8", "NIST SC-5")

def check_open_ports():
    ports = run_cmd("ss -tlnp 2>/dev/null | tail -n +2 || netstat -tlnp 2>/dev/null | tail -n +3")
    risky = []
    risky_ports = {"21": "FTP", "23": "Telnet", "25": "SMTP", "110": "POP3", "143": "IMAP",
                   "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB"}
    for port, name in risky_ports.items():
        if f":{port} " in ports or f":{port}\n" in ports:
            risky.append(f"{port}/{name}")
    status = "pass" if not risky else "warning"
    return check("net_open_ports", "Сеть: Открытые опасные порты", status, "high",
        "Открытые порты СУБД и сервисов без фаервола — вектор атаки.",
        f"Найдены: {', '.join(risky)}" if risky else "Опасных портов не обнаружено",
        "Только необходимые порты с ограниченным доступом",
        "sudo ufw deny <port>/tcp  # Закройте каждый лишний порт",
        "CIS Ubuntu 22.04 §2.2", "NIST CM-7")

# ─── SYSTEM CHECKS ─────────────────────────────────────────────
def check_os_updates():
    updates = run_cmd("apt list --upgradable 2>/dev/null | grep -c upgradable || echo '0'")
    security = run_cmd("apt list --upgradable 2>/dev/null | grep -c security || echo '0'")
    try:
        u = int(updates.strip())
        s = int(security.strip())
    except:
        u, s = 0, 0
    status = "pass" if u == 0 else ("fail" if s > 0 else "warning")
    return check("sys_updates", "Система: Обновления безопасности", status, "high" if s > 0 else "medium",
        f"Устаревшие пакеты содержат известные уязвимости CVE.",
        f"{u} обновлений доступно, из них {s} security", "0 обновлений",
        "sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y",
        "CIS Ubuntu 22.04 §1.9", "NIST SI-2")

def check_suid_files():
    suid = run_cmd("find /usr /bin /sbin -perm -4000 -type f 2>/dev/null")
    known_suid = {"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/newgrp",
                  "/usr/bin/gpasswd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/mount",
                  "/usr/bin/umount", "/usr/bin/fusermount3", "/usr/bin/pkexec"}
    files = [f for f in suid.split('\n') if f.strip() and f.strip() not in known_suid]
    status = "pass" if not files else "warning"
    return check("sys_suid", "Файлы с SUID битом", status, "medium",
        "Нестандартные SUID файлы могут использоваться для повышения привилегий.",
        '\n'.join(files[:5]) if files else "Только стандартные SUID файлы",
        "Только системные SUID файлы",
        "sudo chmod u-s <file>  # Удалите SUID бит с подозрительных файлов",
        "CIS Ubuntu 22.04 §6.1.13", "NIST CM-6")

def check_auditd():
    status_val = run_cmd("systemctl is-active auditd 2>/dev/null || echo 'inactive'")
    status = "pass" if "active" in status_val else "fail"
    return check("sys_auditd", "Аудит: Служба auditd", status, "high",
        "auditd обеспечивает журналирование системных событий безопасности. Без него невозможно расследование инцидентов.",
        status_val, "active",
        "sudo apt-get install -y auditd audispd-plugins && sudo systemctl enable --now auditd",
        "CIS Ubuntu 22.04 §4.1.1", "NIST AU-2")

def check_fail2ban():
    status_val = run_cmd("systemctl is-active fail2ban 2>/dev/null || echo 'inactive'")
    status = "pass" if "active" in status_val else "warning"
    return check("sys_fail2ban", "Защита: Служба fail2ban", status, "medium",
        "fail2ban автоматически блокирует IP-адреса после неудачных попыток входа.",
        status_val, "active",
        "sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban",
        "CIS Ubuntu 22.04 §5.3", "NIST AC-7")

def check_unattended_upgrades():
    val = run_cmd("systemctl is-active unattended-upgrades 2>/dev/null || echo 'inactive'")
    status = "pass" if "active" in val else "warning"
    return check("sys_auto_updates", "Автообновления безопасности", status, "medium",
        "Автоматические обновления безопасности снижают окно уязвимости.",
        val, "active",
        "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
        "CIS Ubuntu 22.04 §1.9", "NIST SI-2")

def check_root_cron():
    cron = run_cmd("crontab -l -u root 2>/dev/null || echo 'no crontab'")
    world_writable = run_cmd("ls -la /etc/cron* 2>/dev/null | grep -E '^-.*w.*w' || echo ''")
    status = "warning" if world_writable.strip() else "pass"
    return check("sys_cron", "Cron: Права на файлы расписания", status, "medium",
        "Файлы cron с широкими правами могут быть изменены для выполнения вредоносного кода.",
        world_writable or "Права корректны", "Только root имеет доступ к cron",
        "sudo chmod 600 /etc/crontab && sudo chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.weekly",
        "CIS Ubuntu 22.04 §5.1.2", "NIST CM-6")

def check_kernel_version():
    kernel = run_cmd("uname -r")
    return check("sys_kernel", "Система: Версия ядра", "pass", "low",
        "Информация о версии ядра Linux.",
        kernel, "Актуальная версия",
        "sudo apt-get install -y linux-image-generic && sudo reboot  # Обновите ядро если версия устарела",
        "CIS Ubuntu 22.04 §1.9", "NIST SI-2")

def check_apparmor():
    status_val = run_cmd("systemctl is-active apparmor 2>/dev/null || echo 'inactive'")
    status = "pass" if "active" in status_val else "warning"
    return check("sys_apparmor", "Мандатный контроль: AppArmor", status, "high",
        "AppArmor ограничивает возможности приложений через мандатный контроль доступа.",
        status_val, "active",
        "sudo apt-get install -y apparmor apparmor-utils && sudo systemctl enable --now apparmor && sudo aa-enforce /etc/apparmor.d/*",
        "CIS Ubuntu 22.04 §1.6.1", "NIST AC-3")

def check_tmp_noexec():
    mounts = run_cmd("mount | grep ' /tmp '")
    status = "pass" if "noexec" in mounts else "warning"
    return check("sys_tmp_noexec", "Файловая система: /tmp noexec", status, "medium",
        "Монтирование /tmp с флагом noexec предотвращает запуск вредоносных скриптов из временной директории.",
        mounts or "/tmp без noexec", "/tmp с флагами noexec,nosuid,nodev",
        "echo 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0' | sudo tee -a /etc/fstab && sudo mount -o remount /tmp",
        "CIS Ubuntu 22.04 §1.1.7", "NIST CM-6")

# ─── CRYPTO CHECKS ─────────────────────────────────────────────
def check_ssh_ciphers():
    val = run_cmd("grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'default (may include weak)'")
    weak = any(c in val.lower() for c in ["arcfour", "des", "3des", "blowfish", "cast"])
    status = "fail" if weak else "pass"
    return check("crypto_ciphers", "SSH: Алгоритмы шифрования", status, "medium",
        "Слабые алгоритмы шифрования SSH уязвимы к атакам на шифрование.",
        val, "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.13", "NIST SC-8")

def check_ssh_macs():
    val = run_cmd("grep -i '^MACs' /etc/ssh/sshd_config 2>/dev/null || echo 'default'")
    weak = any(m in val.lower() for m in ["md5", "sha1"])
    status = "fail" if weak else "pass"
    return check("crypto_macs", "SSH: Алгоритмы MAC", status, "medium",
        "Слабые MAC алгоритмы уязвимы к атакам на целостность данных.",
        val, "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
        "echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "CIS Ubuntu 22.04 §5.2.14", "NIST SC-8")

# ─── MAIN SCANNER ──────────────────────────────────────────────
def run_all_checks() -> List[Dict[str, Any]]:
    checks = [
        # SSH
        check_ssh_root_login(),
        check_ssh_password_auth(),
        check_ssh_protocol(),
        check_ssh_max_auth_tries(),
        check_ssh_empty_passwords(),
        check_ssh_ciphers(),
        check_ssh_macs(),
        # Passwords
        check_password_min_length(),
        check_password_max_age(),
        check_password_complexity(),
        check_empty_passwords(),
        # Network
        check_firewall_status(),
        check_ip_forwarding(),
        check_tcp_syncookies(),
        check_open_ports(),
        # System
        check_os_updates(),
        check_suid_files(),
        check_auditd(),
        check_fail2ban(),
        check_unattended_upgrades(),
        check_root_cron(),
        check_kernel_version(),
        check_apparmor(),
        check_tmp_noexec(),
    ]
    return checks

def calculate_score(findings: List[Dict]) -> int:
    if not findings:
        return 100
    weights = {"critical": 20, "high": 10, "medium": 5, "low": 2}
    total_penalty = 0
    for f in findings:
        if f["status"] == "fail":
            total_penalty += weights.get(f["severity"], 2)
        elif f["status"] == "warning":
            total_penalty += weights.get(f["severity"], 2) // 2
    score = max(0, 100 - total_penalty)
    return score
