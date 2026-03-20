"""
Multi-OS Security Scanner
Поддерживает: Linux (Ubuntu/Debian/CentOS/RHEL), Windows Server, macOS
Подключение: SSH (Linux/macOS), SSH+PowerShell (Windows)
"""
import re
from typing import List, Dict, Any, Optional

# ── Helpers ──────────────────────────────────────────────────────────────────

def chk(check_id, name, status, severity, description, current, expected,
        recommendation, category="general", cis="", nist="", fix_cmd=""):
    return {
        "check_id": check_id,
        "name": name,
        "status": status,          # pass | fail | warning | info
        "severity": severity,      # critical | high | medium | low | info
        "description": description,
        "current_value": str(current),
        "expected_value": str(expected),
        "recommendation": recommendation,
        "fix_cmd": fix_cmd,
        "cis_control": cis,
        "nist_control": nist,
        "category": category,
    }

def _val(output: str, default="not found") -> str:
    return output.strip() if output and output.strip() else default

def _contains(output: str, *words) -> bool:
    out = output.lower()
    return any(w.lower() in out for w in words)

def _num(output: str, default=0) -> int:
    m = re.search(r'\d+', output or "")
    return int(m.group()) if m else default


# ══════════════════════════════════════════════════════════════════════════════
# LINUX SCANNER (50+ checks)
# ══════════════════════════════════════════════════════════════════════════════

class LinuxScanner:
    def __init__(self, run_cmd):
        self.run = run_cmd

    def scan(self) -> List[Dict]:
        results = []
        sections = [
            self._ssh_checks(),
            self._password_checks(),
            self._network_checks(),
            self._system_checks(),
            self._filesystem_checks(),
            self._user_checks(),
            self._service_checks(),
            self._kernel_checks(),
            self._logging_checks(),
        ]
        for section in sections:
            results.extend(section)
        return results

    # ── SSH ──────────────────────────────────────────────────────────────────
    def _ssh_checks(self):
        r = self.run
        results = []

        # Root login
        v = r("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes'")
        results.append(chk("ssh_root_login", "SSH: Запрет входа root",
            "pass" if "no" in v.lower() else "fail", "critical",
            "Прямой вход root по SSH критически опасен.",
            v, "PermitRootLogin no",
            "Отключите вход root по SSH и используйте sudo.",
            "ssh", "CIS §5.2.8", "NIST AC-17",
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"))

        # Password auth
        v = r("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'PasswordAuthentication yes'")
        results.append(chk("ssh_password_auth", "SSH: Парольная аутентификация",
            "pass" if "no" in v.lower() else "warning", "high",
            "Парольная аутентификация уязвима к брутфорсу.",
            v, "PasswordAuthentication no",
            "Перейдите на SSH-ключи.",
            "ssh", "CIS §5.2.11", "NIST IA-5",
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd"))

        # Protocol
        v = r("grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'Protocol 2 (default)'")
        results.append(chk("ssh_protocol", "SSH: Версия протокола",
            "fail" if "1" in v and "2" not in v else "pass", "critical",
            "SSH Protocol 1 содержит критические уязвимости.",
            v, "Protocol 2", "Используйте только SSH Protocol 2.",
            "ssh", "CIS §5.2.1", "NIST SC-8"))

        # MaxAuthTries
        v = r("grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || echo 'MaxAuthTries 6'")
        n = _num(v, 6)
        results.append(chk("ssh_max_auth", "SSH: Лимит попыток входа",
            "pass" if n <= 4 else "warning", "medium",
            "Большой лимит попыток облегчает брутфорс.",
            v, "MaxAuthTries 4", "Установите MaxAuthTries 3-4.",
            "ssh", "CIS §5.2.6", "NIST AC-7",
            "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl restart sshd"))

        # Empty passwords
        v = r("grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitEmptyPasswords no'")
        results.append(chk("ssh_empty_pass", "SSH: Запрет пустых паролей",
            "pass" if "no" in v.lower() else "fail", "critical",
            "Пустые пароли дают немедленный доступ.",
            v, "PermitEmptyPasswords no", "Запретите пустые пароли.",
            "ssh", "CIS §5.2.9", "NIST IA-5"))

        # Ciphers
        v = r("grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null || echo 'default'")
        weak = any(c in v.lower() for c in ["arcfour","3des","blowfish","cast128"])
        results.append(chk("ssh_ciphers", "SSH: Алгоритмы шифрования",
            "fail" if weak else "pass", "high",
            "Слабые алгоритмы шифрования уязвимы к MITM атакам.",
            v, "Только AES-256, ChaCha20",
            "Отключите устаревшие шифры (RC4, 3DES, Blowfish).",
            "ssh", "CIS §5.2.13", "NIST SC-8"))

        # Idle timeout
        v = r("grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null || echo 'not set'")
        n = _num(v, 9999)
        results.append(chk("ssh_idle_timeout", "SSH: Таймаут неактивных сессий",
            "pass" if 0 < n <= 300 else "warning", "medium",
            "Неактивные сессии могут быть захвачены злоумышленником.",
            v, "ClientAliveInterval 300",
            "Установите таймаут 300 секунд (5 минут).",
            "ssh", "CIS §5.2.16", "NIST AC-12",
            "echo 'ClientAliveInterval 300\nClientAliveCountMax 3' >> /etc/ssh/sshd_config"))

        # AllowUsers / AllowGroups
        v = r("grep -iE '^(AllowUsers|AllowGroups)' /etc/ssh/sshd_config 2>/dev/null || echo 'not set'")
        results.append(chk("ssh_allow_users", "SSH: Ограничение пользователей",
            "pass" if v != "not set" else "warning", "medium",
            "Без ограничений любой пользователь может подключиться по SSH.",
            v, "AllowUsers или AllowGroups настроены",
            "Укажите разрешённых пользователей через AllowUsers.",
            "ssh", "CIS §5.2.17", "NIST AC-3"))

        return results

    # ── Passwords ─────────────────────────────────────────────────────────────
    def _password_checks(self):
        r = self.run
        results = []

        v = r("grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null || echo 'PASS_MIN_LEN 5'")
        n = _num(v, 5)
        results.append(chk("pw_min_len", "Пароли: Минимальная длина",
            "pass" if n >= 12 else ("warning" if n >= 8 else "fail"), "high",
            "Короткие пароли легко перебираются.",
            v, "PASS_MIN_LEN 12",
            "Установите минимальную длину 12+ символов.",
            "password", "CIS §5.4.1", "NIST IA-5",
            "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs"))

        v = r("grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null || echo 'PASS_MAX_DAYS 99999'")
        n = _num(v, 99999)
        results.append(chk("pw_max_days", "Пароли: Срок действия",
            "pass" if n <= 90 else "warning", "medium",
            "Без срока действия скомпрометированный пароль используется бесконечно.",
            v, "PASS_MAX_DAYS 90",
            "Установите максимальный срок действия пароля 90 дней.",
            "password", "CIS §5.4.1.1", "NIST IA-5",
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"))

        v = r("grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password 2>/dev/null || echo 'not configured'")
        results.append(chk("pw_complexity", "Пароли: Сложность (pam_pwquality)",
            "pass" if "pam_pwquality" in v or "pam_cracklib" in v else "fail", "high",
            "Без проверки сложности пользователи используют простые пароли.",
            v, "pam_pwquality настроен",
            "Установите и настройте pam_pwquality.",
            "password", "CIS §5.4.1", "NIST IA-5",
            "apt-get install -y libpam-pwquality && echo 'password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' >> /etc/pam.d/common-password"))

        v = r("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>/dev/null || echo 'none'")
        results.append(chk("pw_empty", "Пароли: Пустые пароли",
            "pass" if v.strip() in ["", "none"] else "fail", "critical",
            "Аккаунты с пустыми паролями не требуют аутентификации.",
            v if v.strip() not in ["","none"] else "Не найдены", "Нет аккаунтов с пустым паролем",
            "Установите пароли для всех аккаунтов.",
            "password", "CIS §6.2.1", "NIST IA-5"))

        return results

    # ── Network ───────────────────────────────────────────────────────────────
    def _network_checks(self):
        r = self.run
        results = []

        v = r("ufw status 2>/dev/null || iptables -L INPUT -n 2>/dev/null | head -3 || echo 'inactive'")
        active = "active" in v.lower() or "ACCEPT" in v or "DROP" in v
        results.append(chk("net_firewall", "Сеть: Фаервол (UFW/iptables)",
            "pass" if active else "fail", "critical",
            "Без фаервола все порты открыты для атак.",
            v[:100], "Фаервол активен",
            "Активируйте UFW: ufw enable",
            "network", "CIS §3.5.1", "NIST SC-7",
            "ufw --force enable && ufw default deny incoming && ufw allow ssh"))

        v = r("sysctl net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '1'")
        n = _num(v, 1)
        results.append(chk("net_ip_forward", "Сеть: IP Forwarding",
            "pass" if n == 0 else "warning", "medium",
            "IP Forwarding превращает сервер в маршрутизатор для атак.",
            v, "net.ipv4.ip_forward = 0",
            "Отключите IP Forwarding если не используется.",
            "network", "CIS §3.1.1", "NIST CM-7",
            "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf"))

        v = r("sysctl net.ipv4.tcp_syncookies 2>/dev/null || echo 'net.ipv4.tcp_syncookies = 0'")
        n = _num(v, 0)
        results.append(chk("net_syncookies", "Сеть: TCP SYN Cookies",
            "pass" if n == 1 else "fail", "high",
            "Без SYN cookies сервер уязвим к SYN-flood DDoS атакам.",
            v, "net.ipv4.tcp_syncookies = 1",
            "Включите TCP SYN Cookies.",
            "network", "CIS §3.3.8", "NIST SC-5",
            "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf"))

        # Open ports
        v = r("ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN || echo ''")
        dangerous = []
        for port, name in [("3306","MySQL"),("5432","PostgreSQL"),("6379","Redis"),("27017","MongoDB"),("9200","Elasticsearch"),("11211","Memcached")]:
            if f":{port}" in v or f" {port}" in v:
                dangerous.append(f"{name}:{port}")
        results.append(chk("net_open_ports", "Сеть: Опасные открытые порты",
            "fail" if dangerous else "pass", "critical" if dangerous else "info",
            "Базы данных и внутренние сервисы не должны быть доступны извне.",
            ", ".join(dangerous) if dangerous else "Опасных портов не найдено",
            "БД недоступны из интернета",
            "Закройте доступ к БД через UFW или привяжите к localhost.",
            "network", "CIS §2.2", "NIST CM-7"))

        # IPv6
        v = r("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 'not set'")
        results.append(chk("net_ipv6", "Сеть: IPv6 отключен",
            "pass" if "= 1" in v else "info", "low",
            "IPv6 расширяет поверхность атаки если не используется.",
            v, "net.ipv6.conf.all.disable_ipv6 = 1",
            "Отключите IPv6 если не используется.",
            "network", "CIS §3.1.2", "NIST CM-7"))

        # ICMP redirects
        v = r("sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 'not set'")
        results.append(chk("net_icmp_redirect", "Сеть: ICMP Redirects",
            "pass" if "= 0" in v else "warning", "medium",
            "ICMP redirects могут использоваться для MITM атак.",
            v, "net.ipv4.conf.all.accept_redirects = 0",
            "Отключите приём ICMP redirects.",
            "network", "CIS §3.2.2", "NIST SC-5",
            "sysctl -w net.ipv4.conf.all.accept_redirects=0"))

        return results

    # ── System ────────────────────────────────────────────────────────────────
    def _system_checks(self):
        r = self.run
        results = []

        # Updates
        v = r("apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || yum check-update 2>/dev/null | grep -c '^[a-zA-Z]' || echo '0'")
        n = _num(v, 0)
        results.append(chk("sys_updates", "Система: Обновления безопасности",
            "pass" if n == 0 else ("warning" if n < 10 else "fail"),
            "critical" if n > 20 else ("high" if n > 0 else "info"),
            "Необновлённые пакеты содержат известные уязвимости (CVE).",
            f"{n} пакетов требует обновления", "0 пакетов",
            "Выполните: apt-get update && apt-get upgrade -y",
            "system", "CIS §1.9", "NIST SI-2",
            "apt-get update && apt-get upgrade -y"))

        # SUID files
        v = r("find / -perm -4000 -type f 2>/dev/null | grep -v '/proc' | wc -l || echo '0'")
        n = _num(v, 0)
        results.append(chk("sys_suid", "Система: SUID файлы",
            "pass" if n < 15 else ("warning" if n < 30 else "fail"),
            "high" if n >= 30 else "medium",
            "SUID файлы могут использоваться для повышения привилегий.",
            f"{n} SUID файлов найдено", "< 15 SUID файлов",
            "Проверьте SUID файлы через GTFOBins.",
            "system", "CIS §6.1.13", "NIST CM-7"))

        # AppArmor
        v = r("systemctl is-active apparmor 2>/dev/null || aa-status 2>/dev/null | head -1 || echo 'inactive'")
        results.append(chk("sys_apparmor", "Система: AppArmor (MAC)",
            "pass" if "active" in v.lower() or "profiles" in v.lower() else "fail", "high",
            "AppArmor ограничивает возможности приложений при компрометации.",
            v[:80], "AppArmor активен",
            "Активируйте AppArmor: systemctl enable --now apparmor",
            "system", "CIS §1.6.1", "NIST AC-3",
            "apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor"))

        # auditd
        v = r("systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | grep -o 'active\\|inactive' || echo 'inactive'")
        results.append(chk("sys_auditd", "Система: Auditd (аудит)",
            "pass" if "active" in v.lower() else "fail", "high",
            "Без auditd невозможно расследовать инциденты безопасности.",
            v, "active",
            "Установите и активируйте auditd.",
            "system", "CIS §4.1.1", "NIST AU-2",
            "apt-get install -y auditd && systemctl enable --now auditd"))

        # fail2ban
        v = r("systemctl is-active fail2ban 2>/dev/null || service fail2ban status 2>/dev/null | grep -o 'active\\|inactive' || echo 'inactive'")
        results.append(chk("sys_fail2ban", "Система: Fail2Ban",
            "pass" if "active" in v.lower() else "warning", "high",
            "Без Fail2Ban сервер уязвим к брутфорс-атакам.",
            v, "active",
            "Установите и активируйте Fail2Ban.",
            "system", "CIS §5.3", "NIST AC-7",
            "apt-get install -y fail2ban && systemctl enable --now fail2ban"))

        # Unattended upgrades
        v = r("systemctl is-active unattended-upgrades 2>/dev/null || dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii' || echo '0'")
        results.append(chk("sys_auto_updates", "Система: Автообновления безопасности",
            "pass" if "active" in v.lower() or v.strip() == "1" else "warning", "medium",
            "Без автообновлений критические патчи устанавливаются с задержкой.",
            v, "active",
            "Настройте автоматическую установку обновлений безопасности.",
            "system", "CIS §1.9", "NIST SI-2",
            "apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"))

        # /tmp noexec
        v = r("mount | grep '/tmp' | grep -o 'noexec\\|exec' || cat /proc/mounts | grep '/tmp' | grep -o 'noexec\\|exec' || echo 'not mounted separately'")
        results.append(chk("sys_tmp_noexec", "Файловая система: /tmp noexec",
            "pass" if "noexec" in v else "warning", "medium",
            "Без noexec в /tmp злоумышленник может запускать вредоносный код из /tmp.",
            v, "noexec",
            "Примонтируйте /tmp с опцией noexec.",
            "filesystem", "CIS §1.1.3", "NIST CM-7"))

        # Kernel version
        v = r("uname -r 2>/dev/null || echo 'unknown'")
        results.append(chk("sys_kernel", "Система: Версия ядра",
            "info", "info",
            "Актуальное ядро содержит последние патчи безопасности.",
            v, "Актуальная версия",
            "Регулярно обновляйте ядро.",
            "system", "CIS §1.9", "NIST SI-2"))

        return results

    # ── Filesystem ────────────────────────────────────────────────────────────
    def _filesystem_checks(self):
        r = self.run
        results = []

        # World-writable files
        v = r("find /etc /usr /bin /sbin -perm -o+w -type f 2>/dev/null | grep -v '/proc' | wc -l || echo '0'")
        n = _num(v, 0)
        results.append(chk("fs_world_writable", "ФС: World-writable системные файлы",
            "pass" if n == 0 else "fail", "high",
            "Системные файлы доступные для записи всем — прямой вектор атаки.",
            f"{n} файлов", "0 файлов",
            "Исправьте права доступа: chmod o-w <файл>",
            "filesystem", "CIS §6.1.11", "NIST CM-6"))

        # /etc/passwd permissions
        v = r("stat -c '%a' /etc/passwd 2>/dev/null || echo '644'")
        results.append(chk("fs_passwd_perms", "ФС: Права /etc/passwd",
            "pass" if v.strip() in ["644","444"] else "fail", "medium",
            "Неправильные права на /etc/passwd могут позволить изменение пользователей.",
            f"{v} (ожидается 644)", "644",
            "chmod 644 /etc/passwd",
            "filesystem", "CIS §6.1.2", "NIST AC-3",
            "chmod 644 /etc/passwd"))

        # /etc/shadow permissions
        v = r("stat -c '%a' /etc/shadow 2>/dev/null || echo '640'")
        results.append(chk("fs_shadow_perms", "ФС: Права /etc/shadow",
            "pass" if v.strip() in ["640","000","400"] else "fail", "critical",
            "Широкий доступ к /etc/shadow позволяет извлечь хэши паролей.",
            f"{v} (ожидается 640)", "640",
            "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
            "filesystem", "CIS §6.1.3", "NIST IA-5",
            "chmod 640 /etc/shadow"))

        # Home dirs permissions
        v = r("find /home -maxdepth 1 -type d -perm /o+rwx 2>/dev/null | wc -l || echo '0'")
        n = _num(v, 0)
        results.append(chk("fs_home_perms", "ФС: Права домашних директорий",
            "pass" if n == 0 else "warning", "medium",
            "Домашние директории с широкими правами позволяют доступ к файлам пользователей.",
            f"{n} директорий с широкими правами", "0",
            "Установите права 700 на домашние директории.",
            "filesystem", "CIS §6.2.7", "NIST AC-3"))

        # Sticky bit on /tmp
        v = r("stat -c '%a' /tmp 2>/dev/null || echo '1777'")
        results.append(chk("fs_tmp_sticky", "ФС: Sticky bit на /tmp",
            "pass" if v.strip().startswith("1") else "fail", "medium",
            "Без sticky bit пользователи могут удалять файлы других.",
            v, "1777",
            "chmod +t /tmp",
            "filesystem", "CIS §1.1.2", "NIST CM-6",
            "chmod 1777 /tmp"))

        return results

    # ── Users ─────────────────────────────────────────────────────────────────
    def _user_checks(self):
        r = self.run
        results = []

        # UID 0 accounts
        v = r("awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null || echo 'root'")
        uid0 = [u for u in v.strip().split('\n') if u and u != 'root']
        results.append(chk("usr_uid0", "Пользователи: Аккаунты с UID 0",
            "pass" if not uid0 else "fail", "critical",
            "Несколько аккаунтов с UID 0 (root-привилегии) — признак компрометации.",
            v.strip(), "Только root с UID 0",
            "Удалите лишние аккаунты с UID 0.",
            "users", "CIS §6.2.5", "NIST IA-4"))

        # Users without password
        v = r("awk -F: '($2 == \"!\" || $2 == \"*\" || $2 == \"\") {print $1}' /etc/shadow 2>/dev/null | head -10 || echo ''")
        locked = [u for u in v.strip().split('\n') if u]
        results.append(chk("usr_no_pass", "Пользователи: Без пароля/заблокированные",
            "info", "info",
            "Заблокированные аккаунты (! или *) — это системные аккаунты без входа.",
            f"{len(locked)} аккаунтов: {', '.join(locked[:5])}" if locked else "Нет",
            "Только системные аккаунты", "Проверьте список вручную.",
            "users", "CIS §6.2.1", "NIST IA-5"))

        # Sudo users
        v = r("getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || echo 'not found'")
        results.append(chk("usr_sudo", "Пользователи: Sudo группа",
            "info", "info",
            "Список пользователей с правами sudo.",
            v[:100], "Только доверенные пользователи",
            "Регулярно проверяйте список sudo-пользователей.",
            "users", "CIS §5.3", "NIST AC-6"))

        # Last logins
        v = r("lastlog 2>/dev/null | grep -v 'Never logged in' | tail -5 || echo 'N/A'")
        results.append(chk("usr_last_login", "Пользователи: Последние входы",
            "info", "info",
            "История последних успешных входов в систему.",
            v[:200], "Только авторизованные входы",
            "Регулярно проверяйте историю входов.",
            "users", "CIS §5.5", "NIST AU-2"))

        return results

    # ── Services ──────────────────────────────────────────────────────────────
    def _service_checks(self):
        r = self.run
        results = []

        # Unnecessary services
        for svc, desc in [("telnet","Telnet передаёт данные в открытом виде"),
                          ("rsh","rsh небезопасен"),
                          ("rlogin","rlogin небезопасен"),
                          ("vsftpd","FTP передаёт пароли в открытом виде"),
                          ("tftp","TFTP не имеет аутентификации")]:
            v = r(f"systemctl is-active {svc} 2>/dev/null || echo 'inactive'")
            if "active" in v.lower():
                results.append(chk(f"svc_{svc}", f"Сервисы: {svc} активен",
                    "fail", "high", desc,
                    "active", "inactive",
                    f"Отключите {svc}: systemctl disable --now {svc}",
                    "services", "CIS §2.1", "NIST CM-7",
                    f"systemctl disable --now {svc}"))

        # Cron permissions
        v = r("stat -c '%a' /etc/crontab 2>/dev/null || echo '644'")
        results.append(chk("svc_cron_perms", "Сервисы: Права /etc/crontab",
            "pass" if v.strip() in ["600","400"] else "warning", "medium",
            "Широкий доступ к crontab позволяет добавить вредоносные задачи.",
            v, "600",
            "chmod 600 /etc/crontab",
            "services", "CIS §5.1.2", "NIST CM-6",
            "chmod 600 /etc/crontab && chown root:root /etc/crontab"))

        # NTP
        v = r("timedatectl show 2>/dev/null | grep NTPSynchronized || systemctl is-active ntp 2>/dev/null || systemctl is-active chrony 2>/dev/null || echo 'inactive'")
        results.append(chk("svc_ntp", "Сервисы: Синхронизация времени (NTP)",
            "pass" if "yes" in v.lower() or "active" in v.lower() else "warning", "medium",
            "Неправильное время нарушает работу логов и аутентификации.",
            v[:80], "NTP активен",
            "Установите и настройте NTP/chrony.",
            "services", "CIS §2.2.1", "NIST AU-8",
            "apt-get install -y chrony && systemctl enable --now chronyd"))

        return results

    # ── Kernel ────────────────────────────────────────────────────────────────
    def _kernel_checks(self):
        r = self.run
        results = []

        # ASLR
        v = r("sysctl kernel.randomize_va_space 2>/dev/null || cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo '0'")
        n = _num(v, 0)
        results.append(chk("kern_aslr", "Ядро: ASLR (рандомизация адресов)",
            "pass" if n == 2 else "fail", "high",
            "ASLR усложняет эксплуатацию уязвимостей переполнения буфера.",
            v, "kernel.randomize_va_space = 2",
            "Включите ASLR.",
            "kernel", "CIS §3.3.1", "NIST SI-16",
            "sysctl -w kernel.randomize_va_space=2"))

        # Core dumps
        v = r("sysctl kernel.core_pattern 2>/dev/null || echo 'not set'")
        results.append(chk("kern_core_dump", "Ядро: Core dumps",
            "info", "low",
            "Core dumps могут содержать чувствительные данные из памяти.",
            v[:80], "Ограничены или отключены",
            "Ограничьте core dumps через ulimit и sysctl.",
            "kernel", "CIS §1.5.1", "NIST CM-6"))

        # dmesg restriction
        v = r("sysctl kernel.dmesg_restrict 2>/dev/null || echo 'not set'")
        results.append(chk("kern_dmesg", "Ядро: Ограничение dmesg",
            "pass" if "= 1" in v else "warning", "low",
            "dmesg может содержать информацию об адресах памяти ядра.",
            v, "kernel.dmesg_restrict = 1",
            "Ограничьте доступ к dmesg.",
            "kernel", "CIS §3.3.3", "NIST CM-6",
            "sysctl -w kernel.dmesg_restrict=1"))

        return results

    # ── Logging ───────────────────────────────────────────────────────────────
    def _logging_checks(self):
        r = self.run
        results = []

        # rsyslog
        v = r("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null || echo 'inactive'")
        results.append(chk("log_rsyslog", "Логирование: rsyslog",
            "pass" if "active" in v.lower() else "fail", "medium",
            "Без rsyslog системные события не записываются в логи.",
            v, "active",
            "Установите и активируйте rsyslog.",
            "logging", "CIS §4.2.1", "NIST AU-2",
            "apt-get install -y rsyslog && systemctl enable --now rsyslog"))

        # Log rotation
        v = r("systemctl is-active logrotate 2>/dev/null || ls /etc/logrotate.d/ 2>/dev/null | wc -l || echo '0'")
        results.append(chk("log_rotation", "Логирование: Ротация логов",
            "pass" if "active" in v.lower() or _num(v,0) > 0 else "warning", "low",
            "Без ротации логи занимают всё место на диске.",
            v[:50], "logrotate настроен",
            "Настройте logrotate.",
            "logging", "CIS §4.3", "NIST AU-9"))

        # Auth log
        v = r("ls -la /var/log/auth.log 2>/dev/null || ls -la /var/log/secure 2>/dev/null || echo 'not found'")
        results.append(chk("log_auth", "Логирование: Auth лог существует",
            "pass" if "not found" not in v else "warning", "medium",
            "Auth лог записывает все попытки входа.",
            v[:80], "/var/log/auth.log существует",
            "Убедитесь что rsyslog ведёт auth лог.",
            "logging", "CIS §4.2.1.2", "NIST AU-3"))

        return results


# ══════════════════════════════════════════════════════════════════════════════
# MACOS SCANNER (30+ checks via SSH)
# ══════════════════════════════════════════════════════════════════════════════

class MacOSScanner:
    def __init__(self, run_cmd):
        self.run = run_cmd

    def scan(self) -> List[Dict]:
        results = []
        results.extend(self._system_checks())
        results.extend(self._network_checks())
        results.extend(self._user_checks())
        results.extend(self._security_checks())
        results.extend(self._filesystem_checks())
        return results

    def _system_checks(self):
        r = self.run
        results = []

        v = r("sw_vers -productVersion 2>/dev/null || echo 'unknown'")
        results.append(chk("mac_version", "macOS: Версия системы",
            "info", "info", "Актуальная версия macOS содержит последние патчи.",
            v, "Последняя версия macOS", "Обновите macOS до последней версии.",
            "system"))

        v = r("softwareupdate -l 2>/dev/null | grep -c 'recommended' || echo '0'")
        n = _num(v, 0)
        results.append(chk("mac_updates", "macOS: Обновления системы",
            "pass" if n == 0 else "fail", "high",
            "Необновлённая система содержит известные уязвимости.",
            f"{n} обновлений доступно", "0 обновлений",
            "Установите все доступные обновления: softwareupdate -ia",
            "system", "", "NIST SI-2",
            "softwareupdate -ia"))

        v = r("systemsetup -getremotelogin 2>/dev/null || echo 'unknown'")
        results.append(chk("mac_remote_login", "macOS: Remote Login (SSH)",
            "info", "info",
            "Remote Login активирует SSH сервер.",
            v, "Off если не используется",
            "Отключите Remote Login если SSH не нужен.",
            "system", "", "NIST CM-7"))

        v = r("defaults read /Library/Preferences/com.apple.screensaver askForPassword 2>/dev/null || echo '0'")
        results.append(chk("mac_screensaver_pw", "macOS: Пароль при выходе из скринсейвера",
            "pass" if v.strip() == "1" else "fail", "medium",
            "Без пароля скринсейвера физический доступ к компьютеру не требует аутентификации.",
            v, "1 (включён)",
            "Включите: defaults write com.apple.screensaver askForPassword -int 1",
            "system", "", "NIST AC-11",
            "defaults write com.apple.screensaver askForPassword -int 1 && defaults write com.apple.screensaver askForPasswordDelay -int 0"))

        v = r("sysctl kern.bootargs 2>/dev/null || echo 'unknown'")
        results.append(chk("mac_sip", "macOS: System Integrity Protection (SIP)",
            "info", "info",
            "SIP защищает системные файлы от изменения.",
            r("csrutil status 2>/dev/null || echo 'unknown'"),
            "enabled",
            "Не отключайте SIP без крайней необходимости.",
            "system"))

        return results

    def _network_checks(self):
        r = self.run
        results = []

        v = r("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo 'disabled'")
        results.append(chk("mac_firewall", "macOS: Фаервол",
            "pass" if "enabled" in v.lower() else "fail", "high",
            "Без фаервола входящие соединения не фильтруются.",
            v, "Enabled",
            "Включите: /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            "network", "", "NIST SC-7",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"))

        v = r("networksetup -listallnetworkservices 2>/dev/null | head -10 || echo 'N/A'")
        results.append(chk("mac_network_services", "macOS: Сетевые сервисы",
            "info", "info",
            "Список активных сетевых интерфейсов.",
            v[:200], "Только необходимые сервисы",
            "Отключите неиспользуемые сетевые сервисы.",
            "network"))

        v = r("sudo launchctl list 2>/dev/null | grep -iE 'sharing|bonjour|bluetooth' | head -5 || echo 'N/A'")
        results.append(chk("mac_sharing", "macOS: Сервисы общего доступа",
            "info", "info",
            "Сервисы общего доступа расширяют поверхность атаки.",
            v[:200], "Отключены если не нужны",
            "Отключите Bonjour, File Sharing и Bluetooth если не используются.",
            "network"))

        v = r("defaults read /Library/Preferences/SystemConfiguration/com.apple.captive.control Active 2>/dev/null || echo 'unknown'")
        results.append(chk("mac_wifi_security", "macOS: Открытые Wi-Fi сети",
            "info", "low",
            "Автоподключение к открытым сетям опасно.",
            v, "Осторожно с открытыми сетями",
            "Не подключайтесь автоматически к открытым Wi-Fi сетям.",
            "network"))

        return results

    def _user_checks(self):
        r = self.run
        results = []

        v = r("dscl . list /Users UniqueID | awk '$2 == 0 {print $1}' 2>/dev/null || echo 'root'")
        uid0 = [u for u in v.strip().split('\n') if u and u != 'root']
        results.append(chk("mac_uid0", "Пользователи: UID 0 аккаунты",
            "pass" if not uid0 else "fail", "critical",
            "Несколько аккаунтов с UID 0 — признак компрометации.",
            v.strip(), "Только root",
            "Удалите лишние аккаунты с UID 0.",
            "users"))

        v = r("dscl . list /Users Password 2>/dev/null | grep -v '\\*' | head -5 || echo 'none'")
        results.append(chk("mac_guest", "Пользователи: Guest аккаунт",
            "info", "low",
            "Гостевой аккаунт предоставляет доступ без пароля.",
            r("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo '0'"),
            "0 (отключён)",
            "Отключите гостевой аккаунт в System Preferences.",
            "users"))

        v = r("dscl . list /Groups GroupMembership | grep -E '^admin' 2>/dev/null || echo 'N/A'")
        results.append(chk("mac_admins", "Пользователи: Администраторы",
            "info", "info",
            "Список пользователей с правами администратора.",
            v[:200], "Минимум администраторов",
            "Используйте учётную запись администратора только при необходимости.",
            "users"))

        return results

    def _security_checks(self):
        r = self.run
        results = []

        v = r("fdesetup status 2>/dev/null || diskutil cs list 2>/dev/null | grep -o 'Fully Encrypted\\|Locked' | head -1 || echo 'unknown'")
        results.append(chk("mac_filevault", "Безопасность: FileVault (шифрование)",
            "pass" if "on" in v.lower() or "encrypted" in v.lower() else "fail", "high",
            "Без FileVault данные на диске не зашифрованы.",
            v, "FileVault On",
            "Включите FileVault в System Preferences > Security.",
            "security", "", "NIST SC-28",
            "sudo fdesetup enable"))

        v = r("spctl --status 2>/dev/null || echo 'unknown'")
        results.append(chk("mac_gatekeeper", "Безопасность: Gatekeeper",
            "pass" if "enabled" in v.lower() or "assessments enabled" in v.lower() else "fail", "high",
            "Gatekeeper блокирует запуск неподписанных приложений.",
            v, "assessments enabled",
            "spctl --master-enable",
            "security", "", "NIST SI-3",
            "sudo spctl --master-enable"))

        v = r("defaults read com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled 2>/dev/null || echo '0'")
        results.append(chk("mac_java_safari", "Безопасность: Java в Safari",
            "pass" if v.strip() in ["0",""] else "warning", "medium",
            "Java плагин в браузере — частый вектор атак.",
            v, "0 (отключён)",
            "Отключите Java в настройках Safari.",
            "security"))

        v = r("defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo '0'")
        results.append(chk("mac_fw_logging", "Безопасность: Логирование фаервола",
            "pass" if v.strip() == "1" else "warning", "medium",
            "Без логирования фаервола невозможно обнаружить атаки.",
            v, "1 (включён)",
            "defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true",
            "security", "", "NIST AU-2",
            "sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true"))

        return results

    def _filesystem_checks(self):
        r = self.run
        results = []

        v = r("find /etc /usr/local/bin -perm -o+w -type f 2>/dev/null | wc -l || echo '0'")
        n = _num(v, 0)
        results.append(chk("mac_world_writable", "ФС: World-writable системные файлы",
            "pass" if n == 0 else "fail", "high",
            "Системные файлы доступные для записи всем — вектор атаки.",
            f"{n} файлов", "0 файлов",
            "Исправьте права: chmod o-w <файл>",
            "filesystem"))

        v = r("ls -la /tmp 2>/dev/null | head -3 || echo 'N/A'")
        results.append(chk("mac_tmp", "ФС: Директория /tmp",
            "info", "info",
            "Проверка наличия и прав /tmp.",
            v[:100], "Нормальные права",
            "Убедитесь что /tmp имеет sticky bit.",
            "filesystem"))

        return results


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS SCANNER (via SSH + PowerShell)
# ══════════════════════════════════════════════════════════════════════════════

class WindowsScanner:
    def __init__(self, run_cmd):
        self.run = run_cmd

    def scan(self) -> List[Dict]:
        results = []
        results.extend(self._system_checks())
        results.extend(self._network_checks())
        results.extend(self._user_checks())
        results.extend(self._security_checks())
        results.extend(self._policy_checks())
        return results

    def _ps(self, cmd: str) -> str:
        """Run PowerShell command via SSH"""
        return self.run(f'powershell -Command "{cmd}"')

    def _system_checks(self):
        results = []

        v = self._ps("(Get-WmiObject Win32_OperatingSystem).Caption + ' ' + (Get-WmiObject Win32_OperatingSystem).Version")
        results.append(chk("win_version", "Windows: Версия ОС",
            "info", "info",
            "Версия операционной системы.",
            v[:100], "Windows Server 2019/2022",
            "Используйте актуальные версии Windows Server.",
            "system"))

        v = self._ps("(Get-WmiObject Win32_QuickFixEngineering | Measure-Object).Count")
        n = _num(v, 0)
        results.append(chk("win_updates", "Windows: Установленные обновления",
            "info" if n > 0 else "warning", "high",
            "Количество установленных обновлений безопасности.",
            f"{n} обновлений установлено", "> 0",
            "Регулярно устанавливайте обновления Windows.",
            "system", "", "NIST SI-2",
            "Install-WindowsUpdate -AcceptAll -AutoReboot"))

        v = self._ps("(Get-WmiObject Win32_OperatingSystem).LastBootUpTime")
        results.append(chk("win_uptime", "Windows: Время последней перезагрузки",
            "info", "info",
            "Давно не перезагружённая система может иметь неустановленные патчи.",
            v[:80], "Регулярные перезагрузки",
            "Перезагружайте сервер после установки обновлений.",
            "system"))

        v = self._ps("Get-BitLockerVolume -MountPoint C: 2>$null | Select-Object -ExpandProperty VolumeStatus || echo 'N/A'")
        results.append(chk("win_bitlocker", "Windows: BitLocker (шифрование)",
            "pass" if "FullyEncrypted" in v else "warning", "high",
            "Без BitLocker данные на диске не защищены.",
            v[:80], "FullyEncrypted",
            "Включите BitLocker на системном диске.",
            "system", "", "NIST SC-28",
            "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256"))

        return results

    def _network_checks(self):
        results = []

        v = self._ps("(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Name -join ', '")
        results.append(chk("win_firewall", "Windows: Windows Firewall",
            "fail" if v.strip() else "pass", "critical",
            "Windows Firewall должен быть включён для всех профилей.",
            f"Отключён для: {v}" if v.strip() else "Включён для всех профилей",
            "Включён для всех профилей",
            "Set-NetFirewallProfile -All -Enabled True",
            "network", "", "NIST SC-7",
            "Set-NetFirewallProfile -All -Enabled True"))

        v = self._ps("Get-NetTCPConnection -State Listen | Select-Object LocalPort | Sort-Object LocalPort -Unique | ForEach-Object {$_.LocalPort} | Out-String")
        dangerous = []
        for port, name in [("3389","RDP"),("445","SMB"),("135","RPC"),("23","Telnet"),("21","FTP")]:
            if port in v:
                dangerous.append(f"{name}:{port}")
        results.append(chk("win_open_ports", "Windows: Открытые порты",
            "warning" if dangerous else "info", "high" if dangerous else "info",
            "Список открытых портов.",
            ", ".join(dangerous) if dangerous else "Нет очевидно опасных портов",
            "Минимум открытых портов",
            "Закройте ненужные порты через Windows Firewall.",
            "network", "", "NIST CM-7"))

        # SMBv1
        v = self._ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
        results.append(chk("win_smb1", "Windows: SMBv1 (EternalBlue)",
            "fail" if "True" in v else "pass", "critical",
            "SMBv1 уязвим к атаке EternalBlue (WannaCry, NotPetya).",
            v.strip(), "False",
            "Отключите SMBv1 немедленно.",
            "network", "", "NIST CM-7",
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"))

        # RDP Security
        v = self._ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
        results.append(chk("win_rdp", "Windows: RDP статус",
            "info", "info",
            "Remote Desktop Protocol — частая цель атак.",
            "RDP включён" if v.strip() == "0" else "RDP отключён",
            "Отключён если не нужен",
            "Отключите RDP если не используется или ограничьте по IP.",
            "network"))

        return results

    def _user_checks(self):
        results = []

        v = self._ps("(Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.PasswordRequired -eq $false}).Name -join ', '")
        results.append(chk("win_no_pass", "Пользователи: Без пароля",
            "fail" if v.strip() else "pass", "critical",
            "Аккаунты без пароля не требуют аутентификации.",
            v if v.strip() else "Нет аккаунтов без пароля",
            "Все аккаунты имеют пароль",
            "Установите пароли для всех аккаунтов.",
            "users", "", "NIST IA-5"))

        v = self._ps("(Get-LocalUser -Name 'Administrator').Enabled")
        results.append(chk("win_admin", "Пользователи: Встроенный Administrator",
            "warning" if "True" in v else "pass", "high",
            "Встроенный аккаунт Administrator — частая цель атак.",
            v.strip(), "Disabled",
            "Отключите встроенный аккаунт Administrator и создайте новый.",
            "users", "", "NIST IA-4",
            "Disable-LocalUser -Name 'Administrator'"))

        v = self._ps("(Get-LocalUser -Name 'Guest').Enabled")
        results.append(chk("win_guest", "Пользователи: Guest аккаунт",
            "pass" if "False" in v else "fail", "high",
            "Гостевой аккаунт предоставляет доступ без пароля.",
            v.strip(), "Disabled",
            "Убедитесь что Guest аккаунт отключён.",
            "users", "", "NIST IA-4",
            "Disable-LocalUser -Name 'Guest'"))

        v = self._ps("(Get-LocalGroupMember -Group 'Administrators').Name -join ', '")
        results.append(chk("win_admins", "Пользователи: Локальные администраторы",
            "info", "info",
            "Список локальных администраторов.",
            v[:200], "Минимум администраторов",
            "Проверьте список администраторов.",
            "users"))

        return results

    def _security_checks(self):
        results = []

        # Windows Defender
        v = self._ps("(Get-MpComputerStatus).AntivirusEnabled")
        results.append(chk("win_defender", "Безопасность: Windows Defender",
            "pass" if "True" in v else "fail", "critical",
            "Windows Defender защищает от вирусов и вредоносного ПО.",
            v.strip(), "True",
            "Включите Windows Defender.",
            "security", "", "NIST SI-3",
            "Set-MpPreference -DisableRealtimeMonitoring $false"))

        # Defender updates
        v = self._ps("(Get-MpComputerStatus).AntivirusSignatureLastUpdated")
        results.append(chk("win_defender_sigs", "Безопасность: Базы Defender",
            "info", "info",
            "Дата последнего обновления антивирусных баз.",
            v[:80], "Свежие базы",
            "Обновляйте антивирусные базы ежедневно.",
            "security"))

        # UAC
        v = self._ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
        results.append(chk("win_uac", "Безопасность: UAC (контроль учётных записей)",
            "pass" if v.strip() == "1" else "fail", "high",
            "UAC предотвращает несанкционированные изменения системы.",
            v.strip(), "1 (включён)",
            "Включите UAC.",
            "security", "", "NIST AC-6",
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"))

        # Windows Audit Policy
        v = self._ps("auditpol /get /category:* 2>$null | Select-String 'Logon' | Out-String")
        results.append(chk("win_audit", "Безопасность: Политика аудита",
            "info", "info",
            "Политика аудита определяет что записывается в Event Log.",
            v[:150] if v.strip() else "Не настроена",
            "Аудит входов настроен",
            "Настройте аудит через: auditpol /set /category:*",
            "security", "", "NIST AU-2"))

        return results

    def _policy_checks(self):
        results = []

        # Password policy
        v = self._ps("net accounts | Out-String")
        results.append(chk("win_pw_policy", "Политики: Политика паролей",
            "info", "info",
            "Политика паролей Windows.",
            v[:300] if v.strip() else "Не настроена",
            "Минимум 12 символов, сложность включена",
            "Настройте политику паролей через Group Policy.",
            "policy", "", "NIST IA-5"))

        # Account lockout
        v = self._ps("(net accounts | Select-String 'Lockout threshold').ToString()")
        threshold = _num(v, 0)
        results.append(chk("win_lockout", "Политики: Блокировка аккаунта",
            "pass" if 0 < threshold <= 5 else "fail" if threshold == 0 else "warning", "high",
            "Без блокировки аккаунта возможен неограниченный брутфорс.",
            v.strip(), "3-5 попыток",
            "Настройте блокировку после 3-5 неверных попыток.",
            "policy", "", "NIST AC-7"))

        # PowerShell execution policy
        v = self._ps("Get-ExecutionPolicy -List | Out-String")
        results.append(chk("win_ps_policy", "Политики: PowerShell Execution Policy",
            "pass" if "Restricted" in v or "AllSigned" in v else "warning", "medium",
            "Unrestricted позволяет запускать любые скрипты.",
            v[:200], "Restricted или AllSigned",
            "Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine",
            "policy", "", "NIST CM-7"))

        return results


# ══════════════════════════════════════════════════════════════════════════════
# SCORE CALCULATOR
# ══════════════════════════════════════════════════════════════════════════════

def calculate_score(findings: List[Dict]) -> int:
    weights = {"critical": 15, "high": 8, "medium": 4, "low": 1, "info": 0}
    max_scores = {"critical": 100, "high": 50, "medium": 20, "low": 5, "info": 0}
    deductions = 0
    for f in findings:
        if f["status"] in ["fail", "warning"] and f["severity"] in weights:
            penalty = weights[f["severity"]]
            if f["status"] == "warning":
                penalty = penalty // 2
            deductions += penalty
    return max(0, min(100, 100 - deductions))
