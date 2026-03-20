import paramiko
import io
from typing import Dict, Any, List

POLICY_SCRIPTS = {
    "password": """
#!/bin/bash
MIN_LEN={min_length}
MAX_DAYS={max_age}
sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN $MIN_LEN/" /etc/login.defs
sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS $MAX_DAYS/" /etc/login.defs
sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/" /etc/login.defs
apt-get install -y libpam-pwquality -q 2>/dev/null
if ! grep -q "pam_pwquality" /etc/pam.d/common-password; then
  sed -i '/pam_unix.so/i password requisite pam_pwquality.so minlen={min_length} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 retry=3' /etc/pam.d/common-password
fi
echo "PASSWORD_POLICY: OK"
""",
    "ssh": """
#!/bin/bash
SSHD=/etc/ssh/sshd_config
cp $SSHD $SSHD.bak.linuxshield
set_cfg() {{ sed -i "s/^#*$1.*/$1 $2/" $SSHD || echo "$1 $2" >> $SSHD; }}
set_cfg PermitRootLogin {permit_root}
set_cfg PasswordAuthentication {password_auth}
set_cfg MaxAuthTries {max_auth_tries}
set_cfg ClientAliveInterval {idle_timeout}
set_cfg ClientAliveCountMax 3
set_cfg Protocol 2
systemctl restart sshd
echo "SSH_POLICY: OK"
""",
    "firewall": """
#!/bin/bash
apt-get install -y ufw -q 2>/dev/null
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
{port_rules}
ufw --force enable
echo "FIREWALL_POLICY: OK"
""",
    "audit": """
#!/bin/bash
apt-get install -y auditd audispd-plugins -q 2>/dev/null
systemctl enable auditd
systemctl start auditd
# Add audit rules
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p wa -k identity
auditctl -w /etc/sudoers -p wa -k sudoers
auditctl -w /var/log/auth.log -p wa -k auth_log
auditctl -a always,exit -F arch=b64 -S execve -k exec_commands
# Persist rules
cat > /etc/audit/rules.d/linuxshield.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /var/log/auth.log -p wa -k auth_log
-a always,exit -F arch=b64 -S execve -k exec_commands
EOF
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/linuxshield.rules
echo "AUDIT_POLICY: OK"
""",
    "updates": """
#!/bin/bash
apt-get install -y unattended-upgrades apt-listchanges -q 2>/dev/null
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {{
    "${{distro_id}}:${{distro_codename}}";
    "${{distro_id}}:${{distro_codename}}-security";
    "${{distro_id}}ESMApps:${{distro_codename}}-apps-security";
    "${{distro_id}}ESM:${{distro_codename}}-infra-security";
}};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable unattended-upgrades
echo "UPDATES_POLICY: OK"
"""
}

def apply_policy_to_host(host_ip: str, host_port: int, username: str, password: str,
                          policy_category: str, policy_rules: Dict[str, Any]) -> Dict[str, Any]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host_ip, port=host_port, username=username,
                      password=password, timeout=30)
        
        template = POLICY_SCRIPTS.get(policy_category, "")
        if not template:
            return {"success": False, "error": f"Неизвестная категория политики: {policy_category}"}
        
        # Fill template
        if policy_category == "password":
            script = template.format(
                min_length=policy_rules.get("min_length", 12),
                max_age=policy_rules.get("max_age", 90)
            )
        elif policy_category == "ssh":
            script = template.format(
                permit_root=policy_rules.get("permit_root", "no"),
                password_auth=policy_rules.get("password_auth", "no"),
                max_auth_tries=policy_rules.get("max_auth_tries", 4),
                idle_timeout=policy_rules.get("idle_timeout", 300)
            )
        elif policy_category == "firewall":
            ports = policy_rules.get("allowed_ports", ["22"])
            port_rules = "\n".join([f"ufw allow {p}/tcp" for p in ports])
            script = template.format(port_rules=port_rules)
        elif policy_category in ("audit", "updates"):
            script = template
        else:
            script = template
        
        stdin, stdout, stderr = client.exec_command(f"bash -s << 'ENDSCRIPT'\n{script}\nENDSCRIPT", timeout=120)
        out = stdout.read().decode()
        err = stderr.read().decode()
        
        return {"success": True, "output": out, "stderr": err}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        client.close()
