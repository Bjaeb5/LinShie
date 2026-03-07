import paramiko
import json
import tempfile
import os
from typing import Dict, Any

REMOTE_SCRIPT = r"""#!/bin/bash
run_check() {
    local id=$1 name=$2 cmd=$3 expected=$4 severity=$5 rec=$6 cis=$7 nist=$8
    local result=$(eval "$cmd" 2>/dev/null || echo "N/A")
    echo "$result"
}
output='{\"checks\":['
first=true

add_check() {
    local id=$1 name=$2 status=$3 severity=$4 current=$5 expected=$6 rec=$7 cis=$8 nist=$9
    if [ "$first" = true ]; then first=false; else output="$output,"; fi
    current_escaped=$(echo "$current" | sed 's/"/\\"/g' | tr '\n' ' ')
    output="$output{\"check_id\":\"$id\",\"name\":\"$name\",\"status\":\"$status\",\"severity\":\"$severity\",\"current_value\":\"$current_escaped\",\"expected_value\":\"$expected\",\"recommendation\":\"$rec\",\"cis_control\":\"$cis\",\"nist_control\":\"$nist\"}"
}

# SSH Root Login
val=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'PermitRootLogin yes')
if echo "$val" | grep -qi 'no'; then st="pass"; else st="fail"; fi
add_check "ssh_root" "SSH: Запрет root" "$st" "critical" "$val" "PermitRootLogin no" \
  "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd" \
  "CIS §5.2.8" "NIST AC-17"

# Firewall
ufw_status=$(ufw status 2>/dev/null | head -1 || echo "inactive")
if echo "$ufw_status" | grep -qi 'active'; then st="pass"; else st="fail"; fi
add_check "net_fw" "Фаервол UFW" "$st" "critical" "$ufw_status" "Status: active" \
  "ufw default deny incoming && ufw allow 22/tcp && ufw --force enable" \
  "CIS §3.5.1" "NIST SC-7"

# Updates
updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
if [ "$updates" -eq 0 ]; then st="pass"; else st="warning"; fi
add_check "sys_updates" "Обновления системы" "$st" "high" "$updates доступно" "0" \
  "apt-get update && apt-get upgrade -y" "CIS §1.9" "NIST SI-2"

# Password min length
pass_len=$(grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null || echo "PASS_MIN_LEN 5")
len_num=$(echo "$pass_len" | grep -oE '[0-9]+')
if [ "${len_num:-5}" -ge 12 ]; then st="pass"; else st="fail"; fi
add_check "passwd_len" "Минимальная длина пароля" "$st" "high" "$pass_len" "PASS_MIN_LEN 12" \
  "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs" "CIS §5.4.1" "NIST IA-5"

# Auditd
aud=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
if [ "$aud" = "active" ]; then st="pass"; else st="fail"; fi
add_check "sys_audit" "Служба auditd" "$st" "high" "$aud" "active" \
  "apt-get install -y auditd && systemctl enable --now auditd" "CIS §4.1.1" "NIST AU-2"

# AppArmor
aa=$(systemctl is-active apparmor 2>/dev/null || echo "inactive")
if [ "$aa" = "active" ]; then st="pass"; else st="warning"; fi
add_check "sys_aa" "AppArmor" "$st" "high" "$aa" "active" \
  "apt-get install -y apparmor && systemctl enable --now apparmor" "CIS §1.6.1" "NIST AC-3"

output="$output]}"
echo "$output"
"""

def scan_remote_host(ip: str, port: int, username: str, password: str = None, ssh_key: str = None) -> Dict[str, Any]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        connect_kwargs = {"hostname": ip, "port": port, "username": username, "timeout": 30}
        if ssh_key:
            import io
            key = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))
            connect_kwargs["pkey"] = key
        elif password:
            connect_kwargs["password"] = password
        else:
            raise ValueError("Требуется пароль или SSH-ключ")
        
        client.connect(**connect_kwargs)
        
        # Upload and run script
        sftp = client.open_sftp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(REMOTE_SCRIPT)
            tmp_path = f.name
        
        remote_script = f"/tmp/linuxshield_scan_{os.getpid()}.sh"
        sftp.put(tmp_path, remote_script)
        sftp.chmod(remote_script, 0o755)
        sftp.close()
        os.unlink(tmp_path)
        
        stdin, stdout, stderr = client.exec_command(f"bash {remote_script}", timeout=120)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        
        # Cleanup
        client.exec_command(f"rm -f {remote_script}")
        
        # Parse JSON output
        json_start = output.find('{')
        if json_start >= 0:
            result = json.loads(output[json_start:])
            return {"success": True, "checks": result.get("checks", [])}
        else:
            return {"success": False, "error": f"Неверный формат вывода: {output[:200]}"}
            
    except paramiko.AuthenticationException:
        return {"success": False, "error": "Ошибка аутентификации — неверный пароль или ключ"}
    except paramiko.NoValidConnectionsError:
        return {"success": False, "error": f"Не удалось подключиться к {ip}:{port}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        client.close()
