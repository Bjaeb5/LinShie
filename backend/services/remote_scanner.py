"""
Multi-OS Remote Scanner
Автоматически определяет ОС и запускает соответствующие проверки.
Linux: bash команды
macOS: bash + macOS-specific команды  
Windows: PowerShell через SSH (OpenSSH должен быть установлен)
"""
import paramiko
import json
import os
import io
from typing import Dict, Any

# ══════════════════════════════════════════════════════════════════════════════
# LINUX SCRIPT
# ══════════════════════════════════════════════════════════════════════════════
LINUX_SCRIPT = r'''#!/bin/bash
R='{"os":"linux","checks":['
F=true
a(){
    local id=$1 nm=$2 st=$3 sv=$4 cu=$5 ex=$6 rc=$7 ci=$8 ni=$9
    $F && F=false || R="$R,"
    cu=$(printf '%s' "$cu"|sed 's/"/\\"/g'|tr -d '\n\r'|cut -c1-150)
    rc=$(printf '%s' "$rc"|sed 's/"/\\"/g'|cut -c1-200)
    R="${R}{\"check_id\":\"${id}\",\"name\":\"${nm}\",\"status\":\"${st}\",\"severity\":\"${sv}\",\"current_value\":\"${cu}\",\"expected_value\":\"${ex}\",\"recommendation\":\"${rc}\",\"cis_control\":\"${ci}\",\"nist_control\":\"${ni}\"}"
}

## ── SSH ──────────────────────────────────────────────────────────────────────
v=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null||echo 'not set (default: yes)')
echo "$v"|grep -qi 'no' && s=pass || s=fail
a ssh_root "SSH: Запрет входа root" $s critical "$v" "PermitRootLogin no" \
  "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd" "CIS §5.2.8" "NIST AC-17"

v=$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null||echo 'not set (default: yes)')
echo "$v"|grep -qi 'no' && s=pass || s=warning
a ssh_pw "SSH: Отключить парольный вход" $s high "$v" "PasswordAuthentication no" \
  "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd" "CIS §5.2.11" "NIST IA-5"

v=$(grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null||echo 'not set (default: 6)')
n=$(echo "$v"|grep -oE '[0-9]+'|head -1); n=${n:-6}
[ "$n" -le 4 ] && s=pass || s=warning
a ssh_tries "SSH: Максимум попыток входа" $s medium "$v" "MaxAuthTries 4" \
  "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl restart sshd" "CIS §5.2.6" "NIST AC-7"

v=$(grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null||echo 'not set (default: no)')
echo "$v"|grep -qi 'yes' && s=fail || s=pass
a ssh_empty "SSH: Запрет пустых паролей" $s critical "$v" "PermitEmptyPasswords no" \
  "sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config && systemctl restart sshd" "CIS §5.2.9" "NIST IA-5"

v=$(grep -i '^ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null||echo 'not set')
n=$(echo "$v"|grep -oE '[0-9]+'|head -1); n=${n:-0}
([ "$n" -gt 0 ] && [ "$n" -le 300 ]) && s=pass || s=warning
a ssh_timeout "SSH: Таймаут сессии" $s medium "$v" "ClientAliveInterval 300" \
  "echo 'ClientAliveInterval 300\nClientAliveCountMax 3' >> /etc/ssh/sshd_config && systemctl restart sshd" "CIS §5.2.16" "NIST AC-12"

v=$(grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null||echo 'default (includes weak)')
echo "$v"|grep -qiE 'arcfour|3des|blowfish' && s=fail || s=pass
a ssh_ciphers "SSH: Алгоритмы шифрования" $s high "$v" "Только AES-256, ChaCha20" \
  "echo 'Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr' >> /etc/ssh/sshd_config" "CIS §5.2.13" "NIST SC-8"

## ── Network ───────────────────────────────────────────────────────────────────
v=$(ufw status 2>/dev/null|head -1||echo 'inactive')
echo "$v"|grep -qi 'active' && s=pass || s=fail
a net_fw "Фаервол UFW" $s critical "$v" "Status: active" \
  "ufw default deny incoming && ufw default allow outgoing && ufw allow 22/tcp && ufw --force enable" "CIS §3.5.1" "NIST SC-7"

v=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null||cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null||echo 0)
[ "$v" = "1" ] && s=pass || s=fail
a net_syn "TCP SYN Cookies (защита от DDoS)" $s high "$v" "1" \
  "sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies=1' >> /etc/sysctl.conf" "CIS §3.3.8" "NIST SC-5"

v=$(sysctl -n net.ipv4.ip_forward 2>/dev/null||echo 1)
[ "$v" = "0" ] && s=pass || s=warning
a net_fwd "IP Forwarding отключён" $s medium "$v" "0" \
  "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf" "CIS §3.1.1" "NIST CM-7"

v=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null||echo 1)
[ "$v" = "0" ] && s=pass || s=warning
a net_redir "ICMP Redirects отключены" $s medium "$v" "0" \
  "sysctl -w net.ipv4.conf.all.accept_redirects=0" "CIS §3.2.2" "NIST SC-5"

danger=$(ss -tlnp 2>/dev/null|grep -cE ':(3306|5432|6379|27017|9200|11211)\b'||echo 0)
[ "$danger" -eq 0 ] && s=pass || s=fail
v=$(ss -tlnp 2>/dev/null|grep -E ':(3306|5432|6379|27017|9200|11211)\b'|awk '{print $4}'|tr '\n' ' '||echo 'none')
a net_ports "Опасные открытые порты наружу" $s critical "${v:-none}" "Нет" \
  "Привяжите сервисы к 127.0.0.1 или закройте через UFW" "CIS §2.2" "NIST CM-7"

## ── System ────────────────────────────────────────────────────────────────────
upd=$(apt-get -s upgrade 2>/dev/null|grep -c '^Inst'||yum check-update 2>/dev/null|grep -c '^[a-Z]'||echo 0)
[ "$upd" -eq 0 ] && s=pass || s=warning
a sys_upd "Обновления безопасности" $s high "$upd пакетов ожидает" "0" \
  "apt-get update && apt-get upgrade -y" "CIS §1.9" "NIST SI-2"

suid=$(find / -perm -4000 -type f 2>/dev/null|grep -cvE '/proc|/snap'; echo 0|head -1)
[ "${suid:-0}" -lt 15 ] && s=pass || s=warning
a sys_suid "SUID файлы (вектор привилегий)" $s medium "${suid:-0} файлов" "<15" \
  "find / -perm -4000 -type f 2>/dev/null | xargs ls -la # проверьте через GTFOBins" "CIS §6.1.13" "NIST CM-7"

v=$(systemctl is-active auditd 2>/dev/null||echo inactive)
[ "$v" = "active" ] && s=pass || s=fail
a sys_aud "Auditd (аудит системы)" $s high "$v" "active" \
  "apt-get install -y auditd && systemctl enable --now auditd" "CIS §4.1.1" "NIST AU-2"

v=$(systemctl is-active fail2ban 2>/dev/null||echo inactive)
[ "$v" = "active" ] && s=pass || s=warning
a sys_f2b "Fail2Ban (защита от брутфорса)" $s high "$v" "active" \
  "apt-get install -y fail2ban && systemctl enable --now fail2ban" "CIS §5.3" "NIST AC-7"

v=$(systemctl is-active apparmor 2>/dev/null||aa-status 2>/dev/null|head -1||echo inactive)
echo "$v"|grep -qi 'active\|profile' && s=pass || s=fail
a sys_aa "AppArmor (мандатный контроль)" $s high "$v" "active" \
  "apt-get install -y apparmor apparmor-utils && systemctl enable --now apparmor && aa-enforce /etc/apparmor.d/*" "CIS §1.6.1" "NIST AC-3"

v=$(systemctl is-active unattended-upgrades 2>/dev/null||dpkg -l unattended-upgrades 2>/dev/null|grep -c '^ii'||echo 0)
(echo "$v"|grep -q 'active'||[ "$v" = "1" ]) && s=pass || s=warning
a sys_auto "Автообновления безопасности" $s medium "$v" "active" \
  "apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades" "CIS §1.9" "NIST SI-2"

## ── Passwords ────────────────────────────────────────────────────────────────
v=$(grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null||echo 'not set (default: 5)')
n=$(echo "$v"|grep -oE '[0-9]+'|head -1); n=${n:-5}
[ "$n" -ge 12 ] && s=pass || s=fail
a pw_len "Минимальная длина пароля" $s high "$v" "PASS_MIN_LEN 12" \
  "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs" "CIS §5.4.1" "NIST IA-5"

v=$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null||echo 'not set (default: 99999)')
n=$(echo "$v"|grep -oE '[0-9]+'|head -1); n=${n:-99999}
[ "$n" -le 90 ] && s=pass || s=warning
a pw_max "Срок действия пароля" $s medium "$v" "PASS_MAX_DAYS 90" \
  "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs" "CIS §5.4.1.1" "NIST IA-5"

empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null|wc -l||echo 0)
[ "$empty" -eq 0 ] && s=pass || s=fail
a pw_empty "Пустые пароли" $s critical "$empty аккаунтов" "0" \
  "passwd -l \$(awk -F: '(\$2==\"\"){print \$1}' /etc/shadow | head -1)" "CIS §6.2.1" "NIST IA-5"

v=$(grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password 2>/dev/null||echo 'not configured')
echo "$v"|grep -qE 'pam_pwquality|pam_cracklib' && s=pass || s=fail
a pw_qual "Сложность паролей (pam_pwquality)" $s high "$v" "pam_pwquality настроен" \
  "apt-get install -y libpam-pwquality && echo 'password requisite pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1' >> /etc/pam.d/common-password" "CIS §5.4.1" "NIST IA-5"

## ── Filesystem ───────────────────────────────────────────────────────────────
v=$(stat -c %a /etc/shadow 2>/dev/null||echo '777')
([ "$v" = "640" ]||[ "$v" = "600" ]||[ "$v" = "400" ]) && s=pass || s=fail
a fs_shadow "Права /etc/shadow" $s critical "$v" "640" \
  "chmod 640 /etc/shadow && chown root:shadow /etc/shadow" "CIS §6.1.3" "NIST IA-5"

v=$(stat -c %a /etc/passwd 2>/dev/null||echo '777')
([ "$v" = "644" ]||[ "$v" = "444" ]) && s=pass || s=fail
a fs_passwd "Права /etc/passwd" $s medium "$v" "644" \
  "chmod 644 /etc/passwd" "CIS §6.1.2" "NIST AC-3"

v=$(stat -c %a /tmp 2>/dev/null||echo '777')
echo "$v"|grep -q '^1' && s=pass || s=fail
a fs_tmp "Sticky bit на /tmp" $s medium "$v" "1777" \
  "chmod 1777 /tmp" "CIS §1.1.2" "NIST CM-6"

ww=$(find /etc /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null|wc -l||echo 0)
[ "$ww" -eq 0 ] && s=pass || s=fail
a fs_ww "World-writable системные файлы" $s high "$ww файлов" "0" \
  "find /etc /usr/bin -perm -o+w -type f | xargs chmod o-w" "CIS §6.1.11" "NIST CM-6"

## ── Kernel ───────────────────────────────────────────────────────────────────
v=$(sysctl -n kernel.randomize_va_space 2>/dev/null||echo 0)
[ "$v" = "2" ] && s=pass || s=fail
a kern_aslr "ASLR (рандомизация адресов)" $s high "$v" "2" \
  "sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf" "CIS §3.3.1" "NIST SI-16"

v=$(sysctl -n kernel.dmesg_restrict 2>/dev/null||echo 0)
[ "$v" = "1" ] && s=pass || s=warning
a kern_dmesg "Ограничение dmesg" $s low "$v" "1" \
  "sysctl -w kernel.dmesg_restrict=1" "CIS §3.3.3" "NIST CM-6"

## ── Users ────────────────────────────────────────────────────────────────────
uid0=$(awk -F: '($3==0){print $1}' /etc/passwd|grep -v '^root$'|wc -l||echo 0)
[ "$uid0" -eq 0 ] && s=pass || s=fail
a usr_uid0 "Только root с UID 0" $s critical "$uid0 лишних" "0" \
  "awk -F: '(\$3==0)' /etc/passwd # проверьте вручную" "CIS §6.2.5" "NIST IA-4"

v=$(systemctl is-active rsyslog 2>/dev/null||echo inactive)
[ "$v" = "active" ] && s=pass || s=fail
a log_syslog "Rsyslog (системное логирование)" $s medium "$v" "active" \
  "apt-get install -y rsyslog && systemctl enable --now rsyslog" "CIS §4.2.1" "NIST AU-2"

v=$(uname -r 2>/dev/null||echo unknown)
a sys_kern "Версия ядра Linux" info info "$v" "Актуальная" \
  "apt-get update && apt-get upgrade linux-image-generic -y" "CIS §1.9" "NIST SI-2"

R="$R]}"
printf '%s' "$R"
'''

# ══════════════════════════════════════════════════════════════════════════════
# MACOS SCRIPT
# ══════════════════════════════════════════════════════════════════════════════
MACOS_SCRIPT = r'''#!/bin/bash
R='{"os":"macos","checks":['
F=true
a(){
    local id=$1 nm=$2 st=$3 sv=$4 cu=$5 ex=$6 rc=$7
    $F && F=false || R="$R,"
    cu=$(printf '%s' "$cu"|sed 's/"/\\"/g'|tr -d '\n\r'|cut -c1-150)
    rc=$(printf '%s' "$rc"|sed 's/"/\\"/g'|cut -c1-200)
    R="${R}{\"check_id\":\"${id}\",\"name\":\"${nm}\",\"status\":\"${st}\",\"severity\":\"${sv}\",\"current_value\":\"${cu}\",\"expected_value\":\"${ex}\",\"recommendation\":\"${rc}\",\"cis_control\":\"\",\"nist_control\":\"\"}"
}

# Version
v=$(sw_vers -productVersion 2>/dev/null||echo unknown)
a mac_ver "macOS: Версия системы" info info "$v" "Последняя версия" "Обновите macOS в System Settings > General > Software Update"

# FileVault
v=$(fdesetup status 2>/dev/null||echo "FileVault is Off")
echo "$v"|grep -qi 'on' && s=pass || s=fail
a mac_fv "macOS: FileVault (шифрование диска)" $s high "$v" "FileVault is On" \
  "sudo fdesetup enable — или System Settings > Privacy & Security > FileVault"

# Firewall
v=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null||echo "disabled")
echo "$v"|grep -qi 'enabled' && s=pass || s=fail
a mac_fw "macOS: Фаервол" $s critical "$v" "Firewall is enabled" \
  "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"

# Gatekeeper
v=$(spctl --status 2>/dev/null||echo "unknown")
echo "$v"|grep -qi 'enabled\|assessments enabled' && s=pass || s=fail
a mac_gk "macOS: Gatekeeper" $s high "$v" "assessments enabled" \
  "sudo spctl --master-enable"

# SIP
v=$(csrutil status 2>/dev/null||echo "unknown")
echo "$v"|grep -qi 'enabled' && s=pass || s=warning
a mac_sip "macOS: System Integrity Protection (SIP)" $s high "$v" "enabled" \
  "Не отключайте SIP — он защищает системные файлы от изменения"

# Screensaver password
v=$(defaults read com.apple.screensaver askForPassword 2>/dev/null||echo 0)
[ "$v" = "1" ] && s=pass || s=fail
a mac_ss "macOS: Пароль при выходе из скринсейвера" $s medium "$v" "1" \
  "defaults write com.apple.screensaver askForPassword -int 1 && defaults write com.apple.screensaver askForPasswordDelay -int 0"

# Auto login
v=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null||echo "none")
[ "$v" = "none" ] && s=pass || s=fail
a mac_autologin "macOS: Автовход отключён" $s high "$v" "none" \
  "System Settings > Users & Groups — отключите автовход"

# Guest account
v=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null||echo 0)
[ "$v" = "0" ] && s=pass || s=warning
a mac_guest "macOS: Guest аккаунт отключён" $s medium "$v" "0" \
  "System Settings > Users & Groups > Guest User — отключите"

# Software updates available
v=$(softwareupdate -l 2>/dev/null|grep -c 'recommended'||echo 0)
[ "$v" -eq 0 ] && s=pass || s=warning
a mac_upd "macOS: Доступные обновления" $s high "$v обновлений" "0" \
  "softwareupdate -ia — или System Settings > General > Software Update"

# Remote Management
v=$(systemsetup -getremotelogin 2>/dev/null||echo "unknown")
a mac_ssh "macOS: Remote Login (SSH)" info info "$v" "Off если не нужен" \
  "sudo systemsetup -setremotelogin off — если SSH не используется"

# Sharing services
v=$(launchctl list 2>/dev/null|grep -E 'com.apple.smbd|com.apple.screensharing|com.apple.afpd'|wc -l||echo 0)
[ "$v" -eq 0 ] && s=pass || s=info
a mac_share "macOS: Сервисы общего доступа" $s low "$v активных" "0" \
  "System Settings > General > Sharing — отключите File Sharing, Screen Sharing, Printer Sharing"

# Firewall logging
v=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null||echo 0)
[ "$v" = "1" ] && s=pass || s=warning
a mac_fwlog "macOS: Логирование фаервола" $s medium "$v" "1" \
  "sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true"

# Admin users
v=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null|sed 's/GroupMembership: //'|tr ' ' '\n'|grep -vc '^$'||echo 1)
[ "$v" -le 2 ] && s=pass || s=warning
a mac_admins "macOS: Количество администраторов" $s medium "$v" "≤2" \
  "System Settings > Users & Groups — используйте стандартный аккаунт для работы"

# World-writable files
ww=$(find /etc /usr/local/bin -perm -o+w -type f 2>/dev/null|wc -l||echo 0)
[ "$ww" -eq 0 ] && s=pass || s=fail
a mac_ww "macOS: World-writable системные файлы" $s high "$ww файлов" "0" \
  "find /etc -perm -o+w -type f | xargs chmod o-w"

# SSH config if remote login enabled
if systemsetup -getremotelogin 2>/dev/null|grep -qi 'on'; then
    v=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null||echo 'not set')
    echo "$v"|grep -qi 'no' && s=pass || s=warning
    a mac_ssh_root "SSH: Запрет входа root" $s high "$v" "PermitRootLogin no" \
      "sudo sed -i '' 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo launchctl kickstart -k system/com.openssh.sshd"
    
    v=$(grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null||echo 'not set (default: 6)')
    n=$(echo "$v"|grep -oE '[0-9]+'|head -1); n=${n:-6}
    [ "$n" -le 4 ] && s=pass || s=warning
    a mac_ssh_tries "SSH: Лимит попыток входа" $s medium "$v" "MaxAuthTries 4" \
      "echo 'MaxAuthTries 4' | sudo tee -a /etc/ssh/sshd_config"
fi

# Disk encryption status (detail)
v=$(diskutil list 2>/dev/null|grep -c 'APFS'||echo 0)
a mac_apfs "macOS: APFS разделы" info info "$v APFS" "APFS с FileVault" \
  "Убедитесь что FileVault включён для всех APFS разделов"

R="$R]}"
printf '%s' "$R"
'''

# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS POWERSHELL SCRIPT (через SSH + PowerShell)
# ══════════════════════════════════════════════════════════════════════════════
WINDOWS_SCRIPT = r'''
$ErrorActionPreference = "SilentlyContinue"
$checks = @()

function Add-Check {
    param($id, $name, $status, $severity, $current, $expected, $rec, $cis="", $nist="")
    $checks += [PSCustomObject]@{
        check_id = $id; name = $name; status = $status; severity = $severity
        current_value = "$current".Substring(0, [Math]::Min("$current".Length, 150))
        expected_value = $expected; recommendation = $rec
        cis_control = $cis; nist_control = $nist
    }
}

# OS Version
$os = (Get-WmiObject Win32_OperatingSystem).Caption
Add-Check "win_ver" "Windows: Версия ОС" "info" "info" "$os" "Windows Server 2019/2022" `
  "Используйте актуальные версии Windows Server"

# Windows Defender
$def = (Get-MpComputerStatus).AntivirusEnabled
if ($def) { $st = "pass" } else { $st = "fail" }
Add-Check "win_def" "Windows Defender включён" $st "critical" "$def" "True" `
  "Set-MpPreference -DisableRealtimeMonitoring `$false" "" "NIST SI-3"

# Defender signatures
$sigdate = (Get-MpComputerStatus).AntivirusSignatureLastUpdated
Add-Check "win_defsig" "Windows Defender: дата обновления баз" "info" "info" "$sigdate" "Сегодня" `
  "Update-MpSignature"

# Firewall all profiles
$fwOff = (Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Name -join ", "
if ($fwOff) { $st = "fail" } else { $st = "pass" }
Add-Check "win_fw" "Windows Firewall (все профили)" $st "critical" `
  (if ($fwOff) { "Отключён: $fwOff" } else { "Включён для всех" }) "Включён для всех" `
  "Set-NetFirewallProfile -All -Enabled True" "" "NIST SC-7"

# SMBv1 (EternalBlue / WannaCry)
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) { $st = "fail" } else { $st = "pass" }
Add-Check "win_smb1" "SMBv1 отключён (EternalBlue/WannaCry)" $st "critical" "$smb1" "False" `
  "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" "" "NIST CM-7"

# SMBv2
$smb2 = (Get-SmbServerConfiguration).EnableSMB2Protocol
if ($smb2) { $st = "pass" } else { $st = "warning" }
Add-Check "win_smb2" "SMBv2 включён" $st "medium" "$smb2" "True" `
  "Set-SmbServerConfiguration -EnableSMB2Protocol `$true -Force"

# BitLocker
$bl = (Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).VolumeStatus
if ($bl -eq "FullyEncrypted") { $st = "pass" } else { $st = "warning" }
Add-Check "win_bl" "BitLocker (шифрование диска C:)" $st "high" "$bl" "FullyEncrypted" `
  "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256" "" "NIST SC-28"

# UAC
$uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
if ($uac -eq 1) { $st = "pass" } else { $st = "fail" }
Add-Check "win_uac" "UAC (контроль учётных записей)" $st "high" "$uac" "1" `
  "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1" "" "NIST AC-6"

# Guest account
$guest = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled
if ($guest -eq $false -or $null -eq $guest) { $st = "pass" } else { $st = "fail" }
Add-Check "win_guest" "Guest аккаунт отключён" $st "high" "$guest" "False" `
  "Disable-LocalUser -Name 'Guest'" "" "NIST IA-4"

# Built-in Administrator
$adm = (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled
if ($adm) { $st = "warning" } else { $st = "pass" }
Add-Check "win_adm" "Встроенный Administrator" $st "high" "$adm" "False" `
  "Disable-LocalUser -Name 'Administrator' # и создайте именованный аккаунт" "" "NIST IA-4"

# Accounts without password
$nopw = (Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.PasswordRequired -eq $false}).Name -join ", "
if ($nopw) { $st = "fail" } else { $st = "pass" }
Add-Check "win_nopw" "Аккаунты без пароля" $st "critical" `
  (if ($nopw) { $nopw } else { "Нет" }) "Нет" `
  "Set-LocalUser -Name USERNAME -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)" "" "NIST IA-5"

# Password policy
$pwpol = net accounts 2>$null | Out-String
$minlen = ($pwpol | Select-String "Minimum password length:\s+(\d+)").Matches.Groups[1].Value
if ([int]$minlen -ge 12) { $st = "pass" } else { $st = "fail" }
Add-Check "win_pwlen" "Минимальная длина пароля" $st "high" "Minimum: $minlen" "12+" `
  "net accounts /minpwlen:12" "" "NIST IA-5"

# Account lockout
$lockout = ($pwpol | Select-String "Lockout threshold:\s+(\d+)").Matches.Groups[1].Value
if ([int]$lockout -gt 0 -and [int]$lockout -le 5) { $st = "pass" } else { $st = "fail" }
Add-Check "win_lockout" "Блокировка аккаунта после N попыток" $st "high" "Threshold: $lockout" "3-5" `
  "net accounts /lockoutthreshold:5" "" "NIST AC-7"

# RDP
$rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
if ($rdp -eq 1) { $rdpStatus = "Отключён"; $st = "pass" } else { $rdpStatus = "Включён"; $st = "warning" }
Add-Check "win_rdp" "RDP (Remote Desktop)" $st "medium" $rdpStatus "Отключён если не нужен" `
  "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1"

# PowerShell execution policy
$pspol = Get-ExecutionPolicy -List | Out-String
if ($pspol -match "Restricted|AllSigned") { $st = "pass" } else { $st = "warning" }
Add-Check "win_pspol" "PowerShell Execution Policy" $st "medium" "$pspol".Trim().Substring(0,[Math]::Min($pspol.Length,100)) "Restricted/AllSigned" `
  "Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine" "" "NIST CM-7"

# Windows Updates pending
$wu = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
Add-Check "win_wu" "Последнее обновление Windows" "info" "info" "$wu" "Свежая дата" `
  "Install-WindowsUpdate -AcceptAll # требует PSWindowsUpdate модуль" "" "NIST SI-2"

# Audit policy
$audit = auditpol /get /category:"Logon/Logoff" 2>$null | Out-String
if ($audit -match "Success and Failure|Failure") { $st = "pass" } else { $st = "warning" }
Add-Check "win_audit" "Политика аудита (Logon/Logoff)" $st "medium" `
  $audit.Trim().Substring(0,[Math]::Min($audit.Length,100)) "Success and Failure" `
  "auditpol /set /subcategory:'Logon' /success:enable /failure:enable" "" "NIST AU-2"

# Open dangerous ports
$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
         Where-Object {$_.LocalPort -in @(3389,445,135,23,21,69,161)} | 
         Select-Object LocalPort | Sort-Object LocalPort -Unique
$portList = ($ports.LocalPort -join ", ")
if ($portList) { $st = "warning" } else { $st = "pass" }
Add-Check "win_ports" "Открытые потенциально опасные порты" $st "medium" `
  (if ($portList) { $portList } else { "Нет" }) "Минимум" `
  "Проверьте необходимость каждого порта и закройте ненужные через Firewall"

# Windows Defender Real-time
$rt = (Get-MpPreference).DisableRealtimeMonitoring
if ($rt -eq $false) { $st = "pass" } else { $st = "fail" }
Add-Check "win_rt" "Defender: Защита в реальном времени" $st "critical" `
  (if ($rt) { "Отключена" } else { "Включена" }) "Включена" `
  "Set-MpPreference -DisableRealtimeMonitoring `$false"

# Output JSON
$result = @{os="windows"; checks=$checks}
$result | ConvertTo-Json -Depth 5 -Compress
'''


def _run_cmd(client: paramiko.SSHClient, cmd: str, timeout: int = 15) -> str:
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        return out
    except Exception:
        return ""


def _detect_os(client: paramiko.SSHClient) -> str:
    """Detect remote OS."""
    uname = _run_cmd(client, "uname -s 2>/dev/null", 8).lower()
    if "darwin" in uname:
        return "macos"
    if "linux" in uname:
        return "linux"
    # Try Windows
    ver = _run_cmd(client, "cmd /c ver 2>nul", 8).lower()
    if "windows" in ver:
        return "windows"
    ps = _run_cmd(client, "powershell -Command \"$PSVersionTable.OS\" 2>nul", 8).lower()
    if "windows" in ps:
        return "windows"
    return "linux"


def _upload_and_run(client: paramiko.SSHClient, script: str,
                    remote_path: str, run_cmd: str, timeout: int = 120) -> str:
    """Upload script via SFTP and execute it."""
    sftp = client.open_sftp()
    sftp.putfo(io.BytesIO(script.encode("utf-8")), remote_path)
    sftp.chmod(remote_path, 0o755)
    sftp.close()
    _, stdout, stderr = client.exec_command(run_cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    client.exec_command(f"rm -f {remote_path} 2>/dev/null; del {remote_path} 2>nul", timeout=5)
    return out


def _run_windows(client: paramiko.SSHClient) -> Dict[str, Any]:
    """Run PowerShell scan on Windows."""
    pid = os.getpid()
    # Try via PowerShell directly (if SSH shell is PowerShell)
    remote_ps = f"C:\\Windows\\Temp\\lshi_{pid}.ps1"
    try:
        out = _upload_and_run(
            client, WINDOWS_SCRIPT, remote_ps,
            f"powershell -ExecutionPolicy Bypass -File \"{remote_ps}\"",
            timeout=120
        )
    except Exception:
        # Fallback: encode script as base64 and run inline
        import base64
        encoded = base64.b64encode(WINDOWS_SCRIPT.encode("utf-16-le")).decode()
        _, stdout, _ = client.exec_command(
            f"powershell -EncodedCommand {encoded}", timeout=120
        )
        out = stdout.read().decode("utf-8", errors="replace").strip()

    json_start = out.find('{"os"')
    if json_start == -1:
        json_start = out.find('{"checks"')
    if json_start >= 0:
        return {"success": True, "raw": out[json_start:], "os_type": "windows"}
    return {"success": False, "error": f"Нет JSON в выводе Windows: {out[:300]}"}


def _parse_and_enrich(raw_json: str, os_type: str) -> list:
    """Parse JSON output and add category/description fields."""
    data = json.loads(raw_json)
    checks = data.get("checks", [])

    CATEGORY_MAP = {
        "ssh": "SSH", "net": "Сеть", "sys": "Система",
        "pw": "Пароли", "fs": "Файловая система", "kern": "Ядро",
        "usr": "Пользователи", "log": "Логирование",
        "mac": "macOS", "win": "Windows",
    }

    for c in checks:
        cid = c.get("check_id", "")
        prefix = cid.split("_")[0]
        c["category"] = CATEGORY_MAP.get(prefix, "Общее")
        if not c.get("description"):
            c["description"] = c.get("recommendation", "")

    return checks


def scan_remote_host(ip: str, port: int, username: str,
                     password: str = None, ssh_key: str = None) -> Dict[str, Any]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": ip, "port": port,
            "username": username, "timeout": 30,
        }
        if ssh_key:
            key = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))
            connect_kwargs["pkey"] = key
        elif password:
            connect_kwargs["password"] = password
        else:
            raise ValueError("Требуется пароль или SSH-ключ")

        client.connect(**connect_kwargs)

        # ── Detect OS ─────────────────────────────────────────────────────────
        os_type = _detect_os(client)
        pid = os.getpid()

        # ── Run appropriate script ─────────────────────────────────────────────
        if os_type == "windows":
            win_result = _run_windows(client)
            if not win_result["success"]:
                return win_result
            raw = win_result["raw"]

        else:
            script = LINUX_SCRIPT if os_type == "linux" else MACOS_SCRIPT
            remote_path = f"/tmp/lshi_{pid}.sh"
            raw = _upload_and_run(
                client, script, remote_path,
                f"bash {remote_path}", timeout=120
            )

        # ── Parse JSON ────────────────────────────────────────────────────────
        json_start = raw.find('{"os"')
        if json_start == -1:
            json_start = raw.find('{"checks"')
        if json_start < 0:
            return {"success": False,
                    "error": f"Не удалось получить JSON от {os_type}. Вывод: {raw[:400]}"}

        checks = _parse_and_enrich(raw[json_start:], os_type)
        return {"success": True, "checks": checks, "os_type": os_type}

    except paramiko.AuthenticationException:
        return {"success": False,
                "error": "Ошибка аутентификации — неверный логин или пароль"}
    except paramiko.NoValidConnectionsError as e:
        return {"success": False,
                "error": f"Не удалось подключиться к {ip}:{port}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            client.close()
        except Exception:
            pass
