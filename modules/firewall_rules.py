"""
Firewall Rules Generator Module - Xavfli IP larni avtomatik bloklash buyruqlarini generatsiya qilish.
Linux UFW, IPTables, Windows Firewall, Nginx, Apache va Mikrotik qoidalari.
"""

from typing import List

class FirewallGenerator:
    def __init__(self):
        pass

    def generate_single_ip_rules(self, ip_str: str, reason: str = "CyberThreat"):
        """Bitta IP uchun barcha tizimlardagi bloklash buyruqlari"""
        ip = ip_str.strip()
        reason_str = str(reason) if reason and not hasattr(reason, 'default') else "CyberThreat"
        safe_reason = reason_str.replace(" ", "_")

        return {
            "ip": ip,
            "linux_ufw": f"sudo ufw insert 1 deny from {ip} to any comment '{reason_str}'",
            "linux_iptables": f"sudo iptables -I INPUT -s {ip} -j DROP -m comment --comment '{reason_str}'",
            "windows_powershell": f'New-NetFirewallRule -DisplayName "CyberBlock_{ip}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "{reason_str}"',
            "windows_cmd_netsh": f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}',
            "nginx_deny": f"deny {ip}; # {reason_str}",
            "apache_htaccess": f"Require not ip {ip} # {reason_str}",
            "mikrotik": f'/ip firewall filter add chain=input src-address={ip} action=drop comment="{safe_reason}"',
            "cloudflare_expression": f'(ip.src eq {ip})'
        }

    def generate_batch_script(self, ip_list: List[str], platform: str = "linux_ufw", reason: str = "CyberThreat"):
        """Bir nechta IP lar uchun tayyor skript matni"""
        clean_ips = [ip.strip() for ip in ip_list if ip.strip()]
        
        if platform == "linux_ufw":
            lines = ["#!/bin/bash", "# Avtomatik generatsiya qilingan UFW bloklash skripti", ""]
            for ip in clean_ips:
                lines.append(f"sudo ufw insert 1 deny from {ip} to any comment '{reason}'")
            lines.append("sudo ufw reload")
            lines.append("echo 'Barcha xavfli IP lar UFW orqali bloklandi!'")
            return "\n".join(lines)

        elif platform == "linux_iptables":
            lines = ["#!/bin/bash", "# IPTables bloklash skripti", ""]
            for ip in clean_ips:
                lines.append(f"sudo iptables -I INPUT -s {ip} -j DROP -m comment --comment '{reason}'")
            lines.append("echo 'Barcha xavfli IP lar IPTables orqali bloklandi!'")
            return "\n".join(lines)

        elif platform == "windows_powershell":
            lines = ["# Windows PowerShell Firewall Bloklash Skripti (Run as Administrator)", ""]
            for ip in clean_ips:
                lines.append(f'New-NetFirewallRule -DisplayName "CyberBlock_{ip}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "{reason}"')
            lines.append('Write-Host "Barcha xavfli IP lar Windows Firewall orqali bloklandi!" -ForegroundColor Green')
            return "\n".join(lines)

        elif platform == "windows_bat":
            lines = ["@echo off", ":: Windows Firewall Netsh Bloklash Skripti", ""]
            for ip in clean_ips:
                lines.append(f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}')
            lines.append('echo Barcha xavfli IP lar muvaffaqiyatli bloklandi!')
            lines.append("pause")
            return "\n".join(lines)

        elif platform == "nginx":
            lines = ["# Nginx server blokiga qo'shish uchun:", ""]
            for ip in clean_ips:
                lines.append(f"deny {ip};")
            return "\n".join(lines)

        return ""

firewall_gen = FirewallGenerator()
