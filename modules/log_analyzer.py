"""
Log Analyzer Module - Server loglarini o'qish, IP larni ajratib olish va anomaliyalarni aniqlash.
Nginx, Apache, Linux Auth.log va boshqa server loglari uchun moslashgan.
"""

import re
from collections import Counter
from datetime import datetime

# Xavfli yo'llar va skaner shablonlari
SUSPICIOUS_PATHS = [
    r"/wp-admin", r"/wp-login", r"/xmlrpc\.php",
    r"/\.env", r"/\.git", r"/config\.json",
    r"/phpmyadmin", r"/pma", r"/admin",
    r"/etc/passwd", r"/\.\./", r"/shell",
    r"/actuator", r"/solr", r"/boaform"
]

class LogAnalyzer:
    def __init__(self):
        # IPv4 va IPv6 regex
        self.ip_regex = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        # Nginx/Apache Combined Log formati: 1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /path HTTP/1.1" 200 1234
        self.web_log_regex = re.compile(
            r'^(\S+) \S+ \S+ \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (.*?) HTTP/\d\.\d" (\d{3}) (\d+|-)'
        )
        # Linux SSH auth log: Failed password for invalid user admin from 1.2.3.4 port 22
        self.ssh_fail_regex = re.compile(
            r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
        )

    def extract_ips_from_text(self, text: str):
        """Matndan barcha noyob va takrorlangan IP larni ajratib olish"""
        return self.ip_regex.findall(text)

    def analyze_log_content(self, content: str):
        """To'liq log matnini tahlil qilish va statistik hisobot yaratish"""
        lines = content.strip().splitlines()
        total_lines = len(lines)
        
        all_ips = []
        status_codes = Counter()
        suspicious_events = []
        path_counter = Counter()
        ip_request_counts = Counter()
        ip_error_counts = Counter()
        ssh_brute_force_ips = Counter()

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            # 1. SSH Brute Force urinishlarini aniqlash
            ssh_match = self.ssh_fail_regex.search(line_str)
            if ssh_match:
                user, ip = ssh_match.groups()
                all_ips.append(ip)
                ip_request_counts[ip] += 1
                ssh_brute_force_ips[ip] += 1
                suspicious_events.append({
                    "ip": ip,
                    "type": "SSH Brute-Force",
                    "details": f"Foydalanuvchi '{user}' parolini topishga urinish",
                    "raw": line_str[:120]
                })
                continue

            # 2. Veb server loglarini tahlil qilish
            web_match = self.web_log_regex.search(line_str)
            if web_match:
                ip, ts, method, path, status, size = web_match.groups()
                all_ips.append(ip)
                ip_request_counts[ip] += 1
                status_codes[status] += 1
                path_counter[path] += 1

                # 4xx yoki 5xx xatoliklar
                if status.startswith("4") or status.startswith("5"):
                    ip_error_counts[ip] += 1

                # Zaifliklarni qidirish (Directory Traversal, Admin panellar)
                is_suspicious_path = any(re.search(sp, path, re.IGNORECASE) for sp in SUSPICIOUS_PATHS)
                if is_suspicious_path:
                    suspicious_events.append({
                        "ip": ip,
                        "type": "Exploit / Zaiflik Qidiruvi",
                        "details": f"Shubhali so'rov: {method} {path} [{status}]",
                        "raw": line_str[:120]
                    })
            else:
                # Oddiy IP qidiruvi
                found_ips = self.ip_regex.findall(line_str)
                for f_ip in found_ips:
                    all_ips.append(f_ip)
                    ip_request_counts[f_ip] += 1

        unique_ips = list(set(all_ips))
        top_ips = [{"ip": ip, "count": count} for ip, count in ip_request_counts.most_common(10)]
        top_errors = [{"ip": ip, "error_count": count} for ip, count in ip_error_counts.most_common(10)]
        top_paths = [{"path": path, "count": count} for path, count in path_counter.most_common(10)]

        # Eng shubhali IP lar reytingi
        high_risk_candidates = set(list(ssh_brute_force_ips.keys()) + [e["ip"] for e in suspicious_events])
        suspicious_summary = []
        for s_ip in high_risk_candidates:
            suspicious_summary.append({
                "ip": s_ip,
                "total_requests": ip_request_counts.get(s_ip, 0),
                "failed_auth_count": ssh_brute_force_ips.get(s_ip, 0),
                "error_count": ip_error_counts.get(s_ip, 0),
                "reasons": "SSH hujumi yoki shubhali fayllarni qidirish"
            })

        return {
            "success": True,
            "total_lines_analyzed": total_lines,
            "total_ip_hits": len(all_ips),
            "unique_ip_count": len(unique_ips),
            "top_ips": top_ips,
            "top_paths": top_paths,
            "status_codes": dict(status_codes),
            "top_error_generating_ips": top_errors,
            "suspicious_events_count": len(suspicious_events),
            "suspicious_events": suspicious_events[:25],
            "high_risk_ips": suspicious_summary[:15]
        }

log_analyzer = LogAnalyzer()
