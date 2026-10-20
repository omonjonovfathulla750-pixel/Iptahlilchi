"""
Threat Intelligence Module - Kiberxavfsizlik, IP Reputatsiyasi va Xavflilik Tahlili.
DNSBL Blacklist, Proxy/VPN/Tor aniqlash va Xavflilik darajasi (Risk Score) hisoblash.
"""

import socket
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from .cache_manager import cache

DNSBL_PROVIDERS = [
    {"name": "Spamhaus ZEN", "host": "zen.spamhaus.org", "desc": "Spam, Botnet va Exploit xavfi"},
    {"name": "Barracuda RBL", "host": "b.barracudacentral.org", "desc": "Spam va shubhali xabarlar"},
    {"name": "SpamCop BL", "host": "bl.spamcop.net", "desc": "Zararli spam serverlar"},
    {"name": "SORBS DNSBL", "host": "dnsbl.sorbs.net", "desc": "Shubhali va spam proksilar"},
    {"name": "Abuseat CBL", "host": "cbl.abuseat.org", "desc": "Zararlangan botnet viruslar"}
]

class ThreatIntelligence:
    def __init__(self, abuseipdb_key: str = None):
        self.abuseipdb_key = abuseipdb_key

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def check_dnsbl_single(self, ip_str: str, provider: dict):
        try:
            # IPv4 ni teskarisiga aylantirish (masalan: 1.2.3.4 -> 4.3.2.1.zen.spamhaus.org)
            parts = ip_str.split('.')
            if len(parts) != 4:
                return None
            rev_ip = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.{provider['host']}"
            
            socket.setdefaulttimeout(1.2)
            res = socket.gethostbyname(rev_ip)
            if res.startswith("127.0.0."):
                return {
                    "provider": provider["name"],
                    "host": provider["host"],
                    "desc": provider["desc"],
                    "listed": True,
                    "return_code": res
                }
        except Exception:
            pass
        return {
            "provider": provider["name"],
            "host": provider["host"],
            "desc": provider["desc"],
            "listed": False
        }

    def check_all_dnsbl(self, ip_str: str):
        if self.is_private_ip(ip_str):
            return []
        
        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.check_dnsbl_single, ip_str, p) for p in DNSBL_PROVIDERS]
            for f in futures:
                res = f.result()
                if res:
                    results.append(res)
        return results

    def get_ip_reputation(self, ip_str: str, user_api_key: str = None):
        # Keshni tekshirish
        cache_key = f"threat_{ip_str}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        # Lokal/Xususiy IP bo'lsa
        if self.is_private_ip(ip_str):
            res = {
                "ip": ip_str,
                "is_private": True,
                "risk_score": 0,
                "risk_level": "Lokal Tarmoq (Xavfsiz)",
                "risk_color": "#22c55e",
                "risk_badge": "SAFE",
                "is_vpn": False,
                "is_proxy": False,
                "is_tor": False,
                "is_datacenter": False,
                "dnsbl_listed_count": 0,
                "dnsbl_details": [],
                "abuse_score": 0,
                "reports_count": 0,
                "summary": "Ushbu manzil lokal ichki tarmoqqa (LAN) tegishli."
            }
            cache.set(cache_key, res, ttl_seconds=3600, category="threat")
            return res

        # 1. ip-api orqali proksi va hostingni aniqlash
        ip_info = {}
        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,city,isp,org,as,mobile,proxy,hosting,query"
            resp = requests.get(url, timeout=3.5)
            if resp.status_code == 200:
                ip_info = resp.json()
        except Exception:
            pass

        is_proxy = ip_info.get("proxy", False)
        is_hosting = ip_info.get("hosting", False)
        is_mobile = ip_info.get("mobile", False)

        # 2. DNSBL Blacklist tekshiruvi
        dnsbl_results = self.check_all_dnsbl(ip_str)
        listed_count = sum(1 for r in dnsbl_results if r.get("listed"))

        # 3. AbuseIPDB (agar kalit kiritilgan bo'lsa)
        api_key = user_api_key or self.abuseipdb_key
        abuse_score = 0
        reports_count = 0
        if api_key:
            try:
                headers = {"Key": api_key, "Accept": "application/json"}
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": ip_str, "maxAgeInDays": "90"}
                a_resp = requests.get(url, headers=headers, params=params, timeout=3.5)
                if a_resp.status_code == 200:
                    a_data = a_resp.json().get("data", {})
                    abuse_score = a_data.get("abuseConfidenceScore", 0)
                    reports_count = a_data.get("totalReports", 0)
            except Exception:
                pass

        # 4. Xavflilik darajasini (Risk Score: 0-100) hisoblash
        calculated_score = 0
        if listed_count > 0:
            calculated_score += listed_count * 25
        if is_proxy:
            calculated_score += 35
        if is_hosting:
            calculated_score += 15
        if abuse_score > 0:
            calculated_score = max(calculated_score, abuse_score)

        calculated_score = min(calculated_score, 100)

        # Daraja va tavsif
        if calculated_score >= 75:
            risk_level = "O'ta Xavfli (Kiberhujum / Botnet)"
            risk_color = "#ef4444" # Qizil
            risk_badge = "DANGEROUS"
        elif calculated_score >= 45:
            risk_level = "Shubhali (Proksi / Hosting / Shubhali faollik)"
            risk_color = "#f97316" # To'q sariq
            risk_badge = "SUSPICIOUS"
        elif calculated_score >= 20:
            risk_level = "O'rtacha ehtiyotkorlik"
            risk_color = "#eab308" # Sariq
            risk_badge = "MEDIUM"
        else:
            risk_level = "Toza / Xavfsiz (Oddiy foydalanuvchi)"
            risk_color = "#22c55e" # Yashil
            risk_badge = "SAFE"

        summary_points = []
        if is_proxy:
            summary_points.append("VPN / Proksi orqali yashiringan")
        if is_hosting:
            summary_points.append("Server / Bulutli hosting (Datacenter) IP manzili")
        if listed_count > 0:
            summary_points.append(f"{listed_count} ta jahon qora ro'yxatida (DNSBL) mavjud")
        if not summary_points:
            summary_points.append("Hech qanday kiberxavfsizlik xavfi aniqlanmadi")

        result = {
            "ip": ip_str,
            "is_private": False,
            "risk_score": calculated_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "risk_badge": risk_badge,
            "is_vpn": is_proxy,
            "is_proxy": is_proxy,
            "is_tor": is_proxy and is_hosting,
            "is_datacenter": is_hosting,
            "is_mobile": is_mobile,
            "dnsbl_listed_count": listed_count,
            "dnsbl_details": dnsbl_results,
            "abuse_score": abuse_score,
            "reports_count": reports_count,
            "summary": "; ".join(summary_points),
            "isp": ip_info.get("isp", "Noma'lum"),
            "org": ip_info.get("org", "Noma'lum"),
            "country": ip_info.get("country", "Noma'lum"),
            "city": ip_info.get("city", "Noma'lum")
        }

        # Keshga saqlash (4 soat)
        cache.set(cache_key, result, ttl_seconds=14400, category="threat")
        return result

threat_intel = ThreatIntelligence()
