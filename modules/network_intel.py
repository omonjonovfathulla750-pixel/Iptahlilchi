"""
Network Intelligence Module - Chuqur Tarmoq Tahlili, WHOIS, Port Scanner va Subnet Kalkulyator.
"""

import socket
import ipaddress
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from .cache_manager import cache

COMMON_PORTS = [
    {"port": 21, "name": "FTP", "service": "Fayl Uzatish Protokoli", "protocol": "TCP"},
    {"port": 22, "name": "SSH", "service": "Xavfsiz Masofaviy Konsol", "protocol": "TCP"},
    {"port": 23, "name": "Telnet", "service": "Masofaviy Matnli Konsol (Xavfli)", "protocol": "TCP"},
    {"port": 25, "name": "SMTP", "service": "Pochta Yuborish Xizmati", "protocol": "TCP"},
    {"port": 53, "name": "DNS", "service": "Domen Nomlari Xizmati", "protocol": "TCP/UDP"},
    {"port": 80, "name": "HTTP", "service": "Veb Server / Veb Sayt", "protocol": "TCP"},
    {"port": 110, "name": "POP3", "service": "Pochta Qabul Qilish", "protocol": "TCP"},
    {"port": 135, "name": "MSRPC", "service": "Windows Masofaviy Boshqaruv", "protocol": "TCP"},
    {"port": 139, "name": "NetBIOS", "service": "Windows Tarmoq Fayllari", "protocol": "TCP"},
    {"port": 143, "name": "IMAP", "service": "Internet Pochta Protokoli", "protocol": "TCP"},
    {"port": 443, "name": "HTTPS", "service": "Xavfsiz Veb Server (SSL/TLS)", "protocol": "TCP"},
    {"port": 445, "name": "SMB", "service": "Windows File Sharing / Samba", "protocol": "TCP"},
    {"port": 1433, "name": "MSSQL", "service": "Microsoft SQL Server", "protocol": "TCP"},
    {"port": 1521, "name": "Oracle", "service": "Oracle Ma'lumotlar Bazasi", "protocol": "TCP"},
    {"port": 3306, "name": "MySQL", "service": "MySQL / MariaDB Bazasi", "protocol": "TCP"},
    {"port": 3389, "name": "RDP", "service": "Masofaviy Ish Stoli (Windows)", "protocol": "TCP"},
    {"port": 5432, "name": "PostgreSQL", "service": "PostgreSQL Ma'lumotlar Bazasi", "protocol": "TCP"},
    {"port": 5900, "name": "VNC", "service": "Masofaviy Ekran Boshqaruvi", "protocol": "TCP"},
    {"port": 6379, "name": "Redis", "service": "Redis Kesh / Baza (Xavfli agar ochiq bo'lsa)", "protocol": "TCP"},
    {"port": 8080, "name": "HTTP-Proxy", "service": "Muqobil Veb Server / Kamera / Tomcat", "protocol": "TCP"},
    {"port": 8443, "name": "HTTPS-Alt", "service": "Muqobil SSL Veb Server", "protocol": "TCP"},
    {"port": 9000, "name": "Portainer/PHP", "service": "Docker Portainer / PHP-FPM", "protocol": "TCP"},
    {"port": 9200, "name": "Elasticsearch", "service": "Elasticsearch Qidiruv Tizimi", "protocol": "TCP"},
    {"port": 27017, "name": "MongoDB", "service": "MongoDB Hujjatli Bazasi", "protocol": "TCP"}
]

class NetworkIntelligence:
    def __init__(self):
        pass

    def get_full_ip_details(self, ip_str: str):
        """IP manzilning to'liq geografik, provayder va ASN ma'lumotlarini olish"""
        cache_key = f"ip_details_{ip_str}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        # IP formatini tozalash
        ip_str = ip_str.strip()

        # Dastlabki qiymatlar
        details = {
            "query": ip_str,
            "status": "success",
            "country": "O'zbekiston",
            "countryCode": "UZ",
            "region": "TO",
            "regionName": "Toshkent",
            "city": "Toshkent",
            "zip": "100000",
            "lat": 41.2995,
            "lon": 69.2401,
            "timezone": "Asia/Tashkent",
            "isp": "Lokal Tarmoq",
            "org": "Lokal Tarmoq Tashkiloti",
            "as": "AS Noma'lum",
            "asname": "Lokal",
            "reverse": "",
            "is_private": False,
            "cidr_range": "Noma'lum",
            "abuse_email": "abuse@isp.uz"
        }

        # Xususiy IP tekshiruvi
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                details["is_private"] = True
                details["isp"] = "Lokal Ichki Tarmoq (LAN)"
                details["org"] = "Mahalliy Router / Switch"
                details["as"] = "Xususiy Tarmoq (RFC 1918)"
                details["reverse"] = "local.network"
                cache.set(cache_key, details, ttl_seconds=3600, category="network")
                return details
        except ValueError:
            pass

        # 1. Reverse DNS (PTR)
        try:
            socket.setdefaulttimeout(1.0)
            host, _, _ = socket.gethostbyaddr(ip_str)
            details["reverse"] = host
        except Exception:
            details["reverse"] = "Topilmadi"

        # 2. ip-api.com orqali to'liq geolokatsiya
        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            resp = requests.get(url, timeout=3.5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    details.update(data)
        except Exception:
            pass

        # 3. RDAP orqali WHOIS / Abuse ma'lumotlarini to'ldirish
        try:
            rdap_url = f"https://rdap.arin.net/registry/ip/{ip_str}"
            rdap_resp = requests.get(rdap_url, timeout=3.0, headers={"Accept": "application/json"})
            if rdap_resp.status_code == 200:
                rdap_data = rdap_resp.json()
                if "handle" in rdap_data:
                    details["cidr_range"] = rdap_data.get("handle", "")
                # Abuse email qidirish
                for ent in rdap_data.get("entities", []):
                    for sub in ent.get("entities", []):
                        for item in sub.get("vcardArray", [None, []])[1]:
                            if item[0] == "email":
                                details["abuse_email"] = item[3]
                                break
        except Exception:
            pass

        cache.set(cache_key, details, ttl_seconds=86400, category="network")
        return details

    def grab_banner(self, ip_str: str, port: int, timeout=0.8):
        """Ochiq portdan dastur va versiya ma'lumotlarini (Banner) o'qib olish"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip_str, port))

            # Agar HTTP/HTTPS bo'lsa
            if port in [80, 8080]:
                probe = f"HEAD / HTTP/1.0\r\nHost: {ip_str}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
                s.sendall(probe)
            elif port == 21: # FTP
                pass
            elif port == 22: # SSH o'zi birinchi bo'lib versiya bannerini yuboradi
                pass
            else:
                s.sendall(b"\r\n")

            banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            s.close()

            # Keraksiz bo'shliqlarni tozalash va birinchi qatorni olish
            if banner:
                lines = [line.strip() for line in banner.splitlines() if line.strip()]
                # Agar Server: sarlavhasi bo'lsa
                for line in lines:
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                    if line.lower().startswith("ssh-"):
                        return line
                return lines[0][:80]
        except Exception:
            pass
        return None

    def scan_ports(self, ip_str: str, custom_ports=None):
        """IP dagi portlarni tekshirish va bannerlarni o'qish"""
        ports_to_scan = custom_ports or COMMON_PORTS
        results = []

        def worker(p_info):
            port = p_info["port"]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                res = s.connect_ex((ip_str, port))
                s.close()
                is_open = (res == 0)
                banner = None
                if is_open:
                    banner = self.grab_banner(ip_str, port)
                return {
                    **p_info,
                    "is_open": is_open,
                    "status": "OCHIQ (Faol)" if is_open else "Yopiq",
                    "banner": banner or ("Standart Xizmat" if is_open else "-")
                }
            except Exception:
                return {
                    **p_info,
                    "is_open": False,
                    "status": "Yopiq",
                    "banner": "-"
                }

        with ThreadPoolExecutor(max_workers=20) as executor:
            scanned = list(executor.map(worker, ports_to_scan))

        scanned.sort(key=lambda x: x["port"])
        open_count = sum(1 for r in scanned if r["is_open"])
        return {
            "ip": ip_str,
            "total_scanned": len(scanned),
            "open_count": open_count,
            "ports": scanned
        }

    def calculate_subnet(self, cidr_str: str):
        """Subnet va CIDR kalkulyatori"""
        try:
            cidr_str = cidr_str.strip()
            # Agar oddiy IP berilsa, masalan 192.168.1.1 -> /32 yoki /24 ga moslash
            if "/" not in cidr_str:
                cidr_str = f"{cidr_str}/24"

            net = ipaddress.ip_network(cidr_str, strict=False)
            total_hosts = net.num_addresses
            usable_hosts = max(0, total_hosts - 2) if net.prefixlen < 31 else total_hosts

            first_ip = str(net.network_address + 1) if usable_hosts > 0 else str(net.network_address)
            last_ip = str(net.broadcast_address - 1) if usable_hosts > 0 else str(net.broadcast_address)

            # IP sinfini aniqlash (IPv4 uchun)
            ip_class = "Noma'lum"
            if net.version == 4:
                first_octet = int(str(net.network_address).split(".")[0])
                if 1 <= first_octet <= 126:
                    ip_class = "A Sinif"
                elif 128 <= first_octet <= 191:
                    ip_class = "B Sinif"
                elif 192 <= first_octet <= 223:
                    ip_class = "C Sinif"
                elif 224 <= first_octet <= 239:
                    ip_class = "D Sinif (Multicast)"
                elif 240 <= first_octet <= 255:
                    ip_class = "E Sinif (Eksperimental)"

            return {
                "success": True,
                "input_cidr": cidr_str,
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address) if net.version == 4 else "IPv6 da yo'q",
                "netmask": str(net.netmask),
                "wildcard_mask": str(net.hostmask) if net.version == 4 else "-",
                "prefix_length": net.prefixlen,
                "total_addresses": total_hosts,
                "usable_addresses": usable_hosts,
                "first_usable_ip": first_ip,
                "last_usable_ip": last_ip,
                "ip_version": f"IPv{net.version}",
                "ip_class": ip_class,
                "is_private": net.is_private,
                "is_global": net.is_global
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Noto'g'ri CIDR formati: {str(e)}. Misol: 192.168.1.0/24 yoki 10.0.0.0/16"
            }

network_intel = NetworkIntelligence()
