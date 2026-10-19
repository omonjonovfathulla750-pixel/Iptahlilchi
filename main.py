import os
import re
import socket
import json
import time
import struct
import ctypes
import threading
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# Global holat
active_devices_lock = threading.Lock()
current_active_devices = {}
disconnected_history = {}
events_log = []
hostname_cache = {}


def get_public_geolocation():
    try:
        import urllib.request
        with urllib.request.urlopen("http://ip-api.com/json/", timeout=2) as resp:
            data = json.loads(resp.read().decode())
            city = data.get("city", "Tashkent")
            country = data.get("country", "O'zbekiston")
            isp = data.get("isp", "Internet Provayder")
            return f"{city}, {country} ({isp})"
    except Exception:
        return "Tashkent, O'zbekiston (Lokal Tizim)"


def get_local_ip_and_gateway():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return local_ip, gw
    except Exception:
        return "192.168.0.107", "192.168.0.1"


# Windows native Layer-2 SendARP chaqiruvi (Tarmoqdagi real apparat darajasidagi tekshiruv)
def send_arp_probe(ip_str: str):
    try:
        inet_addr = struct.unpack("!I", socket.inet_aton(ip_str))[0]
        mac = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(
            socket.htonl(inet_addr), 0, ctypes.byref(mac), ctypes.byref(mac_len)
        )
        if res == 0:
            mac_str = ":".join(f"{b & 0xFF:02X}" for b in mac)
            return mac_str
    except Exception:
        pass
    return None


def resolve_hostname(ip_str: str):
    if ip_str in hostname_cache:
        return hostname_cache[ip_str]
    try:
        socket.setdefaulttimeout(0.4)
        name, _, _ = socket.gethostbyaddr(ip_str)
        hostname_cache[ip_str] = name
        return name
    except Exception:
        hostname_cache[ip_str] = None
        return None


def check_single_port(ip_str: str, port: int, timeout=0.35):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip_str, port))
        s.close()
        return res == 0
    except Exception:
        return False


def classify_device(ip_str: str, mac_str: str, local_ip: str, gw_ip: str):
    prefix = mac_str[:8].upper()
    try:
        first_byte = int(mac_str[:2], 16)
        is_random_mac = bool(first_byte & 2)
    except Exception:
        is_random_mac = False

    hostname = resolve_hostname(ip_str)
    upper_host = (hostname or "").upper()

    # 1. Asosiy Wi-Fi Router (Shlyuz)
    if ip_str == gw_ip or ip_str.endswith(".1") or ip_str.endswith(".254") or "C0:4A:00" in prefix:
        return {
            "name": "Asosiy Wi-Fi Router / Shlyuz",
            "device_name": "Wi-Fi Router (Shlyuz Uskunasi)",
            "category": "Tarmoq Uskunasi (Router)",
            "source": "Wi-Fi & Ethernet LAN Asosiy Boshqaruv",
            "type_icon": "🌐",
            "owner": "Tarmoq Administratsiyasi / Provayder",
            "location": "Markaziy Server Xona / Wi-Fi Nuqtasi",
            "description": "Butun lokal tarmoqqa internet tarqatuvchi va simli/simsiz qurilmalarni boshqaruvchi asosiy shlyuz.",
        }

    # 2. Ushbu Kompyuter (Host PC)
    if ip_str == local_ip:
        pc_name = hostname or "DESKTOP-A82U46C"
        return {
            "name": f"Ushbu Kompyuter ({pc_name})",
            "device_name": f"{pc_name} — Boshqaruv Kompyuteri (Host)",
            "category": "Kompyuter (Host PC)",
            "source": "Ethernet LAN Kabel / Wi-Fi",
            "type_icon": "💻",
            "owner": "Siz (Administrator)",
            "location": "Asosiy Ishchi O'rningiz",
            "description": "Hozirgi server va tarmoq monitoring tizimi ishlayotgan shaxsiy kompyuter.",
        }

    # 3. Kompyuterlar (Windows, Linux, Noutbuklar - LAN kabel yoki Wi-Fi)
    is_pc = bool(upper_host and (
        upper_host.startswith("WIN-") or 
        upper_host.startswith("DESKTOP-") or 
        upper_host.startswith("LAPTOP-") or 
        "HOME-PC" in upper_host or
        re.search(r'\bPC\b|\bLAPTOP\b', upper_host)
    ))
    if is_pc:
        return {
            "name": f"{hostname} (Simli LAN / Wi-Fi Kompyuter)",
            "device_name": f"{hostname} — Ishchi Kompyuter / Noutbuk",
            "category": "Kompyuter (LAN kabel / Noutbuk)",
            "source": "Ethernet LAN Kabel orqali (Simli)",
            "type_icon": "🖥️",
            "owner": "Ofis / Ishchi O'rin Foydalanuvchisi",
            "location": "Lokal Ishchi Zonasida",
            "description": "Tarmoqqa sim orqali (LAN kabel) yoki Wi-Fi adapter orqali ulangan ishchi kompyuter.",
        }

    # 4. Android Smart TV / Televizorlar
    tv_prefixes = ["84:C8:A0", "00:08:22", "64:1C:67", "50:85:69", "AC:C1:EE"]
    is_tv = any(p in prefix for p in tv_prefixes) or bool(upper_host and (
        "SMART-TV" in upper_host or "ANDROIDTV" in upper_host or "BRAVIA" in upper_host or
        "HISENSE" in upper_host or "TCL" in upper_host or "SKYWORTH" in upper_host or
        "MI-TV" in upper_host or re.search(r'\bTV\b', upper_host)
    ))
    if is_tv:
        return {
            "name": f"Android Smart TV / Televizor (IP: {ip_str})",
            "device_name": f"Smart TV (Android OS, IP: {ip_str})",
            "category": "Android Smart TV / Televizor",
            "source": "Wi-Fi (5 GHz / 2.4 GHz)",
            "type_icon": "📺",
            "owner": "Umumiy Foydalanishdagi Televizor",
            "location": "Zal / Televizor Paneli",
            "description": "Android TV / Smart tizimida ishlovchi televizor. Wi-Fi orqali media oqimiga ulangan.",
        }

    # 5. Smartfonlar (Android / Apple iOS - Maxfiy MAC)
    if is_random_mac:
        return {
            "name": f"Smartfon / Mobil Gadjet (Android / iOS)",
            "device_name": f"Smartfon / Mobil Telefon (IP: {ip_str})",
            "category": "Smartfon / Mobil",
            "source": "Wi-Fi (Maxfiy / Xususiy MAC manzil)",
            "type_icon": "📱",
            "owner": "Mobil Foydalanuvchi",
            "location": "Wi-Fi Qamrovi Hududida",
            "description": "Android yoki Apple tizimidagi mobil smartfon. Wi-Fi tarmog'iga himoyalangan xususiy MAC bilan ulangan.",
        }

    # 6. Umumiy boshqa qurilma
    dev_title = hostname or f"Qurilma ({ip_str})"
    return {
        "name": f"{dev_title} (Lokal Tarmoq)",
        "device_name": f"Lokal Tarmoq Tuguni ({ip_str})",
        "category": "Lokal Tarmoq Qurilmasi",
        "source": "Wi-Fi / Ethernet LAN",
        "type_icon": "⚡",
        "owner": "Tarmoq Foydalanuvchisi",
        "location": "Lokal Segment",
        "description": "Tarmoqqa ulangan va ayni vaqtda faol javob berayotgan apparat vositasi.",
    }


def scan_subnet_once():
    global current_active_devices, disconnected_history, events_log
    local_ip, gw_ip = get_local_ip_and_gateway()
    parts = local_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}" if len(parts) == 4 else "192.168.0"

    ips_to_scan = [f"{subnet}.{i}" for i in range(1, 255)]
    detected_now = {}

    def worker(ip):
        mac = send_arp_probe(ip)
        return (ip, mac) if mac else (ip, None)

    with ThreadPoolExecutor(max_workers=250) as executor:
        results = list(executor.map(worker, ips_to_scan))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    found_devices = [(ip, mac) for ip, mac in results if mac]
    def classify_worker(item):
        ip, mac = item
        meta = classify_device(ip, mac, local_ip, gw_ip)
        return (ip, mac, meta)

    with ThreadPoolExecutor(max_workers=30) as meta_executor:
        classified_list = list(meta_executor.map(classify_worker, found_devices))

    for ip, mac, meta in classified_list:
        detected_now[ip] = {
            "ip": ip,
            "mac": mac,
            "name": meta["name"],
            "device_name": meta["device_name"],
            "category": meta["category"],
            "source": meta["source"],
            "type_icon": meta["type_icon"],
            "owner": meta["owner"],
            "location": meta["location"],
            "description": meta["description"],
            "status": "Faol (Online)",
            "status_time": f"{now_str} (Faol)",
            "connected_time": now_str,
            "online": True,
        }

    with active_devices_lock:
        old_ips = set(current_active_devices.keys())
        new_ips = set(detected_now.keys())

        # Yangi ulanganlar
        for ip in (new_ips - old_ips):
            dev = detected_now[ip]
            events_log.insert(0, {
                "time": now_str,
                "type": "connected",
                "message": f"🟢 {dev['name']} ({ip}) tarmoqqa ulandi",
                "ip": ip,
            })
            if len(events_log) > 50:
                events_log.pop()

        # Uzilganlar (avtomatik ro'yxatdan chiqadi)
        for ip in (old_ips - new_ips):
            dev = current_active_devices[ip]
            events_log.insert(0, {
                "time": now_str,
                "type": "disconnected",
                "message": f"⚠️ {dev['name']} ({ip}) tarmoqdan uzildi",
                "ip": ip,
            })
            disconnected_history[ip] = {
                **dev,
                "status": "Tarmoqdan uzildi (Offline)",
                "status_time": f"{now_str} (Uzilgan)",
                "online": False,
            }
            if len(events_log) > 50:
                events_log.pop()

        current_active_devices = detected_now


def background_scanner_thread():
    while True:
        try:
            scan_subnet_once()
        except Exception:
            pass
        time.sleep(3.5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fon skanerni darhol ishga tushirish
    t = threading.Thread(target=background_scanner_thread, daemon=True)
    t.start()
    yield


app = FastAPI(
    title="Tarmoq Qurilmalarini Aniq va Chuqur Tahlil Qilish Tizimi",
    lifespan=lifespan
)


# ========================================================
# 🚀 5 TA ULASH VA TEKSHIRISH FUNKSIYALARI (API ENDPOINTLARI)
# ========================================================

# 1. Buyruqlar satri orqali tekshirish (Ping)
@app.get("/api/device/ping")
def api_device_ping(ip: str = Query(...)):
    ip = ip.strip()
    try:
        res = subprocess.run(["ping", "-n", "3", "-w", "600", ip], capture_output=True, text=True)
        out = res.stdout
        success = (res.returncode == 0)
        ttls = re.findall(r"TTL=(\d+)", out, re.IGNORECASE)
        times = re.findall(r"(\d+)\s*(?:ms|мсек)", out, re.IGNORECASE)
        loss_m = re.search(r"\((\d+)%", out)
        loss = f"{loss_m.group(1)}%" if loss_m else ("0%" if success else "100%")
        avg_ms = f"{sum(int(t) for t in times) // len(times)} ms" if times else ("0 ms" if success else "-")

        status_text = "🟢 Aloqa barqaror (Online)" if success else "🔴 Javob bermadi (Offline / Firewall)"
        return {
            "success": success,
            "ip": ip,
            "loss": loss,
            "avg_ms": avg_ms,
            "ttl": ttls[0] if ttls else "-",
            "replies": len(ttls),
            "status_text": status_text,
            "raw_output": out.strip()
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


# 2. Xizmatlar va Portlar tekshiruvi (HTTP, SMB, RDP, SSH, API)
@app.get("/api/device/ports")
def api_device_ports(ip: str = Query(...)):
    ip = ip.strip()
    target_ports = [
        {"port": 80, "name": "HTTP", "desc": "Veb-brauzer / Router Paneli", "icon": "🌐"},
        {"port": 443, "name": "HTTPS", "desc": "Xavfsiz Veb-sayt (SSL)", "icon": "🔒"},
        {"port": 445, "name": "SMB", "desc": "Tarmoq Papkalari (File Sharing)", "icon": "📁"},
        {"port": 3389, "name": "RDP", "desc": "Masofaviy Ish Stoli (Remote Desktop)", "icon": "🖥️"},
        {"port": 22, "name": "SSH", "desc": "Masofaviy Terminal Konsoli", "icon": "💻"},
        {"port": 8080, "name": "HTTP-Alt", "desc": "Veb-kamera / Proksi / Panel", "icon": "📹"},
        {"port": 8000, "name": "Web API", "desc": "FastAPI / Django Backend", "icon": "⚡"},
        {"port": 53, "name": "DNS", "desc": "Domen Nomlari Xizmati", "icon": "🔍"},
    ]

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_single_port, ip, p["port"]): p for p in target_ports}
        for f in futures:
            p_info = futures[f]
            is_open = f.result()
            results.append({
                **p_info,
                "is_open": is_open,
                "status": "OCHIQ (Faol)" if is_open else "Yopiq"
            })

    results.sort(key=lambda x: x["port"])
    open_count = sum(1 for r in results if r["is_open"])
    return {
        "success": True,
        "ip": ip,
        "open_count": open_count,
        "ports": results
    }


# 3. Masofaviy ish stoli (RDP) faylini yuklab berish
@app.get("/api/device/rdp")
def api_device_rdp(ip: str = Query(...)):
    ip = ip.strip()
    rdp_content = f"full address:s:{ip}\nprompt for credentials:i:1\nadministrative session:i:1\n"
    return Response(
        content=rdp_content,
        media_type="application/x-rdp",
        headers={"Content-Disposition": f"attachment; filename=remote_{ip}.rdp"}
    )


# 4. Ro'yxatni olish
@app.get("/devices")
def get_devices():
    with active_devices_lock:
        return list(current_active_devices.values())


# 5. API Skan holati
@app.get("/api/scan")
def api_scan():
    local_ip, gw_ip = get_local_ip_and_gateway()
    parts = local_ip.split(".")
    subnet_desc = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24 (Real Wi-Fi & LAN)"

    with active_devices_lock:
        devices = list(current_active_devices.values())
        events = list(events_log[:20])
        disconnected = list(disconnected_history.values())

    return {
        "success": True,
        "searched_ip": local_ip,
        "total_devices": f"{len(devices)} ta real qurilma ayni vaqtda ulangan",
        "subnet": subnet_desc,
        "devices": devices,
        "disconnected": disconnected,
        "events": events,
    }


@app.get("/api/device/disconnect")
def api_disconnect_device(ip: str = Query(...)):
    ip = ip.strip()
    with active_devices_lock:
        if ip in current_active_devices:
            dev = current_active_devices.pop(ip)
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            disconnected_history[ip] = {
                **dev,
                "status": "Tarmoqdan uzildi (Offline)",
                "status_time": f"{now_str} (Uzilgan)",
                "online": False,
            }
            events_log.insert(0, {
                "time": now_str,
                "type": "disconnected",
                "message": f"⚠️ {dev['name']} ({ip}) tarmoqdan uzildi",
                "ip": ip,
            })
            return {"success": True, "message": f"{ip} uzildi"}
    return {"success": False, "message": "Qurilma topilmadi"}


# ========================================================
# 🎨 WEB INTERFEYS VA HAR BIR QURILMA UCHUN TUGMALAR
# ========================================================
@app.get("/", response_class=HTMLResponse)
def index():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>index.html fayli topilmadi</h1>"


@app.get("/sakinah", response_class=HTMLResponse)
@app.get("/sakinah.html", response_class=HTMLResponse)
def sakinah_page():
    html_path = os.path.join(os.path.dirname(__file__), "sakinah.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>sakinah.html fayli topilmadi</h1>"


@app.get("/email_osint", response_class=HTMLResponse)
@app.get("/email_osint.html", response_class=HTMLResponse)
def email_osint_page():
    html_path = os.path.join(os.path.dirname(__file__), "email_osint.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>email_osint.html fayli topilmadi</h1>"


@app.get("/dns_analyzer", response_class=HTMLResponse)
@app.get("/dns_analyzer.html", response_class=HTMLResponse)
def dns_analyzer_page():
    html_path = os.path.join(os.path.dirname(__file__), "dns_analyzer.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>dns_analyzer.html fayli topilmadi</h1>"


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
