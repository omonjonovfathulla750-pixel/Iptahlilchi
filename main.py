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
    local_ip, gw_ip = get_local_ip_and_gateway()
    geo = get_public_geolocation()

    return f"""<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tarmoq Qurilmalari & Boshqaruv Markazi</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        body {{ background-color: #0b0f19; color: #f8fafc; padding: 22px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        .header {{ 
            background: linear-gradient(135deg, #1e293b, #0f172a); 
            padding: 20px 25px; 
            border-radius: 14px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            border: 1px solid #334155; 
            margin-bottom: 20px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .title {{ font-size: 22px; font-weight: bold; color: #38bdf8; display: flex; align-items: center; gap: 10px; }}
        .geo {{ font-size: 13px; color: #34d399; background: #064e3b; padding: 7px 14px; border-radius: 8px; border: 1px solid #059669; font-weight: 500; }}

        .control-bar {{ 
            background: #1e293b; 
            padding: 16px 22px; 
            border-radius: 12px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            border: 1px solid #334155; 
            margin-bottom: 20px; 
            flex-wrap: wrap;
            gap: 12px;
        }}
        .btn-refresh {{ 
            padding: 10px 22px; 
            background: #0284c7; 
            color: white; 
            border: none; 
            border-radius: 8px; 
            font-weight: bold; 
            cursor: pointer; 
            display: flex; 
            align-items: center; 
            gap: 8px; 
            font-size: 14px;
            transition: all 0.2s; 
        }}
        .btn-refresh:hover {{ background: #0369a1; transform: translateY(-1px); }}

        .pulse-live {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #064e3b;
            color: #34d399;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            border: 1px solid #059669;
        }}
        .dot {{ width: 8px; height: 8px; background: #34d399; border-radius: 50%; display: inline-block; animation: pulse 1.5s infinite; }}
        @keyframes pulse {{
            0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0.7); }}
            70% {{ transform: scale(1); box-shadow: 0 0 0 8px rgba(52, 211, 153, 0); }}
            100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(52, 211, 153, 0); }}
        }}

        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }}
        .stat-card {{ 
            background: #1e293b; 
            padding: 16px; 
            border-radius: 12px; 
            border: 1px solid #334155; 
            text-align: center; 
        }}
        .stat-card h4 {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; margin-bottom: 5px; }}
        .stat-card p {{ font-size: 18px; font-weight: bold; color: #38bdf8; }}

        /* Action Buttons Group */
        .btn-group {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        .btn-action {{
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid #334155;
            background: #0f172a;
            color: #f1f5f9;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            transition: all 0.2s;
            text-decoration: none;
        }}
        .btn-action:hover {{ background: #1e293b; border-color: #38bdf8; transform: translateY(-1px); }}
        .btn-action.btn-web {{ color: #38bdf8; }}
        .btn-action.btn-smb {{ color: #facc15; }}
        .btn-action.btn-rdp {{ color: #a78bfa; }}
        .btn-action.btn-ping {{ color: #4ade80; }}
        .btn-action.btn-port {{ color: #fb923c; }}

        /* Table */
        .table-wrap {{ overflow-x: auto; border-radius: 12px; border: 1px solid #334155; margin-bottom: 22px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; }}
        th, td {{ padding: 14px 16px; text-align: left; font-size: 13px; border-bottom: 1px solid #334155; vertical-align: middle; }}
        th {{ background: #334155; color: #38bdf8; text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.5px; }}
        tr:hover {{ background: #273548; }}
        
        .badge {{ padding: 4px 9px; border-radius: 6px; font-size: 11.5px; font-weight: bold; display: inline-block; }}
        .badge-router {{ background: #1e3a8a; color: #93c5fd; }}
        .badge-pc {{ background: #064e3b; color: #6ee7b7; }}
        .badge-tv {{ background: #701a75; color: #f0abfc; }}
        .badge-phone {{ background: #7c2d12; color: #fdba74; }}
        .badge-general {{ background: #334155; color: #cbd5e1; }}

        /* Modal Styles */
        .modal-overlay {{
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            backdrop-filter: blur(4px);
        }}
        .modal {{
            background: #1e293b;
            border: 1px solid #475569;
            border-radius: 14px;
            width: 90%;
            max-width: 650px;
            padding: 24px;
            color: #f8fafc;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            max-height: 85vh;
            overflow-y: auto;
        }}
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #334155;
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        .modal-title {{ font-size: 17px; font-weight: bold; color: #38bdf8; display: flex; align-items: center; gap: 8px; }}
        .modal-close {{ background: none; border: none; color: #94a3b8; font-size: 22px; cursor: pointer; }}
        .modal-close:hover {{ color: #f87171; }}
        .modal-box {{ background: #0f172a; padding: 14px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 12px; font-size: 13px; line-height: 1.6; }}
        .port-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }}
        .port-card {{ background: #0f172a; border: 1px solid #334155; padding: 10px 12px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .port-open {{ border-color: #059669; background: #064e3b; color: #a7f3d0; }}
        .copy-pill {{ background: #334155; padding: 3px 8px; border-radius: 6px; cursor: pointer; color: #38bdf8; font-size: 11px; }}
        .copy-pill:hover {{ background: #475569; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🌐 Tarmoq Qurilmalari & Boshqaruv Markazi</div>
            <div class="geo">📍 {geo}</div>
        </div>

        <div class="control-bar">
            <div style="display: flex; align-items: center; gap: 14px;">
                <button onclick="refreshDevices()" class="btn-refresh">
                    🔄 Refresh (Yangilash)
                </button>
                <div class="pulse-live">
                    <span class="dot"></span>
                    <span id="scan-status">Jonli Avto-Kuzatuv (3s)</span>
                </div>
            </div>
            <div style="color: #94a3b8; font-size: 13px;">
                Asosiy Shlyuz: <code style="color: #38bdf8;">{gw_ip}</code> | Lokal PC: <code style="color: #38bdf8;">{local_ip}</code>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h4>Jami Ulangan</h4>
                <p id="stat-total">0 ta</p>
            </div>
            <div class="stat-card">
                <h4>Kompyuterlar (LAN / Wi-Fi)</h4>
                <p id="stat-pc" style="color: #6ee7b7;">0 ta</p>
            </div>
            <div class="stat-card">
                <h4>Android Smart TV</h4>
                <p id="stat-tv" style="color: #f0abfc;">0 ta</p>
            </div>
            <div class="stat-card">
                <h4>Smartfonlar / Mobil</h4>
                <p id="stat-phone" style="color: #fdba74;">0 ta</p>
            </div>
        </div>

        <!-- Qurilmalar jadvali va Maxsus Boshqaruv Tugmalari -->
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th style="width: 22%;">Qurilma Nomi</th>
                        <th style="width: 16%;">IP & MAC Manzil</th>
                        <th style="width: 14%;">Kategoriya</th>
                        <th style="width: 16%;">Ulanish Turi</th>
                        <th style="width: 32%;">⚡ Ulanish & Tekshirish Tugmalari</th>
                    </tr>
                </thead>
                <tbody id="deviceTable">
                    <tr><td colspan="5" style="text-align: center; padding: 25px; color: #94a3b8;">Tarmoq qurilmalari aniqlanmoqda...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- PING MODALI -->
    <div id="pingModal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">⚡ Buyruqlar Satri Orqali Tekshirish (Ping)</div>
                <button class="modal-close" onclick="closeModal('pingModal')">&times;</button>
            </div>
            <div id="pingModalBody">
                <div style="text-align: center; padding: 20px; color: #94a3b8;">Paketlar yuborilmoqda, kuting...</div>
            </div>
        </div>
    </div>

    <!-- PORT VA XIZMATLAR MODALI -->
    <div id="portModal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">🔍 Xizmatlar & Portlar Tahlili (API / Xizmatlar)</div>
                <button class="modal-close" onclick="closeModal('portModal')">&times;</button>
            </div>
            <div id="portModalBody">
                <div style="text-align: center; padding: 20px; color: #94a3b8;">Portlar skanerlanmoqda...</div>
            </div>
        </div>
    </div>

    <!-- SMB PAPKA MODALI -->
    <div id="smbModal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">📁 Tarmoq Papkalarini Ulash (SMB / File Sharing)</div>
                <button class="modal-close" onclick="closeModal('smbModal')">&times;</button>
            </div>
            <div id="smbModalBody"></div>
        </div>
    </div>

    <!-- RDP MASOFAVIY ISH STOLI MODALI -->
    <div id="rdpModal" class="modal-overlay">
        <div class="modal">
            <div class="modal-header">
                <div class="modal-title">🖥️ Masofaviy Ish Stoli (RDP / Remote Desktop)</div>
                <button class="modal-close" onclick="closeModal('rdpModal')">&times;</button>
            </div>
            <div id="rdpModalBody"></div>
        </div>
    </div>

    <script>
        let previousDevices = [];

        async function refreshDevices() {{
            const scanStatus = document.getElementById('scan-status');

            try {{
                const res = await fetch('/api/scan');
                const data = await res.json();
                
                const currentDevices = data.devices || [];
                const tbody = document.getElementById('deviceTable');

                // Statistika
                let pcCount = 0, tvCount = 0, phoneCount = 0;
                currentDevices.forEach(d => {{
                    const cat = d.category || '';
                    if (cat.includes('TV') || cat.includes('Televizor')) tvCount++;
                    else if (cat.includes('Smartfon') || cat.includes('Mobil')) phoneCount++;
                    else if (cat.includes('Kompyuter') || cat.includes('PC')) pcCount++;
                }});

                document.getElementById('stat-total').innerText = `${{currentDevices.length}} ta`;
                document.getElementById('stat-pc').innerText = `${{pcCount}} ta`;
                document.getElementById('stat-tv').innerText = `${{tvCount}} ta`;
                document.getElementById('stat-phone').innerText = `${{phoneCount}} ta`;

                // Jadvalni yangilash
                tbody.innerHTML = '';
                if (currentDevices.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 25px; color: #94a3b8;">Tarmoqda faol qurilmalar topilmadi</td></tr>';
                }} else {{
                    currentDevices.forEach(dev => {{
                        let badgeClass = 'badge-general';
                        if (dev.category.includes('Router')) badgeClass = 'badge-router';
                        else if (dev.category.includes('TV')) badgeClass = 'badge-tv';
                        else if (dev.category.includes('Smartfon')) badgeClass = 'badge-phone';
                        else if (dev.category.includes('Kompyuter')) badgeClass = 'badge-pc';

                        const row = `<tr>
                            <td>
                                <b>${{dev.type_icon || '💻'}} ${{dev.name}}</b><br>
                                <span style="color: #94a3b8; font-size: 11px;">👤 ${{dev.owner}}</span>
                            </td>
                            <td>
                                <code style="color: #38bdf8; font-weight: bold; font-size: 13px;">${{dev.ip}}</code><br>
                                <code style="color: #94a3b8; font-size: 11.5px;">${{dev.mac}}</code>
                            </td>
                            <td>
                                <span class="badge ${{badgeClass}}">${{dev.category}}</span>
                            </td>
                            <td>
                                <span style="color: #f1f5f9; font-size: 12.5px;">${{dev.source}}</span><br>
                                <span style="color: #4ade80; font-size: 11px;">🟢 ${{dev.status}}</span>
                            </td>
                            <td>
                                <div class="btn-group">
                                    <!-- 1. Veb-brauzer orqali kirish -->
                                    <a href="http://${{dev.ip}}" target="_blank" class="btn-action btn-web" title="Brauzer orqali veb-interfeysga ulanish">
                                        🌐 Veb
                                    </a>

                                    <!-- 2. Tarmoq papkalarini ulash (SMB) -->
                                    <button onclick="openSmbModal('${{dev.ip}}', '${{escapeHtml(dev.name)}}')" class="btn-action btn-smb" title="Tarmoq papkalariga (SMB) ulanish">
                                        📁 SMB
                                    </button>

                                    <!-- 3. Masofaviy ish stoli (RDP) -->
                                    <button onclick="openRdpModal('${{dev.ip}}', '${{escapeHtml(dev.name)}}')" class="btn-action btn-rdp" title="Remote Desktop orqali ulanish">
                                        🖥️ RDP
                                    </button>

                                    <!-- 4. Buyruqlar satri orqali tekshirish (Ping) -->
                                    <button onclick="runPingTest('${{dev.ip}}', '${{escapeHtml(dev.name)}}')" class="btn-action btn-ping" title="Buyruqlar satrida (Ping) aloqani tekshirish">
                                        ⚡ Ping
                                    </button>

                                    <!-- 5. Maxsus dasturlar va API (Portlar) -->
                                    <button onclick="scanDevicePorts('${{dev.ip}}', '${{escapeHtml(dev.name)}}')" class="btn-action btn-port" title="Portlar, API va xizmatlarni tekshirish">
                                        🔍 Portlar
                                    </button>
                                </div>
                            </td>
                        </tr>`;
                        tbody.innerHTML += row;
                    }});
                }}

                scanStatus.innerText = "Jonli Avto-Kuzatuv (3s)";
            }} catch(e) {{
                scanStatus.innerText = "Kutish rejimida";
            }}
        }}

        // ==========================================
        // 🛠️ MODAL VA FUNKSIYALAR KODI
        // ==========================================

        function closeModal(id) {{
            document.getElementById(id).style.display = 'none';
        }}

        function escapeHtml(str) {{
            return (str || '').replace(/'/g, "\\'");
        }}

        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text);
            alert("Nusxalandi: " + text);
        }}

        // 1. PING TEKSHIRISH
        async function runPingTest(ip, name) {{
            document.getElementById('pingModal').style.display = 'flex';
            const body = document.getElementById('pingModalBody');
            body.innerHTML = `
                <div class="modal-box">
                    <b>Tekshirilayotgan Qurilma:</b> ${{name}} (<code style="color: #38bdf8;">${{ip}}</code>)<br>
                    <span>ICMP echo signallari (ping) yuborilmoqda, kuting...</span>
                </div>
            `;

            try {{
                const res = await fetch(`/api/device/ping?ip=${{encodeURIComponent(ip)}}`);
                const data = await res.json();

                body.innerHTML = `
                    <div class="modal-box" style="border-left: 4px solid ${{data.success ? '#34d399' : '#f87171'}};">
                        <h4 style="color: ${{data.success ? '#34d399' : '#f87171'}}; margin-bottom: 8px;">
                            ${{data.status_text}}
                        </h4>
                        <div>🎯 <b>IP manzil:</b> ${{data.ip}}</div>
                        <div>📊 <b>Paket yo'qotilishi (Loss):</b> <span style="color: #38bdf8;">${{data.loss}}</span></div>
                        <div>⏱️ <b>O'rtacha kechikish (Latency):</b> <span style="color: #4ade80;">${{data.avg_ms}}</span></div>
                        <div>📦 <b>TTL ko'rsatkichi:</b> ${{data.ttl}} | Qabul qilindi: ${{data.replies}}/3 ta</div>
                    </div>
                    <div style="font-size: 11.5px; color: #94a3b8; margin-top: 8px;">
                        Terminaldagi xom natija:<br>
                        <pre style="background: #0f172a; padding: 10px; border-radius: 6px; overflow-x: auto; color: #cbd5e1; margin-top: 4px;">${{data.raw_output || 'Maʼlumot yoʻq'}}</pre>
                    </div>
                `;
            }} catch(err) {{
                body.innerHTML = `<div class="modal-box" style="color: #f87171;">Xatolik: ${{err.message}}</div>`;
            }}
        }}

        // 2. PORTLAR VA XIZMATLARNI TEKSHIRISH
        async function scanDevicePorts(ip, name) {{
            document.getElementById('portModal').style.display = 'flex';
            const body = document.getElementById('portModalBody');
            body.innerHTML = `
                <div class="modal-box">
                    <b>Qurilma:</b> ${{name}} (<code>${{ip}}</code>)<br>
                    <span>HTTP, HTTPS, SMB, RDP, SSH, API portlari tekshirilmoqda...</span>
                </div>
            `;

            try {{
                const res = await fetch(`/api/device/ports?ip=${{encodeURIComponent(ip)}}`);
                const data = await res.json();

                let portCardsHtml = '';
                data.ports.forEach(p => {{
                    portCardsHtml += `
                        <div class="port-card ${{p.is_open ? 'port-open' : ''}}">
                            <div>
                                <b>${{p.icon}} Port ${{p.port}}</b> (${{p.name}})<br>
                                <span style="font-size: 11px; opacity: 0.8;">${{p.desc}}</span>
                            </div>
                            <div>
                                <span style="font-weight: bold; font-size: 11.5px;">${{p.is_open ? '🟢 OCHIQ' : '🔴 Yopiq'}}</span>
                            </div>
                        </div>
                    `;
                }});

                body.innerHTML = `
                    <div class="modal-box">
                        <b>Qurilma:</b> ${{name}} (<code style="color: #38bdf8;">${{ip}}</code>)<br>
                        <span>Jami ochiq xizmatlar: <b style="color: #34d399;">${{data.open_count}} ta port faol</b></span>
                    </div>
                    <div class="port-grid">
                        ${{portCardsHtml}}
                    </div>
                    <div class="modal-box" style="margin-top: 14px; font-size: 12px;">
                        💡 <b>API orqali so'rov yuborish (Python / cURL):</b><br>
                        <code>curl http://${{ip}}/</code> yoki Python: <code>requests.get("http://${{ip}}/")</code>
                    </div>
                `;
            }} catch(err) {{
                body.innerHTML = `<div class="modal-box" style="color: #f87171;">Xatolik: ${{err.message}}</div>`;
            }}
        }}

        // 3. SMB (TARMOQ PAPKALARI)
        function openSmbModal(ip, name) {{
            document.getElementById('smbModal').style.display = 'flex';
            const body = document.getElementById('smbModalBody');
            const smbPath = `\\\\${{ip}}`;
            body.innerHTML = `
                <div class="modal-box">
                    <b>Qurilma:</b> ${{name}} (<code style="color: #38bdf8;">${{ip}}</code>)<br>
                    Windows yoki tarmoq umumiy fayllariga kirish yo'li:
                    <div style="display: flex; gap: 8px; margin-top: 8px; align-items: center;">
                        <input type="text" value="${{smbPath}}" readonly style="background: #1e293b; border: 1px solid #475569; color: #facc15; padding: 8px 12px; border-radius: 6px; font-weight: bold; width: 70%;">
                        <button onclick="copyToClipboard('${{smbPath}}')" class="copy-pill" style="padding: 8px 14px; font-weight: bold;">📋 Manzilni Nusxalash</button>
                    </div>
                </div>
                <div class="modal-box" style="font-size: 12.5px;">
                    📝 <b>Qanday ulaniladi?</b><br>
                    1. Klaviaturada <b>Win + R</b> tugmalarini bosing.<br>
                    2. Chiqqan oynaga <code>${{smbPath}}</code> manzilini qo'ying va <b>Enter</b> bosing.<br>
                    3. Agar umumiy papkalar ochiq bo'lsa, Windows Explorer fayllarni ko'rsatadi.
                </div>
            `;
        }}

        // 4. RDP (MASOFAVIY ISH STOLI)
        function openRdpModal(ip, name) {{
            document.getElementById('rdpModal').style.display = 'flex';
            const body = document.getElementById('rdpModalBody');
            const rdpCmd = `mstsc /v:${{ip}}`;
            body.innerHTML = `
                <div class="modal-box">
                    <b>Qurilma:</b> ${{name}} (<code style="color: #38bdf8;">${{ip}}</code>)<br>
                    Masofaviy ish stoliga 2 xil usulda ulanishingiz mumkin:
                </div>
                <div class="modal-box" style="border-left: 4px solid #a78bfa;">
                    <b>1-usul: Tayyor RDP faylni yuklab olish (1 bosish bilan ulanish):</b><br>
                    <a href="/api/device/rdp?ip=${{encodeURIComponent(ip)}}" class="btn-action btn-rdp" style="margin-top: 8px; padding: 8px 16px;">
                        📥 .RDP Faylni Yuklab Olish (Ulanish)
                    </a>
                </div>
                <div class="modal-box">
                    <b>2-usul: Buyruqlar qatori orqali ulanish:</b><br>
                    <div style="display: flex; gap: 8px; margin-top: 8px; align-items: center;">
                        <input type="text" value="${{rdpCmd}}" readonly style="background: #1e293b; border: 1px solid #475569; color: #a78bfa; padding: 8px 12px; border-radius: 6px; font-weight: bold; width: 70%;">
                        <button onclick="copyToClipboard('${{rdpCmd}}')" class="copy-pill" style="padding: 8px 14px; font-weight: bold;">📋 Buyruqni Nusxalash</button>
                    </div>
                    <span style="font-size: 11.5px; color: #94a3b8; display: block; margin-top: 6px;">Win + R oynasiga yoki CMD terminaliga kiritishingiz mumkin.</span>
                </div>
            `;
        }}

        window.onload = () => {{
            refreshDevices();
            setInterval(refreshDevices, 3000);
        }};
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
