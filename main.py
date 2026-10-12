import os
import re
import socket
import json
import time
import struct
import ctypes
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

app = FastAPI(title="Tarmoq Qurilmalarini Aniq va Chuqur Tahlil Qilish Tizimi")

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


# Windows native Layer-2 SendARP chaqiruvi (Tarmoqdagi real qurilmani darhol aniqlash)
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


# Tezkor hostname aniqlash (keshlangan)
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


# Qurilma turini (Smart TV, Android telefon, Simli kompyuter, Router) aniqlash
def classify_device(ip_str: str, mac_str: str, local_ip: str, gw_ip: str):
    prefix = mac_str[:8].upper()
    try:
        first_byte = int(mac_str[:2], 16)
        is_random_mac = bool(first_byte & 2)
    except Exception:
        is_random_mac = False

    hostname = resolve_hostname(ip_str)

    # 1. Asosiy Wi-Fi Router
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
            "device_name": f"{pc_name} — Asosiy Boshqaruv Kompyuteri",
            "category": "Kompyuter (Host PC)",
            "source": "Ethernet LAN Kabel / Wi-Fi",
            "type_icon": "💻",
            "owner": "Siz (Administrator)",
            "location": "Asosiy Ish O'rningiz",
            "description": "Hozirgi dastur va monitoring tizimi ishlayotgan shaxsiy kompyuter.",
        }

    # 3. Android Smart TV / Televizorlar
    # Gaoshengda (84:C8:A0) modul yoki televizor ishlab chiqaruvchilari
    tv_prefixes = ["84:C8:A0", "00:08:22", "64:1C:67", "50:85:69", "AC:C1:EE"]
    is_tv = any(p in prefix for p in tv_prefixes) or (hostname and any(k in hostname.upper() for k in ["TV", "BRAVIA", "HISENSE", "TCL", "SKYWORTH", "SHARP", "MI-TV"]))
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

    # 4. Android Smartfonlar va Apple iOS (Maxfiy MAC manzilli mobil gadjetlar)
    if is_random_mac:
        return {
            "name": f"Smartfon / Mobil Gadjet (Android / iOS)",
            "device_name": f"Smartfon / Mobil Telefon (IP: {ip_str})",
            "category": "Smartfon / Mobil",
            "source": "Wi-Fi (Maxfiy / Xususiy MAC manzil)",
            "type_icon": "📱",
            "owner": "Mobil Foydalanuvchi",
            "location": "Wi-Fi Qamrovi Hududida",
            "description": "Android yoki Apple tizimidagi mobil smartfon. Wi-Fi tarmog'iga himoyalangan MAC bilan ulangan.",
        }

    # 5. Sim orqali (LAN kabel) yoki Wi-Fi orqali ulangan boshqa kompyuterlar
    if hostname and any(k in hostname.upper() for k in ["WIN-", "DESKTOP-", "HOME-PC", "PC", "LAPTOP"]):
        return {
            "name": f"{hostname} (Simli LAN Kompyuter)",
            "device_name": f"{hostname} — Ishchi Kompyuter (LAN kabel)",
            "category": "Kompyuter (LAN kabel / Noutbuk)",
            "source": "Ethernet LAN Kabel orqali (Simli)",
            "type_icon": "🖥️",
            "owner": "Ofis yoki Oila Foydalanuvchisi",
            "location": "Qo'shimcha Stol / Xona",
            "description": "Routerga sim orqali (LAN kabel) yoki Wi-Fi adapter orqali ulangan ishchi kompyuter.",
        }

    # 6. Umumiy aniqlangan tarmoq qurilmasi
    return {
        "name": f"Tarmoq Qurilmasi (IP: {ip_str})",
        "device_name": f"Lokal Tarmoq Tuguni ({ip_str})",
        "category": "Lokal Tarmoq Qurilmasi",
        "source": "Wi-Fi / Ethernet LAN",
        "type_icon": "⚡",
        "owner": "Tarmoq Foydalanuvchisi",
        "location": "Lokal Segment",
        "description": "Tarmoqqa ulangan va ayni vaqtda faol javob berayotgan apparat vositasi.",
    }


# Butun subnetni Layer-2 da tekshiruvchi funksiya
def scan_subnet_once():
    global current_active_devices, disconnected_history, events_log
    local_ip, gw_ip = get_local_ip_and_gateway()
    parts = local_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}" if len(parts) == 4 else "192.168.0"

    # 1 dan 254 gacha barcha IP larni aniqlash
    ips_to_scan = [f"{subnet}.{i}" for i in range(1, 255)]

    detected_now = {}

    def worker(ip):
        mac = send_arp_probe(ip)
        if mac:
            return ip, mac
        return ip, None

    # Barcha 254 IP ga parallel SendARP jo'natish (4 soniya ichida butun tarmoq aniqlanadi)
    with ThreadPoolExecutor(max_workers=250) as executor:
        results = list(executor.map(worker, ips_to_scan))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ip, mac in results:
        if mac:
            meta = classify_device(ip, mac, local_ip, gw_ip)
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

        # Yangi ulanganlarni topish
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

        # Tarmoqdan UZILGANLARNI (OFFLINE) topish
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

        # Eski ro'yxatni yangisi bilan to'liq almashtirish (Uzilganlar avtomatik ro'yxatdan o'chadi!)
        current_active_devices = detected_now


# Fonda doimiy ishlovchi avtomatik skanerlash ipi
def background_scanner_thread():
    while True:
        try:
            scan_subnet_once()
        except Exception as e:
            pass
        time.sleep(3.5)


# FastAPI start bo'lganda fon skanerni ishga tushirish
@app.on_event("startup")
def startup_event():
    # Birinchi marta darhol skanerlash
    t = threading.Thread(target=background_scanner_thread, daemon=True)
    t.start()


# 1. Ayni vaqtda faol qurilmalar ro'yxatini qaytaruvchi API
@app.get("/devices")
def get_devices():
    with active_devices_lock:
        # Faqat ayni vaqtda ON-LINE bo'lgan qurilmalar qaytadi!
        devices = list(current_active_devices.values())
    return devices


# 2. To'liq skanerlash va hodisalar API si
@app.get("/api/scan")
def api_scan():
    local_ip, gw_ip = get_local_ip_and_gateway()
    parts = local_ip.split(".")
    subnet_desc = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24 (Real Wi-Fi & LAN)"

    with active_devices_lock:
        devices = list(current_active_devices.values())
        events = list(events_log[:10])

    return {
        "success": True,
        "searched_ip": local_ip,
        "total_devices": f"{len(devices)} ta real qurilma ayni vaqtda ulangan",
        "subnet": subnet_desc,
        "devices": devices,
        "events": events,
    }


@app.get("/", response_class=HTMLResponse)
def index():
    local_ip, gw_ip = get_local_ip_and_gateway()
    geo = get_public_geolocation()

    return f"""<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ayni Vaqtdagi Real Tarmoq Qurilmalari Monitoringi</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        body {{ background-color: #0b0f19; color: #f8fafc; padding: 22px; }}
        .container {{ max-width: 1350px; margin: 0 auto; }}

        .header {{ 
            background: linear-gradient(135deg, #1e293b, #0f172a); 
            padding: 22px 25px; 
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
        .control-left {{ display: flex; align-items: center; gap: 12px; }}
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

        /* Live devices and events split */
        .grid-split {{ display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 20px; }}
        
        .panel {{
            background: #1e293b;
            border-radius: 12px;
            border: 1px solid #334155;
            padding: 18px;
        }}
        .panel-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #334155;
            padding-bottom: 12px;
            margin-bottom: 14px;
            font-size: 15px;
            font-weight: bold;
            color: #38bdf8;
        }}

        #device-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-height: 400px;
            overflow-y: auto;
        }}
        .device-card {{
            padding: 12px 16px;
            border-radius: 8px;
            background: #0f172a;
            border: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.25s;
        }}
        .device-card:hover {{ border-color: #38bdf8; background: #172554; }}
        .device-card.just-joined {{
            background: #064e3b !important;
            border-color: #059669 !important;
            animation: highlightJoin 2s ease;
        }}
        .device-card.just-left {{
            background: #451a03 !important;
            border-color: #d97706 !important;
        }}

        #events-list {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 12.5px;
        }}
        .event-item {{
            padding: 8px 12px;
            border-radius: 6px;
            background: #0f172a;
            border-left: 3px solid #38bdf8;
        }}
        .event-item.connected {{ border-left-color: #34d399; color: #a7f3d0; }}
        .event-item.disconnected {{ border-left-color: #f59e0b; color: #fde68a; }}

        .table-wrap {{ overflow-x: auto; border-radius: 12px; border: 1px solid #334155; margin-top: 10px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; }}
        th, td {{ padding: 13px 16px; text-align: left; font-size: 13px; border-bottom: 1px solid #334155; vertical-align: middle; }}
        th {{ background: #334155; color: #38bdf8; text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.5px; }}
        tr:hover {{ background: #273548; }}
        .badge {{ padding: 4px 9px; border-radius: 6px; font-size: 11.5px; font-weight: bold; display: inline-block; }}
        .badge-router {{ background: #1e3a8a; color: #93c5fd; }}
        .badge-pc {{ background: #064e3b; color: #6ee7b7; }}
        .badge-tv {{ background: #701a75; color: #f0abfc; }}
        .badge-phone {{ background: #7c2d12; color: #fdba74; }}
        .badge-general {{ background: #334155; color: #cbd5e1; }}
        .tag-source {{ font-size: 11.5px; color: #38bdf8; font-weight: 500; display: block; margin-top: 2px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🌐 Ayni Vaqtdagi Real Tarmoq Qurilmalari Tahlili</div>
            <div class="geo">📍 {geo}</div>
        </div>

        <div class="control-bar">
            <div class="control-left">
                <button onclick="refreshDevices()" class="btn-refresh">
                    🔄 Refresh (Yangilash)
                </button>
                <div class="pulse-live">
                    <span class="dot"></span>
                    <span id="scan-status">Jonli Avto-Kuzatuv (3s)</span>
                </div>
            </div>
            <div style="color: #94a3b8; font-size: 13px;">
                Tarmoq shlyuzi: <code style="color: #38bdf8;">{gw_ip}</code> | Asosiy PC: <code style="color: #38bdf8;">{local_ip}</code>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h4>Jami Ulangan</h4>
                <p id="stat-total">0 ta</p>
            </div>
            <div class="stat-card">
                <h4>Kompyuterlar (Simli / Wi-Fi)</h4>
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

        <div class="grid-split">
            <!-- Jonli Qurilmalar ro'yxati -->
            <div class="panel">
                <div class="panel-header">
                    <span>📱 Ayni Vaqtda Ulangan Faol Qurilmalar</span>
                    <span style="font-size: 12px; color: #34d399;" id="online-count">0 ta onlayn</span>
                </div>
                <ul id="device-list">
                    <li style="padding: 20px; text-align: center; color: #94a3b8;">Tarmoq tekshirilmoqda...</li>
                </ul>
            </div>

            <!-- Yangi qo'shilish va uzilishlar hodisalari -->
            <div class="panel">
                <div class="panel-header">
                    <span>⚡ Jonli O'zgarishlar Jurnali</span>
                    <span style="font-size: 12px; color: #94a3b8;">Hodisalar</span>
                </div>
                <ul id="events-list">
                    <li style="padding: 10px; color: #94a3b8; text-align: center;">Hozircha o'zgarishlar yo'q</li>
                </ul>
            </div>
        </div>

        <!-- Batafsil Qurilmalar Jadvali -->
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Qurilma & Nomi</th>
                        <th style="width: 20%;">IP & Real MAC Manzil</th>
                        <th style="width: 15%;">Kategoriya</th>
                        <th style="width: 20%;">Ulanish Turi & Port</th>
                        <th style="width: 20%;">Holati & Vaqti</th>
                    </tr>
                </thead>
                <tbody id="deviceTable">
                    <tr><td colspan="5" style="text-align: center; padding: 25px; color: #94a3b8;">Yuklanmoqda...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let previousDevices = [];

        async function refreshDevices() {{
            const scanStatus = document.getElementById('scan-status');
            scanStatus.innerText = "Skanerlanmoqda...";

            try {{
                // Backend dan haqiqiy ayni daqiqada ulangan qurilmalarni olish
                const res = await fetch('/api/scan');
                const data = await res.json();
                
                const currentDevices = data.devices || [];
                const events = data.events || [];

                const listEl = document.getElementById('device-list');
                const tbody = document.getElementById('deviceTable');
                const eventsEl = document.getElementById('events-list');

                const prevIps = new Set(previousDevices.map(d => d.ip));
                const currIps = new Set(currentDevices.map(d => d.ip));

                // 1. STATISTIKA HISOB-KITOBLARI
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
                document.getElementById('online-count').innerText = `${{currentDevices.length}} ta onlayn`;

                // 2. QURILMALAR RO'YXATINI YANGILASH
                listEl.innerHTML = '';
                if (currentDevices.length === 0) {{
                    listEl.innerHTML = '<li style="padding: 20px; text-align: center; color: #94a3b8;">Tarmoqda qurilmalar topilmadi</li>';
                }} else {{
                    currentDevices.forEach(device => {{
                        const li = document.createElement('li');
                        li.className = 'device-card';
                        
                        const isNew = previousDevices.length > 0 && !prevIps.has(device.ip);
                        if (isNew) {{
                            li.className += ' just-joined';
                        }}

                        li.innerHTML = `
                            <div>
                                <div style="font-weight: bold; color: #f8fafc; font-size: 14px;">
                                    ${{device.type_icon || '💻'}} ${{device.name}}
                                </div>
                                <div style="font-size: 12px; color: #94a3b8; margin-top: 3px;">
                                    <code style="color: #38bdf8;">${{device.ip}}</code> | MAC: <code>${{device.mac}}</code>
                                </div>
                                <span class="tag-source">🔗 ${{device.source}}</span>
                            </div>
                            <div>
                                ${{isNew ? '<span style="background: #059669; color: white; padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: bold;">🟢 Yangi</span>' : '<span style="color: #34d399; font-size: 12px; font-weight: bold;">● Faol</span>'}}
                            </div>
                        `;
                        listEl.appendChild(li);
                    }});
                }}

                // 3. JADVALNI YANGILASH (UZILGANLAR AVTOMATIK JADVALDAN O'CHADI)
                tbody.innerHTML = '';
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
                            <span style="color: #94a3b8; font-size: 11.5px;">📍 ${{dev.location}}</span>
                        </td>
                        <td>
                            <span style="color: #4ade80; font-weight: bold; font-size: 12.5px;">🟢 ${{dev.status}}</span><br>
                            <span style="color: #94a3b8; font-size: 11px;">🕒 ${{dev.status_time}}</span>
                        </td>
                    </tr>`;
                    tbody.innerHTML += row;
                }});

                // 4. HODISALAR JURNALINI YANGILASH
                if (events.length > 0) {{
                    eventsEl.innerHTML = '';
                    events.forEach(ev => {{
                        const li = document.createElement('li');
                        li.className = `event-item ${{ev.type}}`;
                        li.innerHTML = `<div>${{ev.message}}</div><div style="font-size: 11px; opacity: 0.7; margin-top: 2px;">${{ev.time}}</div>`;
                        eventsEl.appendChild(li);
                    }});
                }}

                previousDevices = currentDevices;
                scanStatus.innerText = "Jonli Avto-Kuzatuv (3s)";

            }} catch (err) {{
                console.error("Yangilashda xato:", err);
                scanStatus.innerText = "Kutish rejimida";
            }}
        }}

        // Sahifa ochilishi bilan boshlash
        window.onload = () => {{
            refreshDevices();
            // Har 3 soniyada avtomatik tekshirib yangilab turadi!
            setInterval(refreshDevices, 3000);
        }};
    </script>
</body>
</html>
"""


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
