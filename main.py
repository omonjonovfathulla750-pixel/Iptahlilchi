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

from fastapi import FastAPI, Query, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Yangi Kiberxavfsizlik va Tarmoq Modullarini import qilish
from modules.cache_manager import cache
from modules.threat_intel import threat_intel
from modules.network_intel import network_intel
from modules.log_analyzer import log_analyzer
from modules.firewall_rules import firewall_gen
from modules.telegram_alerts import telegram_notifier

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


# Windows native Layer-2 SendARP chaqiruvi
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

    # 3. Kompyuterlar (Windows, Linux, Noutbuklar)
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

    # 5. Smartfonlar (Android / Apple iOS)
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
            # Yangi qurilma ulanganda Telegram orqali xabar yuborish
            threading.Thread(target=telegram_notifier.alert_new_device, args=(dev,), daemon=True).start()

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
    t = threading.Thread(target=background_scanner_thread, daemon=True)
    t.start()
    yield


app = FastAPI(
    title="CyberNet Pro — Kiberxavfsizlik va Tarmoq Tahlili Platformasi",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ========================================================
# 🎨 WEB INTERFEYS
# ========================================================
@app.get("/", response_class=HTMLResponse)
def index():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
            geo = get_public_geolocation()
            content = content.replace("📍 Tashkent, O'zbekiston", f"📍 {geo}")
            return HTMLResponse(content=content)
    return HTMLResponse("<h2>Xatolik: templates/dashboard.html topilmadi</h2>", status_code=500)


# ========================================================
# 🚀 1. LOKAL TARMOQ (LAN) ENDPOINTLARI
# ========================================================
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


@app.get("/api/device/ports")
def api_device_ports(ip: str = Query(...)):
    return network_intel.scan_ports(ip.strip())


@app.get("/api/device/rdp")
def api_device_rdp(ip: str = Query(...)):
    ip = ip.strip()
    rdp_content = f"full address:s:{ip}\nprompt for credentials:i:1\nadministrative session:i:1\n"
    return Response(
        content=rdp_content,
        media_type="application/x-rdp",
        headers={"Content-Disposition": f"attachment; filename=remote_{ip}.rdp"}
    )


@app.get("/devices")
def get_devices():
    with active_devices_lock:
        return list(current_active_devices.values())


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


@app.get("/api/device/scan_ip")
def api_scan_single_ip(ip: str = Query(...)):
    ip = ip.strip()
    mac = send_arp_probe(ip)
    local_ip, gw_ip = get_local_ip_and_gateway()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if mac:
        meta = classify_device(ip, mac, local_ip, gw_ip)
        dev = {
            "ip": ip,
            "mac": mac,
            **meta,
            "status": "Faol (Online)",
            "status_time": f"{now_str} (Faol)",
            "connected_time": now_str,
            "online": True
        }
        with active_devices_lock:
            current_active_devices[ip] = dev
        return {"found": True, "device": dev}
    else:
        res = subprocess.run(["ping", "-n", "1", "-w", "500", ip], capture_output=True)
        if res.returncode == 0:
            meta = classify_device(ip, "Lokal Tarmoq", local_ip, gw_ip)
            dev = {
                "ip": ip,
                "mac": "Wi-Fi Tarmoq",
                **meta,
                "status": "Faol (Online)",
                "status_time": f"{now_str} (Faol)",
                "connected_time": now_str,
                "online": True
            }
            with active_devices_lock:
                current_active_devices[ip] = dev
            return {"found": True, "device": dev}
        return {"found": False, "message": f"{ip} manzilidan javob olinmadi (Offline)"}


# ========================================================
# 🛡️ 2. THREAT INTEL & TARMOQ TAHLILI ENDPOINTLARI
# ========================================================
@app.get("/api/intel/reputation")
def api_intel_reputation(ip: str = Query(...), key: str = Query(None)):
    """IP reputatsiyasi, VPN/Proksi, DNSBL qora ro'yxat va Xavf darajasini olish"""
    return threat_intel.get_ip_reputation(ip.strip(), user_api_key=key)


@app.get("/api/intel/details")
def api_intel_details(ip: str = Query(...)):
    """IP manzilning to'liq geografik, ASN, WHOIS va RDAP ma'lumotlari"""
    return network_intel.get_full_ip_details(ip.strip())


@app.get("/api/intel/deep_ports")
def api_intel_deep_ports(ip: str = Query(...)):
    """Ko'p oqimli (Multi-thread) port skaner va servis bannerlarini o'qish"""
    return network_intel.scan_ports(ip.strip())


@app.get("/api/intel/subnet")
def api_intel_subnet(cidr: str = Query(...)):
    """CIDR va Subnet kalkulyatori"""
    return network_intel.calculate_subnet(cidr.strip())


# ========================================================
# 📊 3. SERVER LOG VA BATCH TAHLILCHI
# ========================================================
class LogPayload(BaseModel):
    content: str

@app.post("/api/log/analyze")
def api_log_analyze(payload: LogPayload):
    """Server log matnidan IP larni ajratish va anomaliyalarni aniqlash"""
    return log_analyzer.analyze_log_content(payload.content)


# ========================================================
# 🚫 4. FIREWALL BLOKLASH QOIDALARI
# ========================================================
@app.get("/api/firewall/rules")
def api_firewall_rules(ip: str = Query(...), reason: str = "CyberThreat"):
    """Bitta IP uchun barcha firewall platformalarida bloklash buyruqlari"""
    return firewall_gen.generate_single_ip_rules(ip.strip(), reason)


@app.get("/api/firewall/download")
def api_firewall_download(ips: str = Query(...), platform: str = "linux_ufw", reason: str = "CyberThreat"):
    """Bir nechta IP lar uchun tayyor .sh yoki .bat bloklash faylini yuklab olish"""
    ip_list = [i.strip() for i in ips.split(",") if i.strip()]
    script = firewall_gen.generate_batch_script(ip_list, platform, reason)
    
    ext = "ps1" if "powershell" in platform else ("bat" if "bat" in platform else "sh")
    filename = f"firewall_block_rules.{ext}"
    
    return Response(
        content=script,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ========================================================
# 🤖 5. TELEGRAM XABARNOMALAR
# ========================================================
class TelegramConfigPayload(BaseModel):
    bot_token: str
    chat_id: str
    enabled: bool = True

@app.get("/api/telegram/config")
def api_telegram_get_config():
    return {
        "bot_token": telegram_notifier.bot_token,
        "chat_id": telegram_notifier.chat_id,
        "enabled": telegram_notifier.enabled
    }

@app.post("/api/telegram/config")
def api_telegram_save_config(payload: TelegramConfigPayload):
    ok = telegram_notifier.save_config(payload.bot_token, payload.chat_id, payload.enabled)
    return {"success": ok}

@app.get("/api/telegram/test")
def api_telegram_test():
    test_ip_data = {
        "ip": "185.220.101.5",
        "risk_score": 85,
        "risk_level": "O'ta Xavfli (Kiberhujum / Botnet)",
        "isp": "Tor Exit Node Network",
        "country": "Germaniya",
        "city": "Frankfurt",
        "summary": "Sinov xabarnomasi: CyberNet Pro muvaffaqiyatli ulandi."
    }
    ok, msg = telegram_notifier.alert_dangerous_ip(test_ip_data)
    return {"success": ok, "message": msg}


class CustomMessagePayload(BaseModel):
    message: str

@app.post("/api/telegram/send_custom")
def api_telegram_send_custom(payload: CustomMessagePayload):
    text = payload.message.strip()
    if not text:
        return {"success": False, "message": "Xabar matni bo'sh bo'lishi mumkin emas"}
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_text = (
        f"📢 <b>ADMINISTRATOR MAXSUS XABARNOMASI</b>\n\n"
        f"💬 <i>\"{text}\"</i>\n\n"
        f"⏱️ <b>Vaqt:</b> {now_str}\n"
        f"🛡️ <b>Tizim:</b> CyberNet SOC Pro Sentinel"
    )
    ok, msg = telegram_notifier.send_message(formatted_text)
    return {"success": ok, "message": msg}



# ========================================================
# ⚡ 6. KESH VA TEZLIK BOSHQARUVI
# ========================================================
@app.get("/api/cache/stats")
def api_cache_stats():
    return cache.get_stats()

@app.get("/api/cache/clear")
def api_cache_clear():
    cache.clear_expired()
    return {"success": True, "message": "Muddati o'tgan kesh muvaffaqiyatli tozalandi!"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
