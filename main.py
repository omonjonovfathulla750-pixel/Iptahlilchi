import os
import re
import socket
import json
import time
import struct
import ctypes
import threading
import subprocess
import random
import urllib.request
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import sqlite3
import hashlib
import secrets
from pydantic import BaseModel

from fastapi import FastAPI, Query, Response, Header, HTTPException, Request
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


@app.get("/phone_osint", response_class=HTMLResponse)
@app.get("/phone_osint.html", response_class=HTMLResponse)
def phone_osint_page():
    html_path = os.path.join(os.path.dirname(__file__), "phone_osint.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>phone_osint.html fayli topilmadi</h1>"


@app.get("/dns_analyzer", response_class=HTMLResponse)
@app.get("/dns_analyzer.html", response_class=HTMLResponse)
def dns_analyzer_page():
    html_path = os.path.join(os.path.dirname(__file__), "dns_analyzer.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>dns_analyzer.html fayli topilmadi</h1>"


@app.get("/login", response_class=HTMLResponse)
@app.get("/login.html", response_class=HTMLResponse)
def login_page():
    html_path = os.path.join(os.path.dirname(__file__), "login.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>login.html fayli topilmadi</h1>"


# ========================================================
# 🔐 AUTENTIFIKATSIYA VA FOYDALANUVCHILAR BAZASI (SQLite)
# ========================================================
AUTH_DB_PATH = os.path.join(os.path.dirname(__file__), "auth_database.db")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8863195525:AAGm7Y0fhLkRv3YxsK9e3-f4GEeAgmnk-sc")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID", "8471528668")


def send_telegram_alert(text: str, chat_id: str = None) -> bool:
    token = TELEGRAM_BOT_TOKEN
    target = chat_id or ADMIN_CHAT_ID
    if not token or not target:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": str(target),
            "text": text,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Telegram Alert Xatosi] {e}")
        return False


def init_auth_db():
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            phone TEXT,
            phone_verified INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            otp_email TEXT,
            otp_phone TEXT,
            otp_expiry TEXT,
            role TEXT DEFAULT 'analyst',
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_type TEXT,
            target_value TEXT,
            summary TEXT,
            created_at TEXT
        )
    """)
    # Migratsiya: mavjud jadvalga yangi ustunlarni qo'shish
    cur.execute("PRAGMA table_info(users)")
    existing_cols = [r[1] for r in cur.fetchall()]
    new_cols = [
        ("phone", "TEXT"),
        ("phone_verified", "INTEGER DEFAULT 0"),
        ("email_verified", "INTEGER DEFAULT 0"),
        ("otp_email", "TEXT"),
        ("otp_phone", "TEXT"),
        ("otp_expiry", "TEXT")
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            try:
                cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

    conn.commit()
    conn.close()


init_auth_db()


def hash_pwd(password: str, salt: str = None):
    if not salt:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return pwd_hash, salt


class RegisterModel(BaseModel):
    email: str
    password: str
    full_name: str = ""
    phone: str = ""


class VerifyOtpModel(BaseModel):
    user_id: int
    otp_email: str = ""
    otp_phone: str = ""


class ResendOtpModel(BaseModel):
    user_id: int


class AdminVerifyModel(BaseModel):
    user_id: int
    status: int = 1


class LoginModel(BaseModel):
    email: str
    password: str


class InvestigationModel(BaseModel):
    target_type: str
    target_value: str
    summary: str = ""


def get_user_by_token(token: str):
    if not token:
        return None
    token = token.replace("Bearer ", "").strip()
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.email, u.full_name, u.role, u.phone, u.phone_verified, u.email_verified
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0],
            "email": row[1],
            "full_name": row[2],
            "role": row[3],
            "phone": row[4] or "",
            "phone_verified": bool(row[5]),
            "email_verified": bool(row[6])
        }
    return None


@app.post("/api/auth/register")
def register_user(data: RegisterModel):
    email = data.email.strip().lower()
    phone = data.phone.strip()
    if not email or "@" not in email:
        return JSONResponse(status_code=400, content={"success": False, "message": "Email noto'g'ri kiritildi"})
    if not phone or len(phone) < 7:
        return JSONResponse(status_code=400, content={"success": False, "message": "Telefon raqami kiritilishi shart (masalan: +998901234567)"})
    if len(data.password) < 6:
        return JSONResponse(status_code=400, content={"success": False, "message": "Parol kamida 6 ta belgidan iborat bo'lishi kerak"})

    pwd_hash, salt = hash_pwd(data.password)
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expiry_str = (now + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")

    # 6 xonali tasdiqlash kodlari (SMS va Email)
    otp_email = f"{random.randint(100000, 999999)}"
    otp_phone = f"{random.randint(100000, 999999)}"

    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, password_hash, salt, full_name, phone, phone_verified, email_verified, otp_email, otp_phone, otp_expiry, created_at)
            VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)
        """, (email, pwd_hash, salt, data.full_name or email.split("@")[0], phone, otp_email, otp_phone, expiry_str, now_str))
        user_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return JSONResponse(status_code=400, content={"success": False, "message": "Bu email avval ro'yxatdan o'tgan"})
    conn.close()

    # Telegram Bot orqali Adminga tezkor bildirishnoma yuborish
    full_name = data.full_name or email.split("@")[0]
    tg_text = (
        f"🔔 <b>Yangi Foydalanuvchi Ro'yxatdan O'tmoqda!</b>\n\n"
        f"👤 <b>Ism:</b> {full_name}\n"
        f"📧 <b>Email:</b> {email}\n"
        f"📱 <b>Telefon:</b> {phone}\n"
        f"🔑 <b>Email OTP kodi:</b> <code>{otp_email}</code>\n"
        f"📲 <b>SMS OTP kodi:</b> <code>{otp_phone}</code>\n"
        f"⏰ <b>Vaqt:</b> {now_str}\n"
        f"🤖 <b>Bot:</b> @cybernetfo_bot"
    )
    send_telegram_alert(tg_text)

    # Server konsoliga ham chiqarish
    print(f"[OTP Yuborildi] Email: {email} -> {otp_email} | SMS: {phone} -> {otp_phone}")

    return {
        "success": True,
        "requires_verification": True,
        "user_id": user_id,
        "email": email,
        "phone": phone,
        "mock_email_otp": otp_email,
        "mock_sms_otp": otp_phone,
        "message": "Tasdiqlash kodi Email va SMS orqali yuborildi! Shuningdek @cybernetfo_bot orqali adminga uzatildi."
    }


@app.post("/api/auth/verify-otp")
def verify_otp_endpoint(data: VerifyOtpModel):
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, full_name, phone, otp_email, otp_phone, otp_expiry, role
        FROM users WHERE id = ?
    """, (data.user_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return JSONResponse(status_code=404, content={"success": False, "message": "Foydalanuvchi topilmadi"})

    uid, email, full_name, phone, stored_email_otp, stored_phone_otp, expiry_str, role = row

    # Muddatini tekshirish
    if expiry_str:
        try:
            exp_dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > exp_dt:
                conn.close()
                send_telegram_alert(f"⚠️ <b>OTP Muddati O'tgan Urinish:</b> {email} ({phone})")
                return JSONResponse(status_code=400, content={"success": False, "message": "Kodni amal qilish muddati o'tgan. Yangi kod so'rang"})
        except Exception:
            pass

    inp_email_otp = (data.otp_email or "").strip()
    inp_phone_otp = (data.otp_phone or "").strip()

    # Ikkala kodni yoki ulardan birini tekshirish (foydalanuvchi qulayligi uchun)
    email_matched = bool(inp_email_otp and inp_email_otp == stored_email_otp)
    phone_matched = bool(inp_phone_otp and inp_phone_otp == stored_phone_otp)

    if not (email_matched or phone_matched):
        conn.close()
        send_telegram_alert(f"🚨 <b>Noto'g'ri OTP kiritildi!</b>\n👤 Foydalanuvchi: {email} ({phone})\nKiritilgan: SMS=[{inp_phone_otp}], Email=[{inp_email_otp}]")
        return JSONResponse(status_code=400, content={"success": False, "message": "Kiritilgan tasdiqlash kodi (SMS yoki Email) noto'g'ri"})

    # Tasdiqlangan deb belgilash
    new_email_ver = 1 if email_matched or stored_email_otp is None else 1
    new_phone_ver = 1 if phone_matched or stored_phone_otp is None else 1

    cur.execute("""
        UPDATE users
        SET phone_verified = ?, email_verified = ?, otp_email = NULL, otp_phone = NULL
        WHERE id = ?
    """, (new_phone_ver, new_email_ver, uid))

    token = secrets.token_urlsafe(32)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, uid, now_str))
    conn.commit()
    conn.close()

    # Telegram botga muvaffaqiyatli xabar yuborish
    tg_success = (
        f"✅ <b>Foydalanuvchi Muvaffaqiyatli Tasdiqlandi!</b>\n\n"
        f"👤 <b>Ism:</b> {full_name}\n"
        f"📧 <b>Email:</b> {email} (Tasdiqlandi)\n"
        f"📱 <b>Telefon:</b> {phone} (Tasdiqlandi)\n"
        f"🛡️ <b>Holat:</b> Kiber-Tahlil tizimiga to'liq ruxsat berildi!\n"
        f"⏰ <b>Vaqt:</b> {now_str}"
    )
    send_telegram_alert(tg_success)

    user_info = {
        "id": uid,
        "email": email,
        "full_name": full_name,
        "phone": phone,
        "role": role,
        "phone_verified": True,
        "email_verified": True
    }
    return {
        "success": True,
        "token": token,
        "user": user_info,
        "message": "Tabriklaymiz! Telefon va Email muvaffaqiyatli tasdiqlandi. Tizimga xush kelibsiz!"
    }


@app.post("/api/auth/resend-otp")
def resend_otp_endpoint(data: ResendOtpModel):
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, email, full_name, phone FROM users WHERE id = ?", (data.user_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return JSONResponse(status_code=404, content={"success": False, "message": "Foydalanuvchi topilmadi"})

    uid, email, full_name, phone = row
    now = datetime.now()
    expiry_str = (now + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    otp_email = f"{random.randint(100000, 999999)}"
    otp_phone = f"{random.randint(100000, 999999)}"

    cur.execute("""
        UPDATE users
        SET otp_email = ?, otp_phone = ?, otp_expiry = ?
        WHERE id = ?
    """, (otp_email, otp_phone, expiry_str, uid))
    conn.commit()
    conn.close()

    # Adminga Telegram xabar
    send_telegram_alert(
        f"🔄 <b>Yangi OTP Kodlari So'raldi:</b>\n"
        f"👤 {full_name} ({email}, {phone})\n"
        f"🔑 Email OTP: <code>{otp_email}</code>\n"
        f"📲 SMS OTP: <code>{otp_phone}</code>"
    )

    return {
        "success": True,
        "mock_email_otp": otp_email,
        "mock_sms_otp": otp_phone,
        "message": "Yangi tasdiqlash kodlari yuborildi!"
    }


# ========================================================
# 👑 ADMIN BOSHQARUV VA TELEGRAM BOT INTEGRATSIYASI
# ========================================================
@app.get("/api/admin/users")
def admin_list_users():
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, full_name, phone, phone_verified, email_verified, role, created_at
        FROM users
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()
    users = []
    for r in rows:
        users.append({
            "id": r[0],
            "email": r[1],
            "full_name": r[2] or "",
            "phone": r[3] or "Kiritilmagan",
            "phone_verified": bool(r[4]),
            "email_verified": bool(r[5]),
            "role": r[6] or "analyst",
            "created_at": r[7] or ""
        })
    return {
        "success": True,
        "users": users,
        "telegram_bot": {
            "username": "@cybernetfo_bot",
            "admin_chat_id": ADMIN_CHAT_ID,
            "status": "Online (Ulangan)"
        }
    }


@app.post("/api/admin/verify-user")
def admin_verify_user(data: AdminVerifyModel):
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET phone_verified = ?, email_verified = ?
        WHERE id = ?
    """, (data.status, data.status, data.user_id))
    cur.execute("SELECT email, full_name, phone FROM users WHERE id = ?", (data.user_id,))
    row = cur.fetchone()
    conn.commit()
    conn.close()

    if row:
        status_txt = "Tasdiqlandi" if data.status else "Bekor qilindi"
        send_telegram_alert(f"👑 <b>Admin Paneli:</b> Foydalanuvchi {row[1]} ({row[0]}) admin tomonidan {status_txt}!")

    return {"success": True, "message": "Foydalanuvchi holati yangilandi"}


@app.post("/api/admin/telegram-test")
def admin_telegram_test():
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"🛡️ <b>KIBER-TAHLIL TIZIMI // SINOV XABARI</b>\n\n"
        f"✅ Telegram bot (@cybernetfo_bot) va Admin paneli integratsiyasi 100% faol!\n"
        f"🆔 <b>Admin Chat ID:</b> <code>{ADMIN_CHAT_ID}</code>\n"
        f"⏰ <b>Vaqt:</b> {now_str}\n"
        f"Status: Barcha ogohlantirishlar va OTP xabarlari to'g'ridan-to'g'ri yetkazilmoqda."
    )
    ok = send_telegram_alert(msg)
    return {
        "success": ok,
        "message": "Telegram adminga sinov xabari jo'natildi!" if ok else "Telegram botga ulanishda xatolik yuz berdi",
        "chat_id": ADMIN_CHAT_ID,
        "bot": "@cybernetfo_bot"
    }


@app.post("/api/auth/login")
def login_user(data: LoginModel):
    email = data.email.strip().lower()
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, salt, full_name, role, phone, phone_verified, email_verified FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return JSONResponse(status_code=401, content={"success": False, "message": "Email yoki parol xato"})

    user_id, stored_hash, salt, full_name, role, phone, p_ver, e_ver = row
    test_hash, _ = hash_pwd(data.password, salt)

    if test_hash != stored_hash:
        conn.close()
        return JSONResponse(status_code=401, content={"success": False, "message": "Email yoki parol xato"})

    token = secrets.token_urlsafe(32)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)", (token, user_id, now_str))
    conn.commit()
    conn.close()

    user_info = {
        "id": user_id,
        "email": email,
        "full_name": full_name,
        "role": role,
        "phone": phone or "",
        "phone_verified": bool(p_ver),
        "email_verified": bool(e_ver)
    }
    return {"success": True, "token": token, "user": user_info}


@app.get("/api/auth/me")
def get_me(authorization: str = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        return JSONResponse(status_code=401, content={"success": False, "message": "Avtorizatsiyadan o'tilmagan"})
    return {"success": True, "user": user}


@app.post("/api/auth/logout")
def logout_user(authorization: str = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        conn = sqlite3.connect(AUTH_DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"success": True, "message": "Chiqildi"}


@app.post("/api/auth/investigations")
def save_investigation(data: InvestigationModel, authorization: str = Header(None)):
    user = get_user_by_token(authorization)
    user_id = user["id"] if user else 1
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO saved_investigations (user_id, target_type, target_value, summary, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, data.target_type, data.target_value, data.summary, now_str))
    inv_id = cur.lastrowid
    conn.commit()
    conn.close()
    return {"success": True, "id": inv_id, "message": "Dosye saqlandi"}


@app.get("/api/auth/investigations")
def list_investigations(authorization: str = Header(None)):
    user = get_user_by_token(authorization)
    user_id = user["id"] if user else 1

    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, target_type, target_value, summary, created_at
        FROM saved_investigations
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()

    items = [
        {"id": r[0], "type": r[1], "target": r[2], "summary": r[3], "date": r[4]}
        for r in rows
    ]
    return {"success": True, "investigations": items}


@app.delete("/api/auth/investigations/{inv_id}")
def delete_investigation(inv_id: int, authorization: str = Header(None)):
    user = get_user_by_token(authorization)
    conn = sqlite3.connect(AUTH_DB_PATH)
    cur = conn.cursor()
    if user:
        cur.execute("DELETE FROM saved_investigations WHERE id = ? AND user_id = ?", (inv_id, user["id"]))
    else:
        cur.execute("DELETE FROM saved_investigations WHERE id = ?", (inv_id,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "O'chirildi"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
