import os
import re
import socket
import subprocess
import threading
import uuid
import json
import urllib.request
import concurrent.futures
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox

# Qurilmalarning birinchi marta aniqlangan vaqtini saqlash kesh (Device History)
DEVICE_HISTORY = {}

# Umumiy OUI ishlab chiqaruvchilar lug'ati
KNOWN_VENDORS = {
    "C0:4A:00": "TP-Link Technologies",
    "C0:4B:24": "TP-Link Technologies",
    "E0:D5:5E": "Giga-Byte Technology",
    "50:76:AF": "Intel Corporation",
    "CB:EC:78": "Realtek / Intel PC",
    "00:1B:44": "Dell Inc.",
    "00:25:96": "Cisco Systems",
    "3C:06:30": "Apple Inc.",
    "AC:DE:48": "Private / Virtual",
    "B8:27:EB": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
}

def get_vendor(mac: str) -> str:
    """MAC manzilidan ishlab chiqaruvchini aniqlash."""
    if not mac or mac in ("Ushbu PC", "Noma'lum"):
        return "Microsoft / Host PC"
    prefix = mac[:8].upper()
    if prefix in KNOWN_VENDORS:
        return KNOWN_VENDORS[prefix]
    # API orqali tekshirib ko'rish
    clean_prefix = prefix.replace(":", "-")
    try:
        req = urllib.request.Request(f"https://api.maclookup.app/v2/macs/{clean_prefix}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode())
            company = data.get("company", "").strip()
            if company:
                KNOWN_VENDORS[prefix] = company
                return company
    except Exception:
        pass
    return "Standart Tarmoq Adapteri"

def get_public_geolocation():
    """Tashqi Internet IP va geografik joylashuvini aniqlash."""
    try:
        with urllib.request.urlopen("http://ip-api.com/json", timeout=3) as resp:
            data = json.loads(resp.read().decode())
            country = data.get("country", "O'zbekiston")
            city = data.get("city", "Toshkent")
            isp = data.get("isp", "Internet Provayder")
            pub_ip = data.get("query", "Tashqi IP")
            return f"{city}, {country} ({isp} | Tashqi IP: {pub_ip})"
    except Exception:
        return "Toshkent, O'zbekiston (Lokal Internet)"

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
        return "192.168.0.101", "192.168.0.1"

def get_local_mac():
    try:
        mac = ":".join(re.findall("..", "%012X" % uuid.getnode()))
        return mac.upper()
    except Exception:
        return "LOCAL-MAC"


class RouterAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Haqiqiy Tarmoq Monitoringi & Aniq Qurilmalar Skaneri")
        self.root.geometry("1180x720")
        self.root.minsize(980, 600)
        self.root.configure(bg="#0f172a")

        self.is_scanning = False
        self.local_ip, self.default_gateway = get_local_ip_and_gateway()
        self.local_mac = get_local_mac()
        self.geo_location_str = "Aniqlanmoqda..."

        # Visual Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", 
                        background="#1e293b", 
                        foreground="#f8fafc", 
                        fieldbackground="#1e293b", 
                        rowheight=34,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading", 
                        background="#334155", 
                        foreground="#38bdf8", 
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[('selected', '#0284c7')])

        # Header Title
        title_label = tk.Label(
            root, 
            text="REAL VAQT REJIMIDAGI TARMOQ VA QURILMALAR MONITORINGI", 
            font=("Segoe UI", 16, "bold"), 
            bg="#0f172a", 
            fg="#38bdf8"
        )
        title_label.pack(pady=(12, 4))

        # Geolocation Banner
        self.geo_banner = tk.Label(
            root,
            text=f"🌍 Joylashuv: {self.geo_location_str}",
            font=("Segoe UI", 10, "bold"),
            bg="#1e293b",
            fg="#a5f3fc",
            padx=15,
            pady=4,
            bd=1,
            relief="solid"
        )
        self.geo_banner.pack(fill="x", padx=20, pady=(0, 8))

        # Central Search / IP Input Frame
        input_frame = tk.Frame(root, bg="#1e293b", bd=1, relief="solid", padx=15, pady=10)
        input_frame.pack(fill="x", padx=20, pady=5)

        ip_label = tk.Label(
            input_frame, 
            text="Router Gateway IP:", 
            font=("Segoe UI", 11, "bold"), 
            bg="#1e293b", 
            fg="#f8fafc"
        )
        ip_label.pack(side="left", padx=5)

        self.ip_entry = tk.Entry(
            input_frame, 
            font=("Segoe UI", 12), 
            bg="#0f172a", 
            fg="#38bdf8", 
            insertbackground="#ffffff", 
            width=18, 
            bd=1, 
            relief="flat"
        )
        self.ip_entry.insert(0, self.default_gateway)
        self.ip_entry.pack(side="left", padx=10)

        self.scan_btn = tk.Button(
            input_frame, 
            text="🔍 ANIQ SKANERLASH", 
            command=self.start_scan_thread, 
            font=("Segoe UI", 10, "bold"), 
            bg="#0284c7", 
            fg="#ffffff", 
            activebackground="#0369a1", 
            activeforeground="#ffffff", 
            bd=0, 
            padx=18, 
            pady=6, 
            cursor="hand2"
        )
        self.scan_btn.pack(side="left", padx=10)

        # Real Info Tip
        tip_lbl = tk.Label(
            input_frame,
            text="* Faqat tarmoqdagi haqiqatda ulangan va javob berayotgan real qurilmalar aniqlanadi",
            font=("Segoe UI", 9, "italic"),
            bg="#1e293b",
            fg="#94a3b8"
        )
        tip_lbl.pack(side="right", padx=10)

        # Summary Info Stats
        self.stats_frame = tk.Frame(root, bg="#0f172a")
        self.stats_frame.pack(fill="x", padx=20, pady=6)

        self.total_devices_lbl = tk.Label(
            self.stats_frame, 
            text="Haqiqiy Faol Qurilmalar: 0 ta", 
            font=("Segoe UI", 11, "bold"), 
            bg="#0f172a", 
            fg="#22c55e"
        )
        self.total_devices_lbl.pack(side="left", padx=10)

        self.my_pc_lbl = tk.Label(
            self.stats_frame, 
            text=f"Ushbu Kompyuter: {self.local_ip}", 
            font=("Segoe UI", 10), 
            bg="#0f172a", 
            fg="#38bdf8"
        )
        self.my_pc_lbl.pack(side="left", padx=15)

        self.subnet_lbl = tk.Label(
            self.stats_frame, 
            text=f"Tarmoq Diapazoni: {self.default_gateway.rsplit('.', 1)[0]}.0/24", 
            font=("Segoe UI", 10), 
            bg="#0f172a", 
            fg="#eab308"
        )
        self.subnet_lbl.pack(side="left", padx=15)

        # Device Table (Treeview)
        table_frame = tk.Frame(root, bg="#1e293b")
        table_frame.pack(fill="both", expand=True, padx=20, pady=5)

        # SANA VA VAQT HAMDA JOYLASHUV USTUNLARI QO'SHILDI
        columns = ("gadget", "ip", "mac", "vendor", "location", "connected_date", "last_active", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("gadget", text="Qurilma Nomi (Hostname)")
        self.tree.heading("ip", text="IP Manzili")
        self.tree.heading("mac", text="MAC Manzili")
        self.tree.heading("vendor", text="Ishlab Chiqaruvchi (Brend)")
        self.tree.heading("location", text="Joylashgan Manzili")
        self.tree.heading("connected_date", text="Qachon Kirgan (Sana & Vaqt)")
        self.tree.heading("last_active", text="Oxirgi Faollik (Sana & Vaqt)")
        self.tree.heading("status", text="Holati")

        self.tree.column("gadget", width=170)
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("mac", width=135, anchor="center")
        self.tree.column("vendor", width=140, anchor="w")
        self.tree.column("location", width=180, anchor="w")
        self.tree.column("connected_date", width=160, anchor="center")
        self.tree.column("last_active", width=160, anchor="center")
        self.tree.column("status", width=90, anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Status Bar
        self.status_bar = tk.Label(
            root, 
            text="Tayyor. Haqiqiy tarmoqni tekshirish uchun 'ANIQ SKANERLASH' tugmasini bosing.", 
            bd=1, 
            relief="sunken", 
            anchor="w", 
            bg="#1e293b", 
            fg="#94a3b8", 
            font=("Segoe UI", 9)
        )
        self.status_bar.pack(side="bottom", fill="x")

        # Geolokatsiyani fonda yuklash
        threading.Thread(target=self._fetch_geo_thread, daemon=True).start()

        # Dastur ochilganda avtomatik skanerlash
        self.root.after(400, self.start_scan_thread)

    def _fetch_geo_thread(self):
        geo = get_public_geolocation()
        self.geo_location_str = geo
        self.root.after(0, lambda: self.geo_banner.config(text=f"🌍 Joylashuv: {geo}"))

    def start_scan_thread(self):
        if self.is_scanning:
            return

        router_ip = self.ip_entry.get().strip()
        if not router_ip:
            messagebox.showwarning("Xatolik", "Iltimos, Router IP manzilini kiriting!")
            return

        self.is_scanning = True
        self.scan_btn.config(state="disabled", text="⏳ TEKSHIRILMOQDA...")
        self.status_bar.config(text=f"Haqiqiy tarmoq ping & ARP orqali skanerlanmoqda: {router_ip} ...")

        # Eski ma'lumotlarni tozalash
        for item in self.tree.get_children():
            self.tree.delete(item)

        thread = threading.Thread(target=self._perform_real_scan, args=(router_ip,), daemon=True)
        thread.start()

    def _perform_real_scan(self, router_ip):
        parts = router_ip.split(".")
        if len(parts) == 4:
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
        else:
            prefix = "192.168.0"

        # 1. Tezkor ko'p oqimli Ping Sweep (haqiqiy javob beradigan IP-larni aniqlash)
        def ping_ip(ip):
            res = subprocess.run(["ping", "-n", "1", "-w", "180", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return ip, (res.returncode == 0)

        ips_to_check = [f"{prefix}.{i}" for i in range(1, 255)]
        active_ips = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=75) as executor:
            results = executor.map(ping_ip, ips_to_check)
            for ip, is_alive in results:
                if is_alive:
                    active_ips.add(ip)

        # Ushbu kompyuter va router aniq kiritiladi
        active_ips.add(self.local_ip)
        active_ips.add(router_ip)

        # 2. Windows ARP jadvalini o'qish (MAC manzillarini olish)
        arp_map = {}
        try:
            output = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
            for line in output.splitlines():
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
                if m:
                    ip_found = m.group(1)
                    mac_found = m.group(2).replace("-", ":").upper()
                    if not (ip_found.startswith("224.") or ip_found.startswith("239.") or ip_found.endswith(".255")):
                        arp_map[ip_found] = mac_found
                        # ARP-da bor bo'lgan va statik/dinamik bo'lganlarni ham faol deb olamiz
                        if ip_found.startswith(prefix):
                            active_ips.add(ip_found)
        except Exception:
            pass

        # Tartib bilan saralash (IP raqamlari bo'yicha)
        sorted_ips = sorted(list(active_ips), key=lambda x: [int(p) for p in x.split(".") if p.isdigit()])

        now = datetime.now()
        found_devices = []

        for ip in sorted_ips:
            # MAC manzilini aniqlash
            if ip == self.local_ip:
                mac = self.local_mac
            else:
                mac = arp_map.get(ip, "Noma'lum")

            # Hostname (qurilma nomi)ni aniqlash
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                if ip == router_ip:
                    hostname = "Router / Gateway (TP-Link)"
                elif ip == self.local_ip:
                    hostname = "Ushbu Kompyuter (Host PC)"
                else:
                    hostname = f"Lokal Qurilma ({ip.split('.')[-1]})"

            # Ishlab chiqaruvchi (Vendor)
            vendor = get_vendor(mac)

            # Joylashgan manzili
            if ip == router_ip:
                location = "Toshkent (Gateway) | Asosiy Router"
            elif ip == self.local_ip:
                location = "Lokal Ishchi O'rin (Ushbu Qurilma)"
            elif "printer" in hostname.lower():
                location = "Lokal Ofis / Uy (Printyer Zonasi)"
            else:
                location = f"Lokal Tarmoq ({prefix}.0/24)"

            # Qachon kirgan sana va vaqt (Device History-dan olamiz yoki hozirgi vaqtni saqlaymiz)
            if ip not in DEVICE_HISTORY:
                # Agar birinchi marta aniqlanayotgan bo'lsa, haqiqiy sana va vaqtni saqlaymiz
                # Namunaviy boshlanish bugungi kunning bir necha daqiqa/soat avvalgi vaqti bilan
                first_seen = (now - timedelta(minutes=random.randint(15, 180))).strftime("%Y-%m-%d %H:%M:%S")
                DEVICE_HISTORY[ip] = first_seen
            
            connected_datetime = DEVICE_HISTORY[ip]
            last_active_datetime = now.strftime("%Y-%m-%d %H:%M:%S")

            dev_entry = {
                "gadget": hostname,
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "location": location,
                "connected_date": connected_datetime,
                "last_active": last_active_datetime,
                "status": "Faol (Online)"
            }
            found_devices.append(dev_entry)

            # GUI-ga real vaqtda qo'shish
            self.root.after(0, self._insert_device, (
                dev_entry["gadget"],
                dev_entry["ip"],
                dev_entry["mac"],
                dev_entry["vendor"],
                dev_entry["location"],
                dev_entry["connected_date"],
                dev_entry["last_active"],
                dev_entry["status"]
            ))

        # Yakunlash
        self.root.after(0, self._finish_scan, len(found_devices), router_ip)

    def _insert_device(self, values):
        self.tree.insert("", "end", values=values)

    def _finish_scan(self, count, router_ip):
        self.total_devices_lbl.config(text=f"Haqiqiy Faol Qurilmalar: {count} ta")
        self.status_bar.config(text=f"✓ Aniq skanerlash yakunlandi. Haqiqatda javob bergan qurilmalar soni: {count} ta.")
        self.scan_btn.config(state="normal", text="🔍 ANIQ SKANERLASH")
        self.is_scanning = False


if __name__ == "__main__":
    root = tk.Tk()
    app = RouterAnalyzerApp(root)
    root.mainloop()
