# 🛡️ CyberNet Pro — Kiberxavfsizlik va Tarmoq Tahlili Platformasi

Zamonaviy **FastAPI**, **Leaflet.js**, **Chart.js** va kiberxavfsizlik modullari asosida yaratilgan to'liq tarmoq monitoringi, IP intellekti (Threat Intelligence) va xavfsizlik boshqaruv tizimi.

---

## 🌟 6 ta Asosiy Imkoniyatlar (Yo'nalishlar)

### 1. 🛡️ IP Xavfsizlik & Threat Intelligence
- **Risk Score (0–100%):** IP manzilning umumiy xavflilik darajasi (Safe, Low, Suspicious, Dangerous).
- **DNSBL / RBL Qora Ro'yxatlar:** Jahonning 5 ta yetakchi xavfsizlik bazasi (*Spamhaus ZEN, Barracuda RBL, SpamCop, SORBS, Abuseat CBL*) orqali tekshirish.
- **VPN / Proksi / Tor / Datacenter:** Tashrif buyuruvchi yoki shubhali IP orqasida yashiringan proksilarni bir zumda aniqlash.
- **AbuseIPDB integratsiyasi:** API kalit orqali 90 kunlik zararli faoliyat hisobotlarini olish.

### 2. 🌐 Chuqur Tarmoq Tahlili (Network Intel & WHOIS)
- **Geolokatsiya va ASN:** IP joylashuvi (davlat, shahar, xarita koordinatalari), provayder (ISP), tashkilot va Autonom Tizim (ASN).
- **Reverse DNS (PTR):** IP ga biriktirilgan domen yoki xost nomlarini fosh qilish.
- **Ko'p oqimli Port Skaner & Banner Grabbing:** 25 ta asosiy tarmoq portlari (SSH, HTTP, HTTPS, RDP, MySQL, Redis, MongoDB va h.k.) holati va ularning dasturiy versiyalari (masalan, `OpenSSH_8.9`, `nginx/1.18`).

### 3. 📊 Server Log va Ommaviy Tahlilchi (Log & Batch Analyzer)
- **Ko'p formatli tahlil:** Nginx, Apache, Linux Auth.log va boshqa server loglarini o'qish.
- **Anomaliyalar detektori:**
  - Eng ko'p so'rov yuborgan IP lar (DDoS va crawler shubhasi).
  - SSH Brute-Force parol buzish urinishlari va foydalanuvchi nomlari.
  - Veb zaifliklarni qidirish (`/wp-admin`, `/.env`, `/.git`, `/phpmyadmin`, directory traversal).
- **Top Ro'yxatlar:** 4xx/5xx xatolar generatsiya qilgan tajovuzkor IP lar statistikasi.

### 4. 🗺️ Dunyo Xaritasi va Vizualizatsiya (Geo-Mapping)
- **Interaktiv Kiberxarita:** *Leaflet.js* orqali tahlil qilingan va aniqlangan IP larni jahon xaritasida rangli nuqtalar (xavflilik darajasiga qarab yashil, sariq, qizil) bilan ko'rsatish.
- **Har bir markerda to'liq dosye:** Davlat, shahar, provayder va xavf foizi.

### 5. 🚫 Avtomatlashtirish & Firewall Qoidalari (Alerts & Action)
- **Bir Bosishda Bloklash:** Aniqlangan xavfli IP lar uchun darhol buyruq generatsiya qilish:
  - Linux UFW: `sudo ufw insert 1 deny from <IP> to any`
  - Linux IPTables: `sudo iptables -I INPUT -s <IP> -j DROP`
  - Windows PowerShell: `New-NetFirewallRule ...`
  - Windows Netsh: `netsh advfirewall ...`
  - Nginx: `deny <IP>;`
  - Mikrotik RouterOS: `/ip firewall filter add ...`
- **Tayyor skriptlarni yuklab olish:** Barcha xavfli IP lar ro'yxatini birdaniga `.sh` yoki `.ps1` qilib yuklab olish.
- **Telegram Bot:** Xavfli IP yoki tarmoqqa yangi begona qurilma ulanganda administratorga avtomatik ogohlantirish xabari yuborish.

### 6. ⚡ Kesh va Yuqori Tezlik (Performance & Cache)
- **SQLite + Xotira Kesh Tizimi:** Takroriy so'rovlar tashqi API ga bormay, 0.001 soniyada chiqariladi.
- **Limitlarni tejash:** Internet trafigi va API limitlarini 90% gacha iqtisod qiladi.
- **Asinxron va Multi-threaded:** 250 tagacha parallel oqimda tezkor tarmoq tekshiruvi.

---

## 📁 Loyiha Strukturasi

```
network_analyzer/
├── modules/
│   ├── __init__.py
│   ├── cache_manager.py     # SQLite va in-memory kesh
│   ├── threat_intel.py      # DNSBL, VPN/Proxy/Tor va Risk Score
│   ├── network_intel.py     # WHOIS, ASN, Port Scanner & Banner Grabbing
│   ├── log_analyzer.py      # Log parser, anomaliyalar & Brute-force
│   ├── firewall_rules.py    # UFW, IPTables, Windows, Nginx bloklash
│   └── telegram_alerts.py   # Telegram xabarnomalar boti
├── templates/
│   └── dashboard.html       # 6 ta yo'nalishli zamonaviy Web SPA Dashboard
├── main.py                  # FastAPI asosiy backend va API lari
├── requirements.txt         # Kerakli kutubxonalar
├── start_server.bat         # 1-klikda ishga tushirish (Windows)
└── README.md                # Hujjat
```

---

## 🚀 Ishga Tushirish

1. Kutubxonalarni o'rnatish:
```bash
pip install -r requirements.txt
```

2. Tizimni ishga tushirish:
```bash
python main.py
```
yoki Windows'da `start_server.bat` faylini ikki marta bosing.

3. Brauzerda ochish:
```text
http://127.0.0.1:8000
```
