import asyncio
import os
import socket
import threading
import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk

# CustomTkinter ko'rinish sozlamalari
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

SYSTEM_INSTRUCTION = """
Siz tarmoq mutaxassisi va router tahlilchi AI agentisiz.
Foydalanuvchi router IP manzilini kiritganda:
1. Ushbu IP manzilning subnet diapazonini aniqlang.
2. Tarmoqda odatda qanday qurilmalar bo'lishi mumkinligini jadval shaklida tushuntiring.
3. IPv4 va IPv6 arxitekturasidagi farqlarni va local tarmoqda ularning tutgan o'rnini ko'rsating.
Javobingiz aniq, strukturatli va o'zbek tilida bo'lsin.
"""

class RouterAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Google Antigravity — Router & Tarmoq Tahlilchisi (Visual GUI)")
        self.geometry("1100x780")
        self.minsize(950, 680)

        # Asosiy layout (2 ta ustun: Chapda sozlamalar, O'ngda natijalar)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._create_sidebar()
        self._create_main_content()

        # Dastlabki avtomatik tahlil
        self.analyze_locally()

    def _create_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=320, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        sidebar.grid_rowconfigure(12, weight=1)

        # Logo / Title
        logo_label = ctk.CTkLabel(
            sidebar, 
            text="📡 Router Tahlilchi", 
            font=ctk.CTkFont(size=22, weight="bold")
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        sub_logo = ctk.CTkLabel(
            sidebar, 
            text="Google Antigravity Network Agent", 
            font=ctk.CTkFont(size=12),
            text_color="gray70"
        )
        sub_logo.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")

        # Router IP input
        ctk.CTkLabel(sidebar, text="Router IP Manzili:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, padx=20, pady=(5, 2), sticky="w")
        self.ip_entry = ctk.CTkEntry(sidebar, placeholder_text="masalan, 192.168.1.1")
        self.ip_entry.insert(0, "192.168.1.1")
        self.ip_entry.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="ew")

        # Tezkor tanlash tugmalari
        quick_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        quick_frame.grid(row=4, column=0, padx=20, pady=(0, 15), sticky="ew")
        for i, tip in enumerate(["192.168.1.1", "192.168.0.1", "10.0.0.1"]):
            btn = ctk.CTkButton(
                quick_frame, 
                text=tip, 
                width=80, 
                height=26, 
                font=ctk.CTkFont(size=11),
                fg_color="gray30", 
                hover_color="gray40",
                command=lambda p=tip: self._set_ip(p)
            )
            btn.grid(row=0, column=i, padx=2)

        # Subnet Mask tanlash
        ctk.CTkLabel(sidebar, text="Subnet Mask (CIDR):", font=ctk.CTkFont(weight="bold")).grid(row=5, column=0, padx=20, pady=(5, 2), sticky="w")
        self.cidr_combobox = ctk.CTkComboBox(
            sidebar, 
            values=["/24 (255.255.255.0 - 254 xost)", "/23 (255.255.254.0 - 510 xost)", "/16 (255.255.0.0 - 65,534 xost)", "/8 (255.0.0.0 - 16M xost)"],
            state="readonly"
        )
        self.cidr_combobox.set("/24 (255.255.255.0 - 254 xost)")
        self.cidr_combobox.grid(row=6, column=0, padx=20, pady=(0, 15), sticky="ew")

        # Gemini API Key (Ixtiyoriy)
        ctk.CTkLabel(sidebar, text="Gemini API Key (AI uchun, ixtiyoriy):", font=ctk.CTkFont(size=12, weight="bold")).grid(row=7, column=0, padx=20, pady=(5, 2), sticky="w")
        self.api_key_entry = ctk.CTkEntry(sidebar, placeholder_text="AIzaSy... yoki env dan olinadi", show="•")
        if "GEMINI_API_KEY" in os.environ:
            self.api_key_entry.insert(0, os.environ["GEMINI_API_KEY"])
        self.api_key_entry.grid(row=8, column=0, padx=20, pady=(0, 15), sticky="ew")

        # Amallar tugmalari
        self.btn_analyze = ctk.CTkButton(
            sidebar, 
            text="🚀 Tezkor Tahlil (Lokal)", 
            height=38,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.analyze_locally
        )
        self.btn_analyze.grid(row=9, column=0, padx=20, pady=(10, 8), sticky="ew")

        self.btn_ai_analyze = ctk.CTkButton(
            sidebar, 
            text="🤖 Antigravity AI Tahlili", 
            height=38,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1a73e8",
            hover_color="#1558b0",
            command=self.start_ai_analysis
        )
        self.btn_ai_analyze.grid(row=10, column=0, padx=20, pady=(0, 10), sticky="ew")

        self.btn_detect_ip = ctk.CTkButton(
            sidebar, 
            text="📍 O'z Gateway IP-ni topish", 
            height=30,
            fg_color="gray25",
            hover_color="gray35",
            command=self.detect_local_gateway
        )
        self.btn_detect_ip.grid(row=11, column=0, padx=20, pady=(0, 15), sticky="ew")

        # Status & Progress bar
        self.progress_bar = ctk.CTkProgressBar(sidebar, height=8, mode="indeterminate")
        self.progress_bar.grid(row=13, column=0, padx=20, pady=(10, 5), sticky="ew")
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            sidebar, 
            text="Holat: Tayyor", 
            font=ctk.CTkFont(size=12),
            text_color="#4ade80"
        )
        self.status_label.grid(row=14, column=0, padx=20, pady=(0, 20), sticky="w")

    def _create_main_content(self):
        # Asosiy tabview
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.tab_subnet = self.tabview.add("📊 Subnet & Metrikalar")
        self.tab_devices = self.tabview.add("🗺️ Qurilmalar Xaritasi")
        self.tab_ipv = self.tabview.add("🌐 IPv4 vs IPv6")
        self.tab_ai = self.tabview.add("🤖 Antigravity AI Natijasi")

        self._build_subnet_tab()
        self._build_devices_tab()
        self._build_ipv_tab()
        self._build_ai_tab()

    def _build_subnet_tab(self):
        container = ctk.CTkScrollableFrame(self.tab_subnet, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(container, text="Lokal Tarmoq Arxitekturasi va Subnet Hisobi", font=ctk.CTkFont(size=18, weight="bold"))
        header.pack(anchor="w", pady=(0, 15))

        # Metrika kartalari (Grid shaklida)
        cards_frame = ctk.CTkFrame(container)
        cards_frame.pack(fill="x", pady=10)
        cards_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.card_net_id = self._create_card(cards_frame, 0, 0, "Tarmoq Manzili (Network ID)", "192.168.1.0/24")
        self.card_gateway = self._create_card(cards_frame, 0, 1, "Standart Gateway (Router)", "192.168.1.1")
        self.card_broadcast = self._create_card(cards_frame, 0, 2, "Broadcast Manzili", "192.168.1.255")
        
        self.card_hosts = self._create_card(cards_frame, 1, 0, "Mavjud Xostlar Soni", "254 ta")
        self.card_usable_range = self._create_card(cards_frame, 1, 1, "Ishlatiladigan IP oralig'i", "192.168.1.1 - 192.168.1.254")
        self.card_dhcp_pool = self._create_card(cards_frame, 1, 2, "Tavsiya etilgan DHCP Pool", "192.168.1.100 - 192.168.1.250")

        # Tavsif bo'limi
        info_frame = ctk.CTkFrame(container)
        info_frame.pack(fill="x", pady=15)
        
        info_title = ctk.CTkLabel(info_frame, text="📌 Xavfsizlik va Segmentatsiya Bo'yicha Tavsiyalar:", font=ctk.CTkFont(size=14, weight="bold"))
        info_title.pack(anchor="w", padx=15, pady=(12, 6))

        self.subnet_info_text = ctk.CTkLabel(
            info_frame,
            text=(
                "• 192.168.1.1 - Standart C-Class xususiy IP manzili (RFC 1918 bo'yicha global internetda yo'naltirilmaydi).\n"
                "• Router boshqaruv paneli (Web GUI) parolini standart 'admin'dan murakkab parolga o'zgartirish lozim.\n"
                "• IoT (aqlli uy) va Mehmon (Guest) qurilmalari uchun alohida VLAN yoki Guest Wi-Fi tarmog'ini ajrating.\n"
                "• Serverlar va Tarmoq printerlari uchun 192.168.1.2 - 192.168.1.30 oralig'ida statik IP zaxirasi saqlang."
            ),
            justify="left",
            font=ctk.CTkFont(size=13),
            text_color="gray85"
        )
        self.subnet_info_text.pack(anchor="w", padx=15, pady=(0, 15))

    def _create_card(self, parent, row, col, title, value):
        card = ctk.CTkFrame(parent, fg_color="gray20", corner_radius=8)
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        
        t_label = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color="gray70")
        t_label.pack(anchor="w", padx=12, pady=(10, 2))
        
        v_label = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8")
        v_label.pack(anchor="w", padx=12, pady=(0, 10))
        return v_label

    def _build_devices_tab(self):
        container = ctk.CTkScrollableFrame(self.tab_devices, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(container, text="Lokal Tarmoqdagi Qurilmalar Taqsimoti va Xaritasi", font=ctk.CTkFont(size=18, weight="bold"))
        header.pack(anchor="w", pady=(0, 15))

        devices_data = [
            ("🌐 Router / Gateway", "192.168.1.1", "Statik", "DNS, DHCP, NAT, WebGUI", "Butun tarmoq shlyuzi. Admin parolini himoyalang."),
            ("📶 Switch / Access Point", "192.168.1.2 – 192.168.1.9", "Statik", "SSH, SNMP, HTTPS", "Tarmoq qamrovi va kommutatsiyasini boshqaradi."),
            ("🖨️ Printer & NAS Server", "192.168.1.10 – 192.168.1.30", "Statik / Rezervatsiya", "IPP, SMB, NFS, FTP", "Boshqa qurilmalar qulay topishi uchun statik IP beriladi."),
            ("💻 Shaxsiy Kompyuter / PC", "192.168.1.100 – 192.168.1.140", "DHCP", "TCP/UDP, SMB, RDP", "Asosiy ishchi stansiyalar, yuqori tezlik talab etadi."),
            ("📱 Smartfon va Planshetlar", "192.168.1.141 – 192.168.1.190", "DHCP", "Wi-Fi (WPA3), mDNS", "Dinamik xostlar; doimiy ulanib-uzilib turadi."),
            ("📺 Smart TV & Mediaplayer", "192.168.1.191 – 192.168.1.215", "DHCP", "DLNA, Cast, SSDP, RTSP", "Streaming video va multimedia qurilmalari."),
            ("💡 IoT & Aqlli Uy Qurilmalari", "192.168.1.216 – 192.168.1.254", "DHCP (Izolyatsiyalangan)", "MQTT, CoAP, Zigbee/Bridge", "Xavfsizlik uchun alohida Guest yoki IoT VLAN ga o'tkazish shart.")
        ]

        for icon_title, ip_range, assign_type, protos, note in devices_data:
            d_card = ctk.CTkFrame(container, fg_color="gray20", corner_radius=8)
            d_card.pack(fill="x", pady=6)

            top_row = ctk.CTkFrame(d_card, fg_color="transparent")
            top_row.pack(fill="x", padx=12, pady=(10, 2))

            ctk.CTkLabel(top_row, text=icon_title, font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc").pack(side="left")
            ctk.CTkLabel(top_row, text=f"IP Oralig'i: {ip_range}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(side="right")

            bot_row = ctk.CTkFrame(d_card, fg_color="transparent")
            bot_row.pack(fill="x", padx=12, pady=(2, 10))

            meta_text = f"Taqsimot: {assign_type}  |  Protokollar: {protos}\nIzoh: {note}"
            ctk.CTkLabel(bot_row, text=meta_text, justify="left", font=ctk.CTkFont(size=12), text_color="gray75").pack(anchor="w")

    def _build_ipv_tab(self):
        container = ctk.CTkScrollableFrame(self.tab_ipv, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(container, text="IPv4 va IPv6 Arxitekturasi Taqqoslashi", font=ctk.CTkFont(size=18, weight="bold"))
        header.pack(anchor="w", pady=(0, 15))

        comparisons = [
            ("Manzil Hajmi & Format", "32-bit (masalan: 192.168.1.10)", "128-bit (masalan: 2001:db8::1 yoki fe80::1)"),
            ("Umumiy Sig'im", "~4.3 milliard manzil (tanqislik mavjud)", "~3.4 × 10³⁸ manzil (deyarli cheksiz)"),
            ("NAT (Tarmoq manzilini o'zgartirish)", "Majburiy (Xususiy IP-lar yagona global IP ortida)", "Kerak emas (Har bir qurilmada global unikal IP bo'lishi mumkin)"),
            ("Manzil Konfiguratsiyasi", "Asosan DHCP orqali yoki qo'lda statik", "SLAAC (Stateless Auto-Config) yoki DHCPv6"),
            ("Lokal Aloqa (Link-Local)", "APIPA (169.254.0.0/16) - ixtiyoriy/nosozlikda", "Majburiy va standart: fe80::/10 har bir interfeysda"),
            ("Kesh va Qo'shnilarni Topish", "ARP (Broadcast so'rovlar - tarmoqni band qiladi)", "NDP (ICMPv6 Multicast - ancha samarali va tez)"),
            ("Xavfsizlik Arxitekturasi", "IPsec qo'shimcha protokol sifatida ulanadi", "IPsec boshidanoq arxitektura ichiga singdirilgan")
        ]

        for feature, v4, v6 in comparisons:
            row_frame = ctk.CTkFrame(container, fg_color="gray20", corner_radius=8)
            row_frame.pack(fill="x", pady=5)
            row_frame.grid_columnconfigure(0, weight=1)
            row_frame.grid_columnconfigure(1, weight=1)

            title_lbl = ctk.CTkLabel(row_frame, text=f"📌 {feature}", font=ctk.CTkFont(size=13, weight="bold"), text_color="#f8fafc")
            title_lbl.grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 4))

            v4_box = ctk.CTkFrame(row_frame, fg_color="gray15", corner_radius=6)
            v4_box.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
            ctk.CTkLabel(v4_box, text="IPv4:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#fb923c").pack(anchor="w", padx=8, pady=(4, 0))
            ctk.CTkLabel(v4_box, text=v4, font=ctk.CTkFont(size=12), text_color="gray85", wraplength=350, justify="left").pack(anchor="w", padx=8, pady=(0, 6))

            v6_box = ctk.CTkFrame(row_frame, fg_color="gray15", corner_radius=6)
            v6_box.grid(row=1, column=1, padx=8, pady=(0, 8), sticky="nsew")
            ctk.CTkLabel(v6_box, text="IPv6:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=8, pady=(4, 0))
            ctk.CTkLabel(v6_box, text=v6, font=ctk.CTkFont(size=12), text_color="gray85", wraplength=350, justify="left").pack(anchor="w", padx=8, pady=(0, 6))

    def _build_ai_tab(self):
        container = ctk.CTkFrame(self.tab_ai, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        top_info = ctk.CTkLabel(
            container, 
            text="Google Antigravity AI Agent real-vaqt rejimida tahlil natijalari:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        top_info.pack(anchor="w", pady=(0, 8))

        self.ai_output_textbox = ctk.CTkTextbox(container, font=ctk.CTkFont(family="Consolas", size=13), wrap="word")
        self.ai_output_textbox.pack(fill="both", expand=True, pady=(0, 10))
        self.ai_output_textbox.insert(
            "1.0", 
            "Antigravity AI Agentining jonli tahlilini olish uchun chap menyudagi '🤖 Antigravity AI Tahlili' tugmasini bosing.\n"
            "Eslatma: AI funksiyasi uchun Gemini API kalit zarur bo'ladi.\n"
        )

    def _set_ip(self, ip_val):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip_val)
        self.analyze_locally()

    def detect_local_gateway(self):
        try:
            # Lokal IP va gateway aniqlash
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Odatda shlyuz shu subnetning .1 manzili bo'ladi
            parts = local_ip.split(".")
            suggested_gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            self._set_ip(suggested_gw)
            messagebox.showinfo("Gateway aniqlandi", f"Sizning lokal IP: {local_ip}\nTaxminiy Router Gateway: {suggested_gw}")
        except Exception as e:
            messagebox.showwarning("Xatolik", f"Lokal gatewayni aniqlab bo'lmadi:\n{e}")

    def analyze_locally(self):
        ip_str = self.ip_entry.get().strip()
        cidr_str = self.cidr_combobox.get().split()[0]  # masalan "/24"
        prefix = int(cidr_str.replace("/", ""))

        try:
            # IP validation
            ip_obj = ipaddress.IPv4Address(ip_str)
            network = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)

            net_id = str(network.network_address) + f"/{prefix}"
            broadcast = str(network.broadcast_address)
            num_hosts = network.num_addresses - 2 if network.num_addresses > 2 else 1

            first_host = str(network.network_address + 1)
            last_host = str(network.broadcast_address - 1)
            usable_range = f"{first_host} — {last_host}"

            # DHCP Pool taxminiy
            dhcp_start = str(network.network_address + 100) if network.num_addresses > 150 else first_host
            dhcp_end = str(network.broadcast_address - 5) if network.num_addresses > 150 else last_host
            dhcp_pool = f"{dhcp_start} — {dhcp_end}"

            # Kartalarni yangilash
            self.card_net_id.configure(text=net_id)
            self.card_gateway.configure(text=ip_str)
            self.card_broadcast.configure(text=broadcast)
            self.card_hosts.configure(text=f"{num_hosts:,} ta")
            self.card_usable_range.configure(text=usable_range)
            self.card_dhcp_pool.configure(text=dhcp_pool)

            self.status_label.configure(text="Holat: Lokal hisob muvaffaqiyatli!", text_color="#4ade80")

        except ValueError as ve:
            self.status_label.configure(text="Holat: Noto'g'ri IP manzil!", text_color="#f87171")
            messagebox.showerror("IP Xatolik", f"Kiritilgan IP manzil noto'g'ri:\n{ve}")

    def start_ai_analysis(self):
        ip_str = self.ip_entry.get().strip()
        api_key = self.api_key_entry.get().strip() or os.environ.get("GEMINI_API_KEY")

        if not api_key:
            messagebox.showwarning(
                "API Kalit Zarur", 
                "Google Antigravity AI Agentidan foydalanish uchun Gemini API kalitini chap menyudagi maydonga kiriting yoki GEMINI_API_KEY muhit o'zgaruvchisiga o'rnating.\n\nLokal vizual tahlil esa kalitsiz ham to'liq ishlaydi!"
            )
            return

        self.tabview.set("🤖 Antigravity AI Natijasi")
        self.ai_output_textbox.delete("1.0", tk.END)
        self.ai_output_textbox.insert("1.0", f"[+] Google Antigravity Agent router tahlilini boshlamoqda: {ip_str}...\n\n")

        self.status_label.configure(text="Holat: AI tahlil qilmoqda...", text_color="#38bdf8")
        self.progress_bar.start()
        self.btn_ai_analyze.configure(state="disabled")

        # Fon oqimida ishga tushirish (GUI muzlab qolmasligi uchun)
        threading.Thread(target=self._run_ai_thread, args=(ip_str, api_key), daemon=True).start()

    def _run_ai_thread(self, router_ip, api_key):
        async def _exec():
            try:
                from google.antigravity import Agent, LocalAgentConfig
                config = LocalAgentConfig(
                    system_instructions=SYSTEM_INSTRUCTION,
                    api_key=api_key
                )
                async with Agent(config) as agent:
                    prompt = f"Mening routerim IP manzili: {router_ip}. Ushbu tarmoq uchun to'liq tahlil va ulangan qurilmalar xaritasini tuzib ber."
                    response = await agent.chat(prompt)
                    async for token in response:
                        self._append_ai_token(token)
                self._ai_finished(True)
            except Exception as e:
                self._append_ai_token(f"\n\n[XATOLIK]: {str(e)}\n")
                self._ai_finished(False)

        asyncio.run(_exec())

    def _append_ai_token(self, token):
        self.after(0, lambda: self._safe_append(token))

    def _safe_append(self, token):
        self.ai_output_textbox.insert(tk.END, token)
        self.ai_output_textbox.see(tk.END)

    def _ai_finished(self, success):
        def _finish():
            self.progress_bar.stop()
            self.progress_bar.set(0)
            self.btn_ai_analyze.configure(state="normal")
            if success:
                self.status_label.configure(text="Holat: AI tahlili yakunlandi!", text_color="#4ade80")
            else:
                self.status_label.configure(text="Holat: AI tahlilida xatolik!", text_color="#f87171")
        self.after(0, _finish)


if __name__ == "__main__":
    app = RouterAnalyzerApp()
    app.mainloop()
