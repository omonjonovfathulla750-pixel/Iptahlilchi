"""
Telegram Alerts Module - Shubhali IP lar va hujumlar haqida Telegram orqali xabar yuborish.
"""

import requests
import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "telegram_config.json")

class TelegramNotifier:
    def __init__(self):
        self.bot_token = ""
        self.chat_id = ""
        self.enabled = False
        self.load_config()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.bot_token = data.get("bot_token", "")
                    self.chat_id = data.get("chat_id", "")
                    self.enabled = data.get("enabled", False)
            except Exception:
                pass

    def save_config(self, bot_token: str, chat_id: str, enabled: bool = True):
        self.bot_token = bot_token.strip()
        self.chat_id = chat_id.strip()
        self.enabled = enabled
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "bot_token": self.bot_token,
                    "chat_id": self.chat_id,
                    "enabled": self.enabled
                }, f, indent=4)
            return True
        except Exception:
            return False

    def send_message(self, text: str):
        if not self.enabled or not self.bot_token or not self.chat_id:
            return False, "Telegram sozlamalari kiritilmagan yoki o'chirilgan."

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }

        try:
            resp = requests.post(url, json=payload, timeout=5)
            if resp.status_code == 200:
                return True, "Xabarnoma muvaffaqiyatli yuborildi."
            else:
                return False, f"Telegram xatosi: {resp.text}"
        except Exception as e:
            return False, f"Ulanish xatosi: {str(e)}"

    def alert_dangerous_ip(self, ip_data: dict):
        """Xavfli IP aniqlanganda darhol xabarnoma yuborish"""
        ip = ip_data.get("ip", "Noma'lum")
        score = ip_data.get("risk_score", 0)
        level = ip_data.get("risk_level", "Xavfli")
        isp = ip_data.get("isp", "Noma'lum")
        country = ip_data.get("country", "Noma'lum")
        city = ip_data.get("city", "")
        summary = ip_data.get("summary", "")

        msg = (
            f"🚨 <b>KIBERXAVFSIZLIK OGOHLANTIRISHI!</b>\n\n"
            f"⚠️ <b>Shubhali / Xavfli IP aniqlandi:</b> <code>{ip}</code>\n"
            f"📊 <b>Xavf darajasi:</b> {score}% ({level})\n"
            f"🌍 <b>Joylashuv:</b> {city}, {country}\n"
            f"🏢 <b>Provayder:</b> {isp}\n"
            f"🔍 <b>Tafsilot:</b> {summary}\n\n"
            f"🛡️ <i>Tizim administratoriga zudlik bilan ushbu IP manzilni bloklash tavsiya etiladi.</i>"
        )
        return self.send_message(msg)

    def alert_new_device(self, device: dict):
        """Lokal tarmoqqa yangi begona qurilma ulanganda"""
        ip = device.get("ip", "")
        mac = device.get("mac", "")
        name = device.get("name", "Noma'lum qurilma")
        category = device.get("category", "")

        msg = (
            f"🔔 <b>YANGI QURILMA TARMOQQA ULANDI</b>\n\n"
            f"💻 <b>Qurilma:</b> {name}\n"
            f"🌐 <b>IP manzil:</b> <code>{ip}</code>\n"
            f"📟 <b>MAC manzil:</b> <code>{mac}</code>\n"
            f"🏷️ <b>Turi:</b> {category}\n\n"
            f"ℹ️ <i>Agar bu qurilma sizga tegishli bo'lmasa, tarmoq xavfsizligini tekshiring!</i>"
        )
        return self.send_message(msg)

telegram_notifier = TelegramNotifier()
