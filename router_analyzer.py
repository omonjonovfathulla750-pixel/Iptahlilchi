import asyncio
import os
import sys
from google.antigravity import Agent, LocalAgentConfig

# 1. Antigravity Agent uchun yo'riqnoma va tizim ko'rsatmasi
SYSTEM_INSTRUCTION = """
Siz tarmoq mutaxassisi va router tahlilchi AI agentisiz.
Foydalanuvchi router IP manzilini kiritganda (masalan, 192.168.1.1 yoki 192.168.0.1):
1. Ushbu IP manzilning subnet diapazonini aniqlang (masalan, 192.168.1.0/24).
2. Tarmoqda odatda qanday qurilmalar (Smartfonlar, Kompyuterlar, IoT, Smart TV, Printyerlar) bo'lishi mumkinligini jadval shaklida tushuntirib bering.
3. IPv4 va IPv6 arxitekturasidagi farqlarni va local tarmoqda ularning tutgan o'rnini ko'rsating.
Javobingiz aniq, strukturatli va o'zbek tilida bo'lsin.
"""

async def run_router_analyzer(router_ip: str, api_key: str | None = None):
    print(f"\n[+] Google Antigravity Agent router IP tahlilini boshlamoqda: {router_ip}...\n")
    
    # 2. Antigravity Agent konfiguratsiyasini sozlash
    config_args = {"system_instructions": SYSTEM_INSTRUCTION}
    if api_key:
        config_args["api_key"] = api_key
    elif "GEMINI_API_KEY" in os.environ:
        config_args["api_key"] = os.environ["GEMINI_API_KEY"]

    config = LocalAgentConfig(**config_args)
    
    # 3. Agentni asinxron context manager orqali ishga tushirish
    async with Agent(config) as agent:
        prompt = f"Mening routerim IP manzili: {router_ip}. Ushbu tarmoq uchun to'liq tahlil va ulangan qurilmalar xaritasini tuzib ber."
        
        # Stream javobini olish
        response = await agent.chat(prompt)
        
        # Real-vaqt rejimida natijani konsolga chiqarish (streaming token)
        async for token in response:
            sys.stdout.write(token)
            sys.stdout.flush()
            
        print("\n\n[✓] Tahlil muvaffaqiyatli yakunlandi!")

def main():
    if "--cli" in sys.argv:
        router_ip = input("Router IP manzilini kiriting (masalan, 192.168.1.1): ").strip()
        if not router_ip:
            router_ip = "192.168.1.1"

        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            api_key = input("Gemini API kalitini kiriting (yoki bo'sh qoldirish uchun Enter bosing): ").strip() or None
            
        asyncio.run(run_router_analyzer(router_ip, api_key=api_key))
    else:
        # Standart holatda vizual grafik interfeysni (GUI) ishga tushiramiz
        from router_analyzer_gui import RouterAnalyzerApp
        app = RouterAnalyzerApp()
        app.mainloop()

if __name__ == "__main__":
    main()
