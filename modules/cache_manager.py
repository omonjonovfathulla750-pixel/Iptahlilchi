"""
Cache Manager - SQLite va Xotira (In-Memory) asosidagi tezkor kesh moduli.
Takroriy so'rovlarni 0.001 soniyada chiqarib beradi va API limitlarini tejaydi.
"""

import sqlite3
import json
import time
import os
import threading

class CacheManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path="cache.db"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(CacheManager, cls).__new__(cls)
                cls._instance._init_db(db_path)
            return cls._instance

    def _init_db(self, db_path):
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), db_path)
        self.mem_cache = {}
        self.stats = {"hits": 0, "misses": 0}
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_store (
                    key TEXT PRIMARY KEY,
                    category TEXT,
                    value TEXT,
                    expires_at REAL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_store(expires_at)")
            conn.commit()

    def get(self, key: str):
        now = time.time()
        # 1. Tezkor xotiradan qidirish
        if key in self.mem_cache:
            entry = self.mem_cache[key]
            if entry["expires_at"] > now:
                self.stats["hits"] += 1
                return entry["value"]
            else:
                del self.mem_cache[key]

        # 2. SQLite bazasidan qidirish
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value, expires_at FROM cache_store WHERE key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    val_json, expires_at = row
                    if expires_at > now:
                        val = json.loads(val_json)
                        self.mem_cache[key] = {"value": val, "expires_at": expires_at}
                        self.stats["hits"] += 1
                        return val
                    else:
                        cursor.execute("DELETE FROM cache_store WHERE key = ?", (key,))
                        conn.commit()
        except Exception:
            pass

        self.stats["misses"] += 1
        return None

    def set(self, key: str, value, ttl_seconds: int = 86400, category: str = "general"):
        now = time.time()
        expires_at = now + ttl_seconds
        
        # Xotiraga yozish
        self.mem_cache[key] = {"value": value, "expires_at": expires_at}
        
        # SQLite ga yozish
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cache_store (key, category, value, expires_at)
                    VALUES (?, ?, ?, ?)
                """, (key, category, json.dumps(value, ensure_ascii=False), expires_at))
                conn.commit()
        except Exception as e:
            print(f"Cache save error: {e}")

    def clear_expired(self):
        now = time.time()
        # Xotiradan tozalash
        expired_mem = [k for k, v in self.mem_cache.items() if v["expires_at"] <= now]
        for k in expired_mem:
            del self.mem_cache[k]
            
        # Bazadan tozalash
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache_store WHERE expires_at <= ?", (now,))
                conn.commit()
        except Exception:
            pass

    def get_stats(self):
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_ratio = round((self.stats["hits"] / total_requests) * 100, 1) if total_requests > 0 else 0
        
        db_entries = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cache_store")
                db_entries = cursor.fetchone()[0]
        except Exception:
            pass

        return {
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "total_requests": total_requests,
            "hit_ratio_percent": hit_ratio,
            "cached_entries_count": db_entries
        }

cache = CacheManager()
