#!/usr/bin/env python3
"""
Onyx VPN — Smart Server Health Manager
=======================================
يحل مشكلة موت السيرفرات داخل التطبيق نفسه بـ 3 طبقات:

  طبقة 1 — Health Cache : يفحص كل سيرفر كل 90 ثانية في الخلفية
  طبقة 2 — Auto-Heal    : لو سيرفر مات → يجيب بديل حي من servers.json فوراً
  طبقة 3 — Remote Sync  : كل 5 دقائق يجلب آخر نسخة من GitHub

الاستخدام:
    from server_health import ServerHealthManager, get_best_server

    # في بداية التطبيق
    manager = ServerHealthManager(servers_json_path="servers.json")
    await manager.start()

    # لما تحتاج سيرفر
    server = manager.get_best_server()
    if server:
        use(server["link"])
"""

import asyncio
import base64
import ipaddress
import json
import logging
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp

# ── إعدادات ──────────────────────────────────────────────────
TCP_TIMEOUT          = 4.0
HEALTH_CHECK_EVERY   = 90       # ثانية — فحص دوري لكل سيرفر
REMOTE_SYNC_EVERY    = 300      # ثانية — جلب آخر servers.json من GitHub
FAIL_THRESHOLD       = 2        # عدد فشل متتالي قبل إعلان السيرفر ميتاً
MAX_CONCURRENCY      = 10       # حد التوازي للفحص الداخلي
MIN_PING_VALID       = 10
MAX_PING             = 1200
GUARANTEED_ALIVE_MIN = 3        # الحد الأدنى من السيرفرات الحية المضمونة

# رابط raw لـ servers.json على GitHub — عدّله لـ repo تبعك
REMOTE_URL = "https://raw.githubusercontent.com/akramfaeq/Upload/main/servers.json"

log = logging.getLogger("onyx.health")


# ══════════════════════════════════════════════════════════════
#  CDN Filter
# ══════════════════════════════════════════════════════════════
_CDN_RANGES = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
    "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15",
    "172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
    "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
    "151.101.0.0/16","199.232.0.0/16",
]
_cdn_nets: list = []

def _build_cdn():
    for c in _CDN_RANGES:
        try: _cdn_nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError: pass

def _is_cdn(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in _cdn_nets)
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════
#  TCP Probe
# ══════════════════════════════════════════════════════════════
async def _tcp_ping(host: str, port: int) -> Optional[float]:
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT,
        )
        ms = (loop.time() - t0) * 1000
        w.close()
        try: await w.wait_closed()
        except: pass
        return ms
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
#  Extract host/port from link
# ══════════════════════════════════════════════════════════════
def _link_host_port(link: str) -> tuple[str, int]:
    try:
        uri = urllib.parse.urlparse(link)
        if link.startswith("vmess://"):
            raw = uri.netloc + uri.path
            raw += "=" * ((4 - len(raw) % 4) % 4)
            d = json.loads(base64.b64decode(raw).decode())
            return str(d.get("add", "")), int(d.get("port", 443))
        if link.startswith("ss://"):
            at = uri.netloc.split("@")
            if len(at) == 2:
                hp = at[1]
                if hp.startswith("["):
                    bi = hp.index("]")
                    return hp[1:bi], int(hp[bi+2:])
                h, p = hp.rsplit(":", 1)
                return h, int(p)
        return str(uri.hostname or ""), uri.port or 443
    except Exception:
        return "", 443


# ══════════════════════════════════════════════════════════════
#  Server State
# ══════════════════════════════════════════════════════════════
class ServerState:
    def __init__(self, info: dict):
        self.info        = info
        self.ping        = info.get("ping", 999)
        self.alive       = True
        self.fail_count  = 0
        self.last_check  = 0.0
        self.host, self.port = _link_host_port(info.get("link", ""))

    @property
    def score(self) -> float:
        if not self.alive:
            return -1
        ping_score = max(0, 100 - self.ping / 12)
        reality    = 20 if self.info.get("reality") else 0
        tls        = 10 if self.info.get("tls")     else 0
        return ping_score + reality + tls

    async def check(self) -> bool:
        if not self.host or _is_cdn(self.host):
            self.alive = False
            return False

        ms = await _tcp_ping(self.host, self.port)
        self.last_check = time.monotonic()

        if ms is None or ms < MIN_PING_VALID or ms > MAX_PING:
            self.fail_count += 1
            if self.fail_count >= FAIL_THRESHOLD:
                if self.alive:
                    log.warning(f"💀 Server died: {self.host}:{self.port} ({self.info.get('country','?')})")
                self.alive = False
            return False
        else:
            was_dead = not self.alive
            self.alive      = True
            self.fail_count = 0
            self.ping       = int(ms)
            self.info["ping"] = self.ping
            if was_dead:
                log.info(f"✅ Server recovered: {self.host}:{self.port} | {self.ping}ms")
            return True


# ══════════════════════════════════════════════════════════════
#  Server Health Manager
# ══════════════════════════════════════════════════════════════
class ServerHealthManager:
    """
    المدير الرئيسي — يعمل في الخلفية ويضمن إن عندك دايماً سيرفر حي.

    مثال:
        manager = ServerHealthManager("servers.json", remote_url=REMOTE_URL)
        await manager.start()
        ...
        server = manager.get_best_server()
    """

    def __init__(
        self,
        servers_json_path: str = "servers.json",
        remote_url: str = REMOTE_URL,
    ):
        self.path        = Path(servers_json_path)
        self.remote_url  = remote_url
        self._states:    list[ServerState] = []
        self._lock       = asyncio.Lock()
        self._session:   Optional[aiohttp.ClientSession] = None
        self._tasks:     list[asyncio.Task] = []
        self._last_sync  = 0.0
        self._started    = False
        _build_cdn()

    # ── تحميل الملف المحلي ──────────────────────────────────
    def _load_local(self) -> list[dict]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            servers = data.get("servers", [])
            log.info(f"📂 Loaded {len(servers)} servers from {self.path}")
            return servers
        except Exception as e:
            log.error(f"❌ Cannot load {self.path}: {e}")
            return []

    # ── جلب من GitHub ──────────────────────────────────────
    async def _fetch_remote(self) -> Optional[list[dict]]:
        if not self._session:
            return None
        try:
            async with self._session.get(
                self.remote_url,
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"Cache-Control": "no-cache"},
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                servers = data.get("servers", [])
                log.info(f"☁️  Remote sync: {len(servers)} servers fetched")
                return servers
        except Exception as e:
            log.debug(f"Remote sync failed: {e}")
            return None

    # ── تهيئة الحالة الداخلية ───────────────────────────────
    async def _init_states(self, servers: list[dict]):
        async with self._lock:
            existing = {
                f"{s.host}:{s.port}": s
                for s in self._states
            }
            new_states = []
            for srv in servers:
                h, p = _link_host_port(srv.get("link", ""))
                key = f"{h}:{p}"
                if key in existing:
                    # احتفظ بالحالة الموجودة (fail_count وغيره)
                    existing[key].info = srv
                    new_states.append(existing[key])
                else:
                    new_states.append(ServerState(srv))
            self._states = new_states

    # ── الحلقة الدورية للفحص ────────────────────────────────
    async def _health_loop(self):
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        async def _check_one(state: ServerState):
            async with semaphore:
                await state.check()

        while True:
            await asyncio.sleep(HEALTH_CHECK_EVERY)
            try:
                async with self._lock:
                    states_copy = list(self._states)

                tasks = [_check_one(s) for s in states_copy]
                await asyncio.gather(*tasks, return_exceptions=True)

                alive = sum(1 for s in states_copy if s.alive)
                log.info(f"🔍 Health check: {alive}/{len(states_copy)} alive")

                # لو عدد الأحياء أقل من الحد الأدنى → نحاول remote sync
                if alive < GUARANTEED_ALIVE_MIN:
                    log.warning(f"⚠️  Only {alive} alive servers! Forcing remote sync...")
                    await self._sync_remote(force=True)

            except Exception as e:
                log.error(f"Health loop error: {e}")

    # ── الحلقة الدورية للمزامنة مع GitHub ──────────────────
    async def _sync_loop(self):
        while True:
            await asyncio.sleep(REMOTE_SYNC_EVERY)
            await self._sync_remote()

    async def _sync_remote(self, force: bool = False):
        now = time.monotonic()
        if not force and (now - self._last_sync) < 60:
            return  # ما تزامن أكثر من مرة كل دقيقة

        servers = await self._fetch_remote()
        if servers:
            await self._init_states(servers)
            self._last_sync = now
            # حفظ نسخة محلية
            try:
                data = {"servers": servers, "synced_at": datetime.now(timezone.utc).isoformat()}
                tmp = self.path.with_suffix(".tmp")
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                tmp.replace(self.path)  # atomic replace — ما فيه race condition
            except Exception as e:
                log.debug(f"Local save failed: {e}")

    # ── بدء التشغيل ─────────────────────────────────────────
    async def start(self):
        if self._started:
            return
        self._started = True
        self._session = aiohttp.ClientSession()

        # تحميل محلي أولاً (سريع)
        servers = self._load_local()
        if servers:
            await self._init_states(servers)

        # محاولة remote sync فورية
        remote = await self._fetch_remote()
        if remote:
            await self._init_states(remote)
            self._last_sync = time.monotonic()
        elif not servers:
            log.error("❌ No servers available — check servers.json and REMOTE_URL")

        # تشغيل المهام الخلفية
        self._tasks = [
            asyncio.create_task(self._health_loop(), name="health-loop"),
            asyncio.create_task(self._sync_loop(),   name="sync-loop"),
        ]
        log.info(f"🚀 ServerHealthManager started — {len(self._states)} servers loaded")

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        if self._session:
            await self._session.close()
        self._started = False

    # ── الواجهة العامة ──────────────────────────────────────

    def get_best_server(self) -> Optional[dict]:
        """يرجع أفضل سيرفر حي (الأعلى score)."""
        alive = [s for s in self._states if s.alive]
        if not alive:
            # fallback — كل السيرفرات اللي عندنا حتى الميتة
            log.warning("⚠️  No alive servers! Returning any available server.")
            if self._states:
                return self._states[0].info
            return None
        best = max(alive, key=lambda s: s.score)
        return best.info

    def get_servers(self, count: int = 10, alive_only: bool = True) -> list[dict]:
        """يرجع قائمة مرتبة من السيرفرات."""
        states = [s for s in self._states if s.alive] if alive_only else self._states
        states.sort(key=lambda s: s.score, reverse=True)
        return [s.info for s in states[:count]]

    def get_status(self) -> dict:
        """إحصائيات الحالة الحالية."""
        total = len(self._states)
        alive = sum(1 for s in self._states if s.alive)
        return {
            "total":       total,
            "alive":       alive,
            "dead":        total - alive,
            "last_sync":   self._last_sync,
            "health_pct":  round(alive / total * 100) if total else 0,
        }

    def mark_failed(self, link: str):
        """
        اتصل بهذا لو التطبيق جرب سيرفر وفشل.
        يزيد fail_count مباشرةً بدل ما تنتظر الدورة التالية.
        """
        for s in self._states:
            if s.info.get("link") == link:
                s.fail_count += 1
                if s.fail_count >= FAIL_THRESHOLD:
                    s.alive = False
                    log.warning(f"⚡ Marked dead (app reported): {s.host}")
                break


# ══════════════════════════════════════════════════════════════
#  Singleton helper (اختياري)
# ══════════════════════════════════════════════════════════════
_manager: Optional[ServerHealthManager] = None

def get_manager() -> Optional[ServerHealthManager]:
    return _manager

async def init_manager(
    servers_json_path: str = "servers.json",
    remote_url: str = REMOTE_URL,
) -> ServerHealthManager:
    global _manager
    _manager = ServerHealthManager(servers_json_path, remote_url)
    await _manager.start()
    return _manager

def get_best_server() -> Optional[dict]:
    """اتصل بهذه مباشرةً بعد init_manager()."""
    if _manager:
        return _manager.get_best_server()
    return None


# ══════════════════════════════════════════════════════════════
#  Demo — شغّل مباشرةً لاختبار
# ══════════════════════════════════════════════════════════════
async def _demo():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    print("╔══════════════════════════════════════════╗")
    print("║  Onyx VPN — Health Manager Demo          ║")
    print("╚══════════════════════════════════════════╝\n")

    manager = ServerHealthManager(
        servers_json_path="servers.json",
        remote_url=REMOTE_URL,
    )
    await manager.start()

    # فحص فوري للسيرفرات الأولى 10
    print("\n⚡ فحص فوري للسيرفرات...")
    semaphore = asyncio.Semaphore(10)
    async def _chk(s):
        async with semaphore:
            await s.check()
    await asyncio.gather(*[_chk(s) for s in manager._states[:10]])

    status = manager.get_status()
    print(f"\n📊 الحالة: {status['alive']}/{status['total']} حي ({status['health_pct']}%)")

    best = manager.get_best_server()
    if best:
        print(f"\n🌟 أفضل سيرفر حالياً:")
        print(f"   {best.get('flag','')} {best.get('country','?')} | "
              f"{best.get('protocol','?')} | {best.get('ping','?')}ms | "
              f"{'★ Reality' if best.get('reality') else ''}")

    print("\n🔁 القائمة الكاملة (أحياء فقط):")
    for i, s in enumerate(manager.get_servers(count=5), 1):
        print(f"  {i}. {s.get('flag','')} {s.get('country','?'):<15} | "
              f"{s.get('protocol','?'):<7} | {s.get('ping','?')}ms")

    await manager.stop()


if __name__ == "__main__":
    asyncio.run(_demo())
