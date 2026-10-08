#!/usr/bin/env python3
"""
Onyx VPN — Server Monitor  v1
==============================
يفحص أول GUARANTEED_ALIVE سيرفرات في servers.json
لو واحد ميت → يسحب بديل حي من المصادر ويحل محله فوراً
يشتغل كل 5 دقائق عبر GitHub Actions
"""

import asyncio
import base64
import ipaddress
import json
import re
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import aiohttp

# ══════════════════════════════════════════════════════════════
#  الإعدادات
# ══════════════════════════════════════════════════════════════
SERVERS_FILE      = "servers.json"
GUARANTEED_ALIVE  = 10        # عدد السيرفرات الأولى اللي نضمن حياتها
TCP_TIMEOUT       = 4.0
TLS_TIMEOUT       = 5.0
FETCH_TIMEOUT     = 15
MAX_PING          = 800
MIN_PING_VALID    = 10
MAX_CONCURRENCY   = 30

SUPPORTED = ("vless://", "vmess://", "trojan://", "ss://")

# مصادر البدائل — نفس مصادر Hiddify
BACKUP_SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/trojan",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub3.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
]

# ══════════════════════════════════════════════════════════════
#  CDN ranges
# ══════════════════════════════════════════════════════════════
CDN_RANGES = [
    "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "104.16.0.0/13",  "104.24.0.0/14",  "108.162.192.0/18",
    "131.0.72.0/22",  "141.101.64.0/18","162.158.0.0/15",
    "172.64.0.0/13",  "173.245.48.0/20","188.114.96.0/20",
    "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
    "151.101.0.0/16", "199.232.0.0/16",
]
_cdn_nets: list = []

def _build_cdn_nets():
    for cidr in CDN_RANGES:
        try:
            _cdn_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

def _is_cdn_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _cdn_nets)
    except ValueError:
        return False

# ══════════════════════════════════════════════════════════════
#  اختبار TCP
# ══════════════════════════════════════════════════════════════
async def _tcp_connect(host: str, port: int) -> Optional[float]:
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT,
        )
        ms = (loop.time() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ms
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════
#  فحص البروتوكول الحقيقي
# ══════════════════════════════════════════════════════════════
async def _verify_vpn_protocol(host: str, port: int, protocol: str) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT,
        )
        if protocol in ("vless", "trojan"):
            tls_hello = (
                b"\x16\x03\x01\x00\x3c"
                b"\x01\x00\x00\x38"
                b"\x03\x03"
                + b"\xaa" * 32
                + b"\x00"
                + b"\x00\x02\x00\x2f"
                + b"\x01\x00"
                + b"\x00\x00"
            )
            writer.write(tls_hello)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=3.0)
                if not data:
                    return False
                if data[0] == 0x16 and data[1] == 0x03:
                    return True
                if data[:4] in (b"HTTP", b"html", b"<htm", b"<!DO"):
                    return False
                return len(data) > 0
            except asyncio.TimeoutError:
                return True
        elif protocol == "vmess":
            writer.write(b"\x00" * 16)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(64), timeout=2.0)
                if data and data[:4] in (b"HTTP", b"html", b"<htm"):
                    return False
                return True
            except asyncio.TimeoutError:
                return True
        elif protocol == "ss":
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(32), timeout=2.0)
                if data and data[:4] in (b"HTTP", b"html", b"<htm"):
                    return False
                return True
            except asyncio.TimeoutError:
                return True
        return True
    except Exception:
        return False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════
#  فحص سيرفر واحد (مزدوج)
# ══════════════════════════════════════════════════════════════
async def check_server(s: dict) -> tuple[bool, int]:
    """
    يفحص السيرفر بـ 3 خطوات:
    TCP → انتظار → TCP مرة ثانية → فحص البروتوكول
    يرجع (حي/ميت, ping)
    """
    host     = s.get("host") or _extract_host(s.get("link", ""))
    port     = s.get("port") or _extract_port(s.get("link", ""))
    protocol = s.get("protocol", "vless")

    if not host or not port:
        return False, 0

    if _is_cdn_ip(host):
        return False, 0

    # TCP جولة 1
    ms1 = await _tcp_connect(host, port)
    if ms1 is None or ms1 < MIN_PING_VALID or ms1 > MAX_PING:
        return False, 0

    # انتظر ثم أعد
    await asyncio.sleep(0.4)

    # TCP جولة 2
    ms2 = await _tcp_connect(host, port)
    if ms2 is None or ms2 < MIN_PING_VALID or ms2 > MAX_PING:
        return False, 0

    # فحص البروتوكول
    real = await _verify_vpn_protocol(host, port, protocol)
    if not real:
        return False, 0

    return True, int(min(ms1, ms2))


def _extract_host(link: str) -> str:
    try:
        uri = urllib.parse.urlparse(link)
        if link.startswith("vmess://"):
            raw    = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data   = json.loads(base64.b64decode(padded).decode())
            return str(data.get("add", ""))
        if link.startswith("ss://"):
            netloc = uri.netloc
            at = netloc.split("@")
            if len(at) == 2:
                hp = at[1]
                if hp.startswith("["):
                    return hp[1:hp.index("]")]
                return hp.rsplit(":", 1)[0]
        return str(uri.hostname or "")
    except Exception:
        return ""

def _extract_port(link: str) -> int:
    try:
        uri = urllib.parse.urlparse(link)
        if link.startswith("vmess://"):
            raw    = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data   = json.loads(base64.b64decode(padded).decode())
            return int(data.get("port", 443))
        if link.startswith("ss://"):
            netloc = uri.netloc
            at = netloc.split("@")
            if len(at) == 2:
                hp = at[1]
                if hp.startswith("["):
                    return int(hp[hp.index("]")+2:])
                return int(hp.rsplit(":", 1)[1])
        return uri.port or 443
    except Exception:
        return 443

# ══════════════════════════════════════════════════════════════
#  سحب بدائل من المصادر
# ══════════════════════════════════════════════════════════════
def _try_base64(text: str) -> Optional[str]:
    if "://" in text:
        return None
    try:
        padded  = text + "=" * ((4 - len(text) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return None

def _parse_body(body: str) -> list[str]:
    if not body:
        return []
    decoded = _try_base64(body)
    text = decoded if decoded else body
    links = []
    for line in re.split(r"[\r\n]+", text):
        line = line.strip()
        if any(line.startswith(p) for p in SUPPORTED):
            links.append(line)
            if len(links) >= 500:
                break
    return links

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "hiddify/2.0 (sing-box compatible)"},
        ) as resp:
            if resp.status != 200:
                return []
            body = await resp.text()
            return _parse_body(body.strip())
    except Exception:
        return []

async def fetch_candidates(
    session: aiohttp.ClientSession,
    existing_links: set[str],
    need: int,
) -> list[str]:
    """يجلب links جديدة من المصادر ويستبعد الموجودة مسبقاً"""
    print(f"  📥 جلب بدائل من {len(BACKUP_SOURCES)} مصدر...")
    tasks   = [fetch_source(session, url) for url in BACKUP_SOURCES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    seen   = set(existing_links)
    links  = []
    for batch in results:
        if not isinstance(batch, list):
            continue
        for link in batch:
            if link not in seen:
                seen.add(link)
                links.append(link)

    print(f"  📊 {len(links)} link جديد متاح للاختيار")
    return links

# ══════════════════════════════════════════════════════════════
#  إيجاد بديل حي
# ══════════════════════════════════════════════════════════════
def _parse_link_info(link: str) -> Optional[dict]:
    """يستخرج host/port/protocol من الـ link"""
    try:
        uri = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(uri.fragment) if uri.fragment else ""

        if link.startswith("vmess://"):
            raw    = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data   = json.loads(base64.b64decode(padded).decode())
            return {
                "protocol": "vmess",
                "host": str(data.get("add", "")).strip(),
                "port": int(data.get("port", 443)),
                "name": str(data.get("ps") or name).strip(),
                "tls":  str(data.get("tls", "")).lower() == "tls",
                "reality": False,
            }
        if link.startswith(("vless://", "trojan://")):
            params = dict(urllib.parse.parse_qsl(uri.query))
            sec    = params.get("security", "none").lower()
            return {
                "protocol": uri.scheme,
                "host": str(uri.hostname or "").strip(),
                "port": uri.port or 443,
                "name": name,
                "tls":  sec in ("tls", "reality"),
                "reality": sec == "reality",
            }
        if link.startswith("ss://"):
            at_parts = uri.netloc.split("@")
            if len(at_parts) == 2:
                hp = at_parts[1]
                if hp.startswith("["):
                    bi = hp.index("]")
                    host = hp[1:bi]
                    port_s = hp[bi+2:]
                else:
                    host, port_s = hp.rsplit(":", 1)
                return {"protocol": "ss", "host": host, "port": int(port_s), "name": name, "tls": False, "reality": False}
    except Exception:
        pass
    return None

QUALITY_MAP = {
    "Excellent": lambda p: p <= 80,
    "Good":      lambda p: p <= 200,
    "Fair":      lambda p: p <= 500,
    "Slow":      lambda p: True,
}

def _ping_to_quality(ping: int) -> str:
    if ping <= 80:  return "Excellent"
    if ping <= 200: return "Good"
    if ping <= 500: return "Fair"
    return "Slow"

async def find_replacement(
    session: aiohttp.ClientSession,
    existing_links: set[str],
    needed: int,
) -> list[dict]:
    """
    يبحث عن `needed` سيرفرات بديلة حية وحقيقية.
    يختبرها بالتوازي ويتوقف بمجرد ما يجمع العدد المطلوب.
    """
    candidates = await fetch_candidates(session, existing_links, needed)
    if not candidates:
        print("  ⚠ لا يوجد candidates جديدة")
        return []

    print(f"  ⚡ اختبار البدائل (نحتاج {needed} حي)...")

    semaphore  = asyncio.Semaphore(MAX_CONCURRENCY)
    found:   list[dict] = []
    tested   = 0
    stop_evt = asyncio.Event()

    async def _test_one(link: str):
        nonlocal tested
        if stop_evt.is_set():
            return
        async with semaphore:
            if stop_evt.is_set():
                return
            info = _parse_link_info(link)
            if not info or not info.get("host") or _is_cdn_ip(info.get("host","")):
                tested += 1
                return

            host     = info["host"]
            port     = info["port"]
            protocol = info["protocol"]

            ms1 = await _tcp_connect(host, port)
            if ms1 is None or ms1 < MIN_PING_VALID or ms1 > MAX_PING:
                tested += 1
                return

            await asyncio.sleep(0.3)
            ms2 = await _tcp_connect(host, port)
            if ms2 is None or ms2 < MIN_PING_VALID or ms2 > MAX_PING:
                tested += 1
                return

            real = await _verify_vpn_protocol(host, port, protocol)
            tested += 1
            if not real:
                return

            ping = int(min(ms1, ms2))
            found.append({
                "name":     _clean_name(info.get("name") or f"{protocol.upper()} Server"),
                "flag":     "🌐",
                "country":  "Unknown",
                "protocol": protocol,
                "host":     host,
                "port":     port,
                "ping":     ping,
                "quality":  _ping_to_quality(ping),
                "tls":      info.get("tls", False),
                "reality":  info.get("reality", False),
                "link":     link,
            })
            print(f"    ✅ بديل #{len(found)}: {host} | {protocol} | {ping}ms")

            if len(found) >= needed:
                stop_evt.set()

    tasks = [_test_one(link) for link in candidates]
    await asyncio.gather(*tasks)

    print(f"  🔍 فحص {tested} سيرفر → وجدنا {len(found)} بديل")
    return found[:needed]


def _clean_name(name: str) -> str:
    name = re.sub(r"[^\w\s\u0600-\u06FF\u4E00-\u9FFF·\-|().,@🌐\U0001F1E0-\U0001F1FF]", "", name)
    return name.strip()[:60] or "Server"

# ══════════════════════════════════════════════════════════════
#  القلب — الفحص والاستبدال
# ══════════════════════════════════════════════════════════════
async def monitor():
    t0 = time.monotonic()
    print("╔══════════════════════════════════════════╗")
    print("║   Onyx VPN — Server Monitor  v1          ║")
    print("╚══════════════════════════════════════════╝\n")

    _build_cdn_nets()

    # ─ قراءة servers.json
    try:
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ {SERVERS_FILE} غير موجود — شغّل collect.py أولاً")
        return
    except json.JSONDecodeError as e:
        print(f"❌ خطأ في قراءة {SERVERS_FILE}: {e}")
        return

    servers = data.get("servers", [])
    if not servers:
        print("❌ القائمة فارغة")
        return

    print(f"📋 القائمة: {len(servers)} سيرفر")
    print(f"🎯 نفحص أول {GUARANTEED_ALIVE} ونضمن حياتهم\n")

    # ─ فحص أول GUARANTEED_ALIVE سيرفر بالتوازي
    top     = servers[:GUARANTEED_ALIVE]
    rest    = servers[GUARANTEED_ALIVE:]

    print(f"🔍 فحص أول {len(top)} سيرفرات...")
    check_tasks = [check_server(s) for s in top]
    check_results = await asyncio.gather(*check_tasks)

    alive_servers: list[dict] = []
    dead_servers:  list[dict] = []

    for s, (is_alive, ping) in zip(top, check_results):
        if is_alive:
            s["ping"] = ping  # تحديث الـ ping
            alive_servers.append(s)
            print(f"  ✅ {s.get('flag','🌐')} {s.get('country','?'):<15} | "
                  f"{s.get('protocol','?'):<7} | {ping}ms")
        else:
            dead_servers.append(s)
            print(f"  ❌ {s.get('flag','🌐')} {s.get('country','?'):<15} | "
                  f"{s.get('protocol','?'):<7} | ميت")

    print(f"\n📊 النتيجة: {len(alive_servers)} حي، {len(dead_servers)} ميت")

    changed = False

    if not dead_servers:
        print("\n✅ كل السيرفرات الأولى أحياء — لا حاجة لتغيير")
    else:
        print(f"\n🔄 نبحث عن {len(dead_servers)} بديل...")

        existing_links = {s.get("link","") for s in servers}

        async with aiohttp.ClientSession() as session:
            replacements = await find_replacement(
                session,
                existing_links,
                needed=len(dead_servers),
            )

        if replacements:
            print(f"\n  ✅ وجدنا {len(replacements)} بديل من {len(dead_servers)} مطلوب")
        else:
            print("\n  ⚠ ما وجدنا بدائل كافية — نبقي الميتين في النهاية")

        # ─ بناء القائمة الجديدة:
        # الأحياء أولاً + البدائل + الميتون في النهاية + الباقي
        new_servers = alive_servers + replacements

        # لو ما اكتملنا 10 → نحاول من rest
        if len(new_servers) < GUARANTEED_ALIVE:
            shortage = GUARANTEED_ALIVE - len(new_servers)
            new_servers += rest[:shortage]
            rest = rest[shortage:]

        # أضف بقية الـ rest
        existing_in_new = {s.get("link","") for s in new_servers}
        for s in rest:
            if s.get("link","") not in existing_in_new:
                new_servers.append(s)

        # الميتون في النهاية (مو في الأولى)
        dead_links = {s.get("link","") for s in dead_servers}
        final_servers = [s for s in new_servers if s.get("link","") not in dead_links]
        for s in dead_servers:
            final_servers.append(s)

        # trim
        final_servers = final_servers[:len(servers)]

        data["servers"]    = final_servers
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        data["monitor_last_run"] = datetime.now(timezone.utc).isoformat()
        data["monitor_stats"] = {
            "checked":      len(top),
            "alive":        len(alive_servers),
            "dead":         len(dead_servers),
            "replaced":     len(replacements),
        }

        with open(SERVERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        changed = True
        print(f"\n💾 servers.json محدّث")

    # ─ ملخص نهائي
    elapsed = time.monotonic() - t0
    print(f"\n{'═'*50}")
    if changed:
        replaced = len(dead_servers)
        found    = len(replacements) if dead_servers else 0
        print(f"  🔄 استُبدل: {found}/{replaced} سيرفر ميت")
    print(f"  ⏱  الوقت: {elapsed:.1f}s")
    print(f"  🕐  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'═'*50}\n")

    # exit code — لو ما وجدنا بدائل كافية
    if dead_servers and len(replacements if dead_servers else []) < len(dead_servers):
        import sys
        print("⚠ تحذير: بعض الميتين ما استُبدلوا (مصادر شحيحة)")
        # مو failure — نكمل بدون error


if __name__ == "__main__":
    asyncio.run(monitor())
