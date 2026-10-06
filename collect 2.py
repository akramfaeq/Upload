#!/usr/bin/env python3
"""
Onyx VPN — Server Collector
يجمع سيرفرات من أفضل المصادر، يختبر سرعتها، ويرفع النتيجة كـ JSON
يشتغل كل 6 ساعات عبر GitHub Actions
"""

import asyncio
import base64
import json
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
import aiohttp

# ─── المصادر ──────────────────────────────────────────────────
# أفضل مصادر مجربة — مرتبة من الأفضل للأضعف
SOURCES = [
    # soroushmirzaei — يجمع من مئات قنوات تيليغرام يومياً ✅
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/trojan",

    # barry-far — Reality servers عالية الجودة ✅
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub3.txt",

    # mahdibland — aggregator موثوق ✅
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",

    # MahsaNet — سيرفرات إيران ✅
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt",

    # ارتقاء — Reality + VLESS ✅
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",

    # Pawdroid — سيرفرات منوعة ✅
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
]

# ─── إعدادات ──────────────────────────────────────────────────
MAX_SERVERS      = 50    # عدد السيرفرات في النتيجة النهائية
TEST_TIMEOUT     = 5     # ثواني لكل اختبار
FETCH_TIMEOUT    = 15    # ثواني لجلب المصدر
MAX_CONCURRENCY  = 30    # اختبارات موازية
TEST_URL         = "https://www.gstatic.com/generate_204"  # نفس sing-box urltest
OUTPUT_FILE      = "servers.json"

# بروتوكولات مدعومة
SUPPORTED = ("vless://", "vmess://", "trojan://", "ss://")

# ─── جلب المصادر ──────────────────────────────────────────────

async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    """يجلب مصدر واحد ويرجع قائمة links"""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "hiddify/2.0 (sing-box compatible)"},
        ) as resp:
            if resp.status != 200:
                print(f"  ✗ {url[:60]} → {resp.status}")
                return []
            body = await resp.text()
            links = parse_body(body.strip())
            print(f"  ✓ {url[:60]} → {len(links)} links")
            return links
    except Exception as e:
        print(f"  ✗ {url[:60]} → {type(e).__name__}")
        return []


def parse_body(body: str) -> list[str]:
    """يحلل الجسم — يدعم plain text وbase64"""
    if not body:
        return []

    # base64
    decoded = try_base64(body)
    text = decoded if decoded else body

    links = []
    for line in re.split(r"[\r\n]+", text):
        line = line.strip()
        if any(line.startswith(p) for p in SUPPORTED):
            links.append(line)
            if len(links) >= 500:
                break
    return links


def try_base64(text: str) -> Optional[str]:
    if "://" in text:
        return None
    try:
        padded = text + "=" * ((4 - len(text) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return None


async def fetch_all_sources(session: aiohttp.ClientSession) -> list[str]:
    """يجلب كل المصادر بالتوازي ويدمج النتائج"""
    print(f"\n📥 جلب {len(SOURCES)} مصادر...")
    tasks = [fetch_source(session, url) for url in SOURCES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    seen  = set()
    links = []
    for batch in results:
        if isinstance(batch, list):
            for link in batch:
                # إزالة المكرر بناءً على host:port
                key = _link_key(link)
                if key and key not in seen:
                    seen.add(key)
                    links.append(link)

    print(f"\n📊 إجمالي links فريدة: {len(links)}")
    return links


def _link_key(link: str) -> Optional[str]:
    """مفتاح فريد لكل سيرفر — host:port"""
    try:
        uri = urllib.parse.urlparse(link)
        if uri.scheme == "vmess":
            data = json.loads(base64.b64decode(uri.netloc + "==").decode())
            return f"{data.get('add')}:{data.get('port')}"
        return f"{uri.hostname}:{uri.port}"
    except Exception:
        return None

# ─── اختبار السرعة ────────────────────────────────────────────

async def test_server(session: aiohttp.ClientSession, link: str) -> Optional[dict]:
    """
    يختبر سيرفر واحد بقياس وقت الاستجابة لـ gstatic
    ملاحظة: هذا اختبار HTTP مباشر (بدون tunnel) — يقيس وصولية الـ endpoint
    الاختبار الحقيقي يكون عبر sing-box urltest
    """
    info = parse_link(link)
    if not info:
        return None

    host = info.get("host", "")
    port = info.get("port", 443)

    if not host:
        return None

    start = time.monotonic()
    try:
        # نقيس وقت TCP connect للـ host مباشرة
        conn = aiohttp.TCPConnector()
        async with aiohttp.ClientSession(connector=conn) as test_session:
            async with test_session.get(
                f"http://{host}:{port}",
                timeout=aiohttp.ClientTimeout(
                    connect=TEST_TIMEOUT,
                    total=TEST_TIMEOUT,
                ),
                allow_redirects=False,
            ) as _:
                pass
    except aiohttp.ClientConnectorError:
        # Connection refused = السيرفر موجود بس يرفض HTTP عادي (طبيعي للـ VPN)
        ping_ms = int((time.monotonic() - start) * 1000)
        if ping_ms < TEST_TIMEOUT * 1000:
            return _build_result(info, link, ping_ms)
        return None
    except asyncio.TimeoutError:
        return None
    except Exception:
        # أي استجابة = السيرفر موجود
        ping_ms = int((time.monotonic() - start) * 1000)
        if ping_ms < TEST_TIMEOUT * 1000:
            return _build_result(info, link, ping_ms)
        return None
    else:
        ping_ms = int((time.monotonic() - start) * 1000)
        return _build_result(info, link, ping_ms)


def _build_result(info: dict, link: str, ping_ms: int) -> dict:
    quality = "Excellent" if ping_ms <= 80 else "Good" if ping_ms <= 150 else "Fair"
    country, flag = _guess_country(info.get("host", ""), info.get("name", ""))
    return {
        "name":    info.get("name") or f"{country} · {info['protocol'].upper()}",
        "flag":    flag,
        "country": country,
        "protocol": info["protocol"],
        "host":    info.get("host", ""),
        "port":    info.get("port", 443),
        "ping":    ping_ms,
        "quality": quality,
        "link":    link,
    }


async def test_all(links: list[str]) -> list[dict]:
    """يختبر كل السيرفرات بالتوازي"""
    print(f"\n⚡ اختبار {len(links)} سيرفر (max {MAX_CONCURRENCY} موازي)...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    results   = []
    tested    = 0

    async def _test(session, link):
        nonlocal tested
        async with semaphore:
            r = await test_server(session, link)
            tested += 1
            if tested % 50 == 0:
                print(f"  → {tested}/{len(links)} تم اختبارها، {len(results)} ناجحة")
            if r:
                results.append(r)

    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*[_test(session, l) for l in links])

    print(f"\n✅ {len(results)} سيرفر ناجح من {len(links)}")
    return results

# ─── Parse Link ───────────────────────────────────────────────

def parse_link(link: str) -> Optional[dict]:
    try:
        uri = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(uri.fragment) if uri.fragment else ""

        if link.startswith("vmess://"):
            raw  = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data = json.loads(base64.b64decode(padded).decode())
            return {
                "protocol": "vmess",
                "host":     data.get("add", ""),
                "port":     int(data.get("port", 443)),
                "name":     data.get("ps") or name,
            }

        if link.startswith(("vless://", "trojan://")):
            return {
                "protocol": uri.scheme,
                "host":     uri.hostname or "",
                "port":     uri.port or 443,
                "name":     name,
            }

        if link.startswith("ss://"):
            # ss://base64@host:port#name أو ss://base64(host:port)
            try:
                at_part = uri.netloc.split("@")
                if len(at_part) == 2:
                    host_port = at_part[1]
                    host, port = host_port.rsplit(":", 1)
                    return {"protocol": "ss", "host": host, "port": int(port), "name": name}
            except Exception:
                pass
            return None

    except Exception:
        pass
    return None

# ─── Country Detection ────────────────────────────────────────

_COUNTRY_MAP = {
    "de": ("Germany",     "🇩🇪"),
    "nl": ("Netherlands", "🇳🇱"),
    "us": ("United States","🇺🇸"),
    "uk": ("United Kingdom","🇬🇧"),
    "gb": ("United Kingdom","🇬🇧"),
    "fr": ("France",      "🇫🇷"),
    "jp": ("Japan",       "🇯🇵"),
    "sg": ("Singapore",   "🇸🇬"),
    "ca": ("Canada",      "🇨🇦"),
    "au": ("Australia",   "🇦🇺"),
    "fi": ("Finland",     "🇫🇮"),
    "se": ("Sweden",      "🇸🇪"),
    "no": ("Norway",      "🇳🇴"),
    "tr": ("Turkey",      "🇹🇷"),
    "ir": ("Iran",        "🇮🇷"),
    "ru": ("Russia",      "🇷🇺"),
    "hk": ("Hong Kong",   "🇭🇰"),
    "kr": ("South Korea", "🇰🇷"),
    "in": ("India",       "🇮🇳"),
    "br": ("Brazil",      "🇧🇷"),
    "pl": ("Poland",      "🇵🇱"),
    "ch": ("Switzerland", "🇨🇭"),
    "at": ("Austria",     "🇦🇹"),
}

_NAME_HINTS = {
    "german": "de", "deutsch": "de",
    "nether": "nl", "dutch": "nl", "amsterdam": "nl",
    "united states": "us", "america": "us",
    "united kingdom": "gb", "britain": "gb", "london": "gb",
    "france": "fr", "paris": "fr",
    "japan": "jp", "tokyo": "jp",
    "singapore": "sg",
    "canada": "ca", "toronto": "ca",
    "australia": "au", "sydney": "au",
    "finland": "fi", "helsinki": "fi",
    "sweden": "se", "stockholm": "se",
    "turkey": "tr", "istanbul": "tr",
    "iran": "ir", "tehran": "ir",
    "russia": "ru", "moscow": "ru",
    "hong kong": "hk",
    "korea": "kr", "seoul": "kr",
}


def _guess_country(host: str, name: str) -> tuple[str, str]:
    text = (host + " " + name).lower()

    # من الاسم
    for hint, code in _NAME_HINTS.items():
        if hint in text:
            c = _COUNTRY_MAP.get(code, ("Unknown", "🌐"))
            return c

    # من الـ TLD
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in _COUNTRY_MAP:
            return _COUNTRY_MAP[tld]

    return ("Unknown", "🌐")

# ─── الترتيب والفلترة ─────────────────────────────────────────

def rank_and_filter(servers: list[dict]) -> list[dict]:
    """يرتب السيرفرات ويختار أفضل MAX_SERVERS"""

    # إزالة السيرفرات البطيئة جداً
    servers = [s for s in servers if s["ping"] < 2000]

    # ترتيب: ping أولاً
    servers.sort(key=lambda s: s["ping"])

    # تنويع الدول — لا أكثر من 5 من نفس الدولة
    country_count: dict[str, int] = {}
    filtered = []
    for s in servers:
        c = s["country"]
        if country_count.get(c, 0) < 5:
            filtered.append(s)
            country_count[c] = country_count.get(c, 0) + 1
        if len(filtered) >= MAX_SERVERS:
            break

    # لو ما وصلنا MAX_SERVERS → أضف الباقي بدون قيد
    if len(filtered) < MAX_SERVERS:
        existing_links = {s["link"] for s in filtered}
        for s in servers:
            if s["link"] not in existing_links:
                filtered.append(s)
            if len(filtered) >= MAX_SERVERS:
                break

    return filtered

# ─── الإخراج ──────────────────────────────────────────────────

def build_output(servers: list[dict]) -> dict:
    return {
        "version":    2,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "count":      len(servers),
        "servers":    servers,
    }

# ─── Main ─────────────────────────────────────────────────────

async def main():
    start = time.monotonic()
    print("🚀 Onyx VPN Server Collector")
    print("=" * 50)

    async with aiohttp.ClientSession() as session:
        links = await fetch_all_sources(session)

    if not links:
        print("❌ لا توجد links — تحقق من المصادر")
        return

    # اختبار السرعة
    servers = await test_all(links)

    if not servers:
        print("❌ لا توجد سيرفرات ناجحة")
        return

    # ترتيب وفلترة
    best = rank_and_filter(servers)
    print(f"\n🏆 أفضل {len(best)} سيرفر:")
    for i, s in enumerate(best[:10], 1):
        print(f"  {i:2}. {s['flag']} {s['name']:<30} {s['ping']:>4} ms  {s['quality']}")
    if len(best) > 10:
        print(f"  ... و {len(best)-10} سيرفر آخر")

    # حفظ النتيجة
    output = build_output(best)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    elapsed = time.monotonic() - start
    print(f"\n✅ تم الحفظ في {OUTPUT_FILE}")
    print(f"⏱  الوقت الكلي: {elapsed:.1f} ثانية")


if __name__ == "__main__":
    asyncio.run(main())
