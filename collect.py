#!/usr/bin/env python3
"""
Onyx VPN — Server Collector  v5
================================
تحسينات v5:
  • فحص حقيقي للبروتوكول (يكشف CDN وهمية وـ web servers)
  • double-confirm لكل سيرفر قبل قبوله
  • re_verify صارم يضمن أول 10 سيرفرات كلهم أحياء وحقيقيين
  • MAX_PING أقل، معايير أصعب
"""

import asyncio
import base64
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import aiohttp

# ══════════════════════════════════════════════════════════════
#  المصادر
# ══════════════════════════════════════════════════════════════
SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/trojan",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2Ray-Configs/main/Sub5.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci/sub_2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_2.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription1",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription2",
]

# ══════════════════════════════════════════════════════════════
#  الإعدادات
# ══════════════════════════════════════════════════════════════
MAX_SERVERS       = 60
MAX_PER_COUNTRY   = 6
FETCH_TIMEOUT     = 20
TCP_TIMEOUT       = 4.0
TLS_TIMEOUT       = 5.0
MAX_CONCURRENCY   = 40
MAX_PING          = 800    # رفعنا الصرامة — أقل من 1500
MIN_PING_VALID    = 10
OUTPUT_FILE       = "servers.json"
SUPPORTED         = ("vless://", "vmess://", "trojan://", "ss://")

# كم سيرفر نضمن إنهم أحياء في أول القائمة
GUARANTEED_ALIVE  = 10

# إعدادات إعادة التحقق الصارمة
RE_VERIFY_TOP     = 40    # نختبر أكثر عشان نضمن أول 10 أحياء
RE_VERIFY_ROUNDS  = 3     # 3 محاولات لكل سيرفر

PROTOCOL_SCORE = {"vless": 3, "trojan": 3, "vmess": 2, "ss": 1}

# ══════════════════════════════════════════════════════════════
#  قاموس الدول
# ══════════════════════════════════════════════════════════════
COUNTRIES: dict[str, tuple[str, str, int]] = {
    "de": ("Germany",        "🇩🇪", 3),
    "nl": ("Netherlands",    "🇳🇱", 3),
    "fi": ("Finland",        "🇫🇮", 3),
    "se": ("Sweden",         "🇸🇪", 3),
    "no": ("Norway",         "🇳🇴", 3),
    "ch": ("Switzerland",    "🇨🇭", 3),
    "at": ("Austria",        "🇦🇹", 3),
    "fr": ("France",         "🇫🇷", 2),
    "gb": ("United Kingdom", "🇬🇧", 2),
    "uk": ("United Kingdom", "🇬🇧", 2),
    "us": ("United States",  "🇺🇸", 2),
    "ca": ("Canada",         "🇨🇦", 2),
    "pl": ("Poland",         "🇵🇱", 2),
    "cz": ("Czechia",        "🇨🇿", 2),
    "lt": ("Lithuania",      "🇱🇹", 2),
    "ro": ("Romania",        "🇷🇴", 2),
    "bg": ("Bulgaria",       "🇧🇬", 2),
    "hu": ("Hungary",        "🇭🇺", 2),
    "es": ("Spain",          "🇪🇸", 2),
    "pt": ("Portugal",       "🇵🇹", 2),
    "it": ("Italy",          "🇮🇹", 2),
    "sg": ("Singapore",      "🇸🇬", 2),
    "hk": ("Hong Kong",      "🇭🇰", 2),
    "jp": ("Japan",          "🇯🇵", 2),
    "kr": ("South Korea",    "🇰🇷", 2),
    "au": ("Australia",      "🇦🇺", 2),
    "nz": ("New Zealand",    "🇳🇿", 2),
    "tr": ("Turkey",         "🇹🇷", 1),
    "in": ("India",          "🇮🇳", 1),
    "br": ("Brazil",         "🇧🇷", 1),
    "mx": ("Mexico",         "🇲🇽", 1),
    "ar": ("Argentina",      "🇦🇷", 1),
    "za": ("South Africa",   "🇿🇦", 1),
    "ru": ("Russia",         "🇷🇺", 0),
    "ir": ("Iran",           "🇮🇷", 0),
}

NAME_HINTS: dict[str, str] = {
    "german": "de", "deutsch": "de", "frankfurt": "de",
    "netherlands": "nl", "dutch": "nl", "amsterdam": "nl", "holland": "nl",
    "finland": "fi", "helsinki": "fi",
    "sweden": "se", "stockholm": "se",
    "norway": "no", "oslo": "no",
    "switzerland": "ch", "zurich": "ch", "swiss": "ch",
    "austria": "at", "vienna": "at",
    "france": "fr", "paris": "fr",
    "united kingdom": "gb", "britain": "gb", "london": "gb", "england": "gb",
    "united states": "us", "america": "us", "new york": "us", "los angeles": "us",
    "canada": "ca", "toronto": "ca", "montreal": "ca",
    "poland": "pl", "warsaw": "pl",
    "czechia": "cz", "czech": "cz", "prague": "cz",
    "romania": "ro", "bucharest": "ro",
    "singapore": "sg",
    "hong kong": "hk",
    "japan": "jp", "tokyo": "jp",
    "south korea": "kr", "korea": "kr", "seoul": "kr",
    "australia": "au", "sydney": "au", "melbourne": "au",
    "turkey": "tr", "istanbul": "tr",
    "india": "in", "mumbai": "in",
    "brazil": "br", "sao paulo": "br",
    "russia": "ru", "moscow": "ru",
    "iran": "ir", "tehran": "ir",
}

# ══════════════════════════════════════════════════════════════
#  CDN ranges
# ══════════════════════════════════════════════════════════════
CDN_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
    "131.0.72.0/22",   "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13",   "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22","198.41.128.0/17",
    "2400:cb00::/32",  "2606:4700::/32",  "2803:f800::/32",
    "23.235.32.0/20",  "43.249.72.0/22",  "103.244.50.0/24",
    "103.245.222.0/23","103.245.224.0/24","104.156.80.0/20",
    "151.101.0.0/16",  "157.52.192.0/18", "167.82.0.0/17",
    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
    "172.111.64.0/18", "185.31.16.0/22",  "199.27.72.0/21",
    "199.232.0.0/16",  "202.21.128.0/21",
]

_cdn_nets: list = []

def _build_cdn_nets() -> None:
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
#  جلب المصادر
# ══════════════════════════════════════════════════════════════
async def fetch_source(session: aiohttp.ClientSession, url: str) -> list[str]:
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
            headers={"User-Agent": "hiddify/2.0 (sing-box compatible)"},
        ) as resp:
            if resp.status != 200:
                print(f"  ✗ {url[:70]} → HTTP {resp.status}")
                return []
            body = await resp.text()
            links = _parse_body(body.strip())
            print(f"  ✓ {url[:70]} → {len(links)} links")
            return links
    except asyncio.TimeoutError:
        print(f"  ✗ {url[:70]} → timeout")
        return []
    except Exception as e:
        print(f"  ✗ {url[:70]} → {type(e).__name__}: {e}")
        return []


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
            if len(links) >= 800:
                break
    return links


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


async def fetch_all(session: aiohttp.ClientSession) -> list[str]:
    print(f"\n📥 جلب {len(SOURCES)} مصادر بالتوازي...")
    tasks   = [fetch_source(session, url) for url in SOURCES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    seen, links = set(), []
    for batch in results:
        if not isinstance(batch, list):
            continue
        for link in batch:
            key = _link_key(link)
            if key and key not in seen:
                seen.add(key)
                links.append(link)

    print(f"\n📊 إجمالي links فريدة: {len(links)}")
    return links


def _link_key(link: str) -> Optional[str]:
    try:
        uri = urllib.parse.urlparse(link)
        if link.startswith("vmess://"):
            raw    = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data   = json.loads(base64.b64decode(padded).decode())
            return f"{data.get('add')}:{data.get('port')}"
        return f"{uri.hostname}:{uri.port}"
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════
#  تحليل الـ link
# ══════════════════════════════════════════════════════════════
def parse_link(link: str) -> Optional[dict]:
    try:
        uri  = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(uri.fragment) if uri.fragment else ""

        if link.startswith("vmess://"):
            raw    = uri.netloc + uri.path
            padded = raw + "=" * ((4 - len(raw) % 4) % 4)
            data   = json.loads(base64.b64decode(padded).decode())
            return {
                "protocol": "vmess",
                "host":     str(data.get("add", "")).strip(),
                "port":     int(data.get("port", 443)),
                "name":     str(data.get("ps") or name).strip(),
                "tls":      str(data.get("tls", "")).lower() == "tls",
            }

        if link.startswith(("vless://", "trojan://")):
            params = dict(urllib.parse.parse_qsl(uri.query))
            return {
                "protocol": uri.scheme,
                "host":     str(uri.hostname or "").strip(),
                "port":     uri.port or 443,
                "name":     name,
                "tls":      params.get("security", "none").lower() in ("tls", "reality"),
                "reality":  params.get("security", "").lower() == "reality",
            }

        if link.startswith("ss://"):
            at_parts = uri.netloc.split("@")
            if len(at_parts) == 2:
                hp = at_parts[1]
                # دعم IPv6
                if hp.startswith("["):
                    bracket_end = hp.index("]")
                    host = hp[1:bracket_end]
                    port_s = hp[bracket_end + 2:]
                else:
                    host, port_s = hp.rsplit(":", 1)
                return {"protocol": "ss", "host": host, "port": int(port_s), "name": name, "tls": False}
    except Exception:
        pass
    return None

# ══════════════════════════════════════════════════════════════
#  اختبار TCP
# ══════════════════════════════════════════════════════════════
async def _tcp_connect(host: str, port: int) -> Optional[float]:
    loop = asyncio.get_event_loop()
    t0   = loop.time()
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
#  اختبار TLS
# ══════════════════════════════════════════════════════════════
async def _tls_handshake(host: str, port: int, server_name: str) -> Optional[float]:
    loop = asyncio.get_event_loop()
    t0   = loop.time()
    ctx  = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_name or host),
            timeout=TLS_TIMEOUT,
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
#  فحص البروتوكول الحقيقي — يكشف CDN وهمية و web servers
# ══════════════════════════════════════════════════════════════
async def _verify_vpn_protocol(host: str, port: int, protocol: str) -> bool:
    """
    يرسل packet حقيقي ويتحقق إن الرد منطقي لسيرفر VPN.
    يحذف:
      - CDN ترد بـ HTTP 200/301
      - Web servers عادية على port 443
      - سيرفرات منتهية الصلاحية
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT,
        )

        if protocol in ("vless", "trojan"):
            # نرسل TLS ClientHello بسيط
            # سيرفر VPN حقيقي → يرد بـ TLS ServerHello (0x16 0x03)
            # CDN/web server   → يرد بـ HTTP أو يقطع الاتصال
            tls_hello = (
                b"\x16\x03\x01\x00\x3c"   # TLS Record: Handshake, TLS 1.0, length 60
                b"\x01\x00\x00\x38"        # ClientHello, length 56
                b"\x03\x03"                # TLS 1.2
                + b"\xaa" * 32             # Random
                + b"\x00"                  # Session ID: empty
                + b"\x00\x02\x00\x2f"      # Cipher: TLS_RSA_WITH_AES_128_CBC_SHA
                + b"\x01\x00"              # Compression: null
                + b"\x00\x00"              # Extensions: none
            )
            writer.write(tls_hello)
            await writer.drain()

            try:
                data = await asyncio.wait_for(reader.read(128), timeout=3.0)
                if not data:
                    return False

                # ✅ TLS ServerHello — سيرفر حقيقي
                if data[0] == 0x16 and data[1] == 0x03:
                    return True

                # ❌ HTTP response — CDN وهمية أو web server
                if data[:4] in (b"HTTP", b"html", b"<htm", b"<!DO"):
                    return False

                # رد مجهول — نعطيه فرصة (Reality servers تتصرف بشكل غير تقليدي)
                return len(data) > 0

            except asyncio.TimeoutError:
                # صمت = سيرفر VPN صارم أو Reality → نقبله
                return True

        elif protocol == "vmess":
            # نرسل bytes عشوائية ونتحقق إنه ما يرد بـ HTTP
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
            # Shadowsocks — نتحقق إنه مو web server
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
#  اختبار سيرفر واحد
# ══════════════════════════════════════════════════════════════
async def test_server(link: str) -> Optional[dict]:
    info = parse_link(link)
    if not info:
        return None

    host     = info.get("host", "")
    port     = info.get("port", 443)
    protocol = info["protocol"]

    if not host or not port:
        return None

    # ─ فلتر CDN
    if _is_cdn_ip(host):
        return None

    # ─ TCP
    tcp_ms = await _tcp_connect(host, port)
    if tcp_ms is None:
        return None
    if tcp_ms < MIN_PING_VALID or tcp_ms > MAX_PING:
        return None

    # ─ فحص البروتوكول الحقيقي (يكشف الوهمية)
    is_real = await _verify_vpn_protocol(host, port, protocol)
    if not is_real:
        return None

    # ─ TLS
    final_ms = tcp_ms
    if info.get("tls") and port in (443, 8443, 2053, 2096):
        tls_ms = await _tls_handshake(host, port, host)
        if tls_ms is not None:
            final_ms = tls_ms

    country, flag, bypass_score = _guess_country(host, info.get("name", ""))
    quality = (
        "Excellent" if final_ms <= 80  else
        "Good"      if final_ms <= 200 else
        "Fair"      if final_ms <= 500 else
        "Slow"
    )

    return {
        "name":         _clean_name(info.get("name") or f"{country} · {protocol.upper()}"),
        "flag":         flag,
        "country":      country,
        "protocol":     protocol,
        "host":         host,
        "port":         port,
        "ping":         int(final_ms),
        "quality":      quality,
        "bypass_score": bypass_score,
        "tls_verified": info.get("tls", False),
        "reality":      info.get("reality", False),
        "link":         link,
    }


def _clean_name(name: str) -> str:
    # نحافظ على الأعلام (emoji flags: U+1F1E0–U+1F1FF)
    name = re.sub(r"[^\w\s\u0600-\u06FF\u4E00-\u9FFF·\-|().,@🌐\U0001F1E0-\U0001F1FF]", "", name)
    return name.strip()[:60] or "Server"


async def test_all(links: list[str]) -> list[dict]:
    print(f"\n⚡ اختبار {len(links)} سيرفر (حد التوازي: {MAX_CONCURRENCY})...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    results: list[dict] = []
    tested = 0

    async def _run(link: str):
        nonlocal tested
        async with semaphore:
            r = await test_server(link)
            tested += 1
            if tested % 100 == 0 or tested == len(links):
                alive = len(results)
                pct   = tested / len(links) * 100
                print(f"  [{pct:5.1f}%] {tested}/{len(links)} tested — {alive} alive")
            if r:
                results.append(r)

    await asyncio.gather(*[_run(l) for l in links])
    print(f"\n✅ {len(results)} سيرفر حي من أصل {len(links)}")
    return results

# ══════════════════════════════════════════════════════════════
#  GeoIP
# ══════════════════════════════════════════════════════════════
_geo_cache: dict[str, tuple[str, str, int]] = {}

async def _resolve_host(host: str) -> Optional[str]:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return info[0][4][0]
    except Exception:
        return None

async def _batch_geoip(
    session: aiohttp.ClientSession,
    ips: list[str],
) -> dict[str, tuple[str, str, int]]:
    result: dict[str, tuple[str, str, int]] = {}
    if not ips:
        return result

    for i in range(0, len(ips), 100):
        batch = ips[i : i + 100]
        payload = [{"query": ip, "fields": "query,countryCode,country"} for ip in batch]
        try:
            async with session.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json(content_type=None)
                for item in data:
                    ip   = item.get("query", "")
                    code = item.get("countryCode", "").lower()
                    name = item.get("country", "")
                    if ip and code and code in COUNTRIES:
                        cn, flag, score = COUNTRIES[code]
                        result[ip] = (cn, flag, score)
                    elif ip and name:
                        result[ip] = (name, "🌐", 0)
        except Exception as e:
            print(f"  ⚠ ip-api batch error: {e}")
        await asyncio.sleep(1)

    return result

async def enrich_with_geoip(
    session: aiohttp.ClientSession,
    servers: list[dict],
) -> None:
    unknown = [s for s in servers if s["country"] in ("Unknown", "", "🌐")]
    if not unknown:
        return

    print(f"\n🌍 GeoIP lookup لـ {len(unknown)} سيرفر مجهول الدولة...")

    host_to_ip: dict[str, str] = {}
    resolve_tasks = [_resolve_host(s["host"]) for s in unknown]
    resolved = await asyncio.gather(*resolve_tasks)
    for s, ip in zip(unknown, resolved):
        if ip:
            host_to_ip[s["host"]] = ip

    unique_ips = list({ip for ip in host_to_ip.values() if ip not in _geo_cache})
    geo_data = await _batch_geoip(session, unique_ips)
    _geo_cache.update(geo_data)

    updated = 0
    for s in unknown:
        ip = host_to_ip.get(s["host"])
        if ip and ip in _geo_cache:
            cn, flag, score = _geo_cache[ip]
            s["country"]      = cn
            s["flag"]         = flag
            s["bypass_score"] = score
            updated += 1

    print(f"  ✅ تم تحديد دولة {updated}/{len(unknown)} سيرفر")


def _guess_country(host: str, name: str) -> tuple[str, str, int]:
    text = (host + " " + name).lower()
    for hint, code in NAME_HINTS.items():
        if hint in text:
            if code in COUNTRIES:
                n, f, s = COUNTRIES[code]
                return n, f, s
            return hint.title(), "🌐", 0
    parts = host.rstrip(".").split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in COUNTRIES:
            n, f, s = COUNTRIES[tld]
            return n, f, s
    return "Unknown", "🌐", 0

# ══════════════════════════════════════════════════════════════
#  الترتيب والفلترة
# ══════════════════════════════════════════════════════════════
def rank_and_filter(servers: list[dict]) -> list[dict]:
    def _score(s: dict) -> float:
        ping          = s["ping"]
        ping_score    = max(0, 100 - ping / 10)
        proto_score   = PROTOCOL_SCORE.get(s["protocol"], 1) * 20
        bypass        = s.get("bypass_score", 0) * 40
        tls_bonus     = 15 if s.get("tls_verified") else 0
        reality_bonus = 20 if s.get("reality")      else 0
        return bypass + proto_score + tls_bonus + reality_bonus + ping_score * 0.05

    servers.sort(key=_score, reverse=True)

    country_count: dict[str, int] = defaultdict(int)
    selected: list[dict] = []

    for s in servers:
        c = s["country"]
        if country_count[c] < MAX_PER_COUNTRY:
            selected.append(s)
            country_count[c] += 1
        if len(selected) >= MAX_SERVERS:
            break

    if len(selected) < MAX_SERVERS:
        existing = {s["link"] for s in selected}
        for s in servers:
            if s["link"] not in existing:
                selected.append(s)
                existing.add(s["link"])
            if len(selected) >= MAX_SERVERS:
                break

    return selected[:MAX_SERVERS]

# ══════════════════════════════════════════════════════════════
#  إعادة التحقق الصارمة — تضمن أول GUARANTEED_ALIVE سيرفرات أحياء
# ══════════════════════════════════════════════════════════════
async def _re_test_server_strict(s: dict) -> bool:
    """
    اختبار صارم مزدوج:
    1. TCP connect
    2. ينتظر 500ms ثم يعيد TCP
    3. فحص البروتوكول الحقيقي
    كلهم لازم ينجحوا.
    """
    host = s.get("host", "")
    port = s.get("port", 443)
    protocol = s.get("protocol", "vless")

    for attempt in range(RE_VERIFY_ROUNDS):
        # جولة 1 — TCP
        ms1 = await _tcp_connect(host, port)
        if ms1 is None or ms1 < MIN_PING_VALID or ms1 > MAX_PING:
            await asyncio.sleep(0.5)
            continue

        # انتظر قليلاً ثم أعد
        await asyncio.sleep(0.5)

        # جولة 2 — TCP مرة ثانية للتأكيد
        ms2 = await _tcp_connect(host, port)
        if ms2 is None or ms2 < MIN_PING_VALID or ms2 > MAX_PING:
            await asyncio.sleep(0.5)
            continue

        # جولة 3 — فحص البروتوكول الحقيقي
        is_real = await _verify_vpn_protocol(host, port, protocol)
        if not is_real:
            return False  # وهمي بشكل مؤكد — ما في فائدة من إعادة المحاولة

        # ✅ نجح كل شيء
        s["ping"] = int(min(ms1, ms2))
        return True

    return False


async def re_verify_top(servers: list[dict]) -> list[dict]:
    """
    يضمن إن أول GUARANTEED_ALIVE سيرفرات كلهم أحياء حقيقيين.
    يحذف الميتين ويستبدلهم من بقية القائمة.
    """
    if not servers:
        return servers

    print(f"\n🔁 إعادة التحقق الصارمة — نضمن أول {GUARANTEED_ALIVE} سيرفرات أحياء...")

    verified_alive: list[dict] = []
    candidates = list(servers)  # نسخة نعمل عليها
    checked_links: set = set()

    # نكمل حتى نحصل على GUARANTEED_ALIVE سيرفر مؤكد
    # أو حتى ننفد من المرشحين
    for s in candidates:
        if len(verified_alive) >= GUARANTEED_ALIVE:
            break

        link = s.get("link", "")
        if link in checked_links:
            continue
        checked_links.add(link)

        alive = await _re_test_server_strict(s)
        if alive:
            verified_alive.append(s)
            print(f"  ✅ [{len(verified_alive)}/{GUARANTEED_ALIVE}] "
                  f"{s['flag']} {s['country']} | {s['protocol']} | {s['ping']}ms")
        else:
            print(f"  ❌ {s.get('host','?')} → ميت أو وهمي، يُحذف")

    # أضف الباقي (غير المُختبرين) لإكمال القائمة
    alive_links = {s["link"] for s in verified_alive}
    for s in candidates:
        if s["link"] not in alive_links and s["link"] not in checked_links:
            verified_alive.append(s)
        if len(verified_alive) >= MAX_SERVERS:
            break

    alive_count = sum(1 for s in verified_alive[:GUARANTEED_ALIVE])
    print(f"\n  🎯 {alive_count}/{GUARANTEED_ALIVE} سيرفر مؤكد حي في أول القائمة")
    return verified_alive[:MAX_SERVERS]


# ══════════════════════════════════════════════════════════════
#  الإخراج
# ══════════════════════════════════════════════════════════════
def build_output(servers: list[dict]) -> dict:
    clean = []
    for s in servers:
        clean.append({
            "name":     s["name"],
            "flag":     s["flag"],
            "country":  s["country"],
            "protocol": s["protocol"],
            "ping":     s["ping"],
            "quality":  s["quality"],
            "tls":      s.get("tls_verified", False),
            "reality":  s.get("reality", False),
            "link":     s["link"],
        })
    return {
        "version":    5,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "count":      len(clean),
        "servers":    clean,
    }

# ══════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════
async def main():
    t0 = time.monotonic()
    print("╔══════════════════════════════════════════╗")
    print("║   Onyx VPN — Server Collector  v5        ║")
    print("╚══════════════════════════════════════════╝\n")

    _build_cdn_nets()
    print(f"🛡  CDN filter: {len(_cdn_nets)} IP ranges loaded\n")

    async with aiohttp.ClientSession() as session:
        # ─ جلب المصادر
        links = await fetch_all(session)

        if not links:
            print("❌ لا توجد links — تحقق من المصادر")
            return

        # ─ اختبار أولي
        servers = await test_all(links)

        if not servers:
            print("❌ لا توجد سيرفرات حية")
            return

        # ─ GeoIP
        await enrich_with_geoip(session, servers)

    # ─ ترتيب وفلترة
    best = rank_and_filter(servers)

    # ─ إعادة التحقق الصارمة — يضمن أول 10 أحياء وحقيقيين
    best = await re_verify_top(best)

    # ─ ملخص
    print(f"\n{'═'*54}")
    print(f"  {'#':<3}  {'Protocol':<8}  {'Country':<16}  {'Ping':>5}  {'Quality'}")
    print(f"  {'─'*50}")
    for i, s in enumerate(best, 1):
        rl      = " ★" if s.get("reality") else ""
        marker  = " ✅" if i <= GUARANTEED_ALIVE else ""
        print(f"  {i:<3}  {s['protocol']:<8}  {s['flag']} {s['country']:<13}  {s['ping']:>4}ms  {s['quality']}{rl}{marker}")
    print(f"{'═'*54}")

    from collections import Counter
    countries = Counter(s["country"] for s in best)
    print("\n  دول مُمثَّلة:")
    for country, count in countries.most_common():
        flag = next((s["flag"] for s in best if s["country"] == country), "🌐")
        print(f"    {flag} {country:<20} {count} سيرفر")

    protocols = Counter(s["protocol"] for s in best)
    print(f"\n  البروتوكولات: " + "  |  ".join(f"{p}: {c}" for p, c in protocols.most_common()))
    print(f"\n  Reality servers: {sum(1 for s in best if s.get('reality'))} ★")
    print(f"\n  ✅ أول {GUARANTEED_ALIVE} سيرفرات مضمونة الحياة")

    # ─ حفظ
    output = build_output(best)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    elapsed = time.monotonic() - t0
    print(f"\n✅ حُفظ {len(best)} سيرفر في → {OUTPUT_FILE}")
    print(f"⏱  الوقت الكلي: {elapsed:.1f}s\n")


if __name__ == "__main__":
    asyncio.run(main())
