import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, BackgroundTasks
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("X4G")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="X4G", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "x4g-default-static-secret-2010"),
    # روی Railway از RAILWAY_PUBLIC_DOMAIN، روی Vercel از VERCEL_PROJECT_PRODUCTION_URL / VERCEL_URL استفاده می‌شود
    "host": (
        os.environ.get("RAILWAY_PUBLIC_DOMAIN")
        or os.environ.get("VERCEL_PROJECT_PRODUCTION_URL")
        or os.environ.get("VERCEL_URL")
        or "localhost"
    ),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence (Redis) ─────────────────────────────────────────────────────
# روی Vercel فایل‌سیستم موقتی و ناپایدار است، پس LINKS/SUBS/رمز پنل باید در Redis
# (مثلاً Vercel Marketplace → Redis/Upstash) ذخیره شوند. متغیر REDIS_URL را ست کنید.
#
# نکته‌ی مهم معماری: چون روی Vercel هر درخواست ممکن است به یک instance متفاوت
# برخورد کند، دیگر همه‌چیز را در یک کلید JSON واحد ذخیره نمی‌کنیم (چون اگر یک
# instance با نسخه‌ی قدیمی‌ترِ حافظه‌اش دوباره save کند، رکوردهای تازه‌ی
# instanceهای دیگر پاک می‌شدند). حالا هر لینک/گروه در یک فیلد جدا داخل یک
# Redis Hash ذخیره می‌شود، و قبل از هر خواندن/نوشتن، از Redis تازه‌سازی می‌شود.
REDIS_URL = os.environ.get("REDIS_URL") or os.environ.get("KV_URL")
REDIS_LINKS_KEY = "x4g:links"             # Hash: field=uid    -> json لینک
REDIS_SUBS_KEY = "x4g:subs"               # Hash: field=sub_id -> json گروه
REDIS_PASSWORD_KEY = "x4g:password_hash"  # String
REDIS_STATE_KEY_LEGACY = "x4g:state"      # کلید قدیمی (برای مهاجرت خودکار یک‌باره)
SAVE_LOCK = asyncio.Lock()
redis_client = None  # در startup مقداردهی می‌شود

async def get_redis():
    global redis_client
    if redis_client is None and REDIS_URL and aioredis:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    return redis_client

async def _migrate_legacy_blob_if_needed(r):
    """اگر از نسخه‌ی قبلی، داده‌ها هنوز به‌صورت یک بلوک JSON واحد در Redis مانده
    (کلید قدیمی x4g:state) و ساختار Hash جدید هنوز خالی است، یک‌بار مهاجرت می‌کند."""
    try:
        has_links = await r.exists(REDIS_LINKS_KEY)
        has_subs = await r.exists(REDIS_SUBS_KEY)
        if has_links or has_subs:
            return
        legacy = await r.get(REDIS_STATE_KEY_LEGACY)
        if not legacy:
            return
        data = json.loads(legacy)
        legacy_links = data.get("links") or {}
        legacy_subs = data.get("subs") or {}
        if legacy_links:
            await r.hset(REDIS_LINKS_KEY, mapping={k: json.dumps(v, ensure_ascii=False) for k, v in legacy_links.items()})
        if legacy_subs:
            await r.hset(REDIS_SUBS_KEY, mapping={k: json.dumps(v, ensure_ascii=False) for k, v in legacy_subs.items()})
        if data.get("password_hash"):
            await r.set(REDIS_PASSWORD_KEY, data["password_hash"])
        logger.info(f"Migrated legacy x4g:state blob -> hash structure ({len(legacy_links)} links, {len(legacy_subs)} subs)")
    except Exception as e:
        logger.warning(f"Legacy migration skipped/failed: {e}")

async def load_state():
    """در startup هر instance صدا زده می‌شود: کل LINKS/SUBS/رمز را از Redis می‌خواند."""
    global LINKS, AUTH, SUBS
    r = await get_redis()
    if not r:
        logger.warning("REDIS_URL تنظیم نشده؛ داده‌ها فقط در حافظه‌ی همین نمونه باقی می‌مانند و با ری‌استارت پاک می‌شوند.")
        return
    try:
        await _migrate_legacy_blob_if_needed(r)
        links_raw = await r.hgetall(REDIS_LINKS_KEY)
        subs_raw = await r.hgetall(REDIS_SUBS_KEY)
        LINKS.clear()
        for uid, raw in links_raw.items():
            try:
                LINKS[uid] = json.loads(raw)
            except Exception:
                pass
        SUBS.clear()
        for sid, raw in subs_raw.items():
            try:
                SUBS[sid] = json.loads(raw)
            except Exception:
                pass
        pw_hash = await r.get(REDIS_PASSWORD_KEY)
        if pw_hash:
            AUTH["password_hash"] = pw_hash
        tg_raw = await r.get(REDIS_TG_KEY)
        if tg_raw:
            try:
                TG_CONFIG.update(json.loads(tg_raw))
            except Exception:
                pass
        logger.info(f"State loaded from Redis: {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.warning(f"Could not load state from Redis: {e}")

_LAST_REFRESH_TS = 0.0
_REFRESH_THROTTLE_SECONDS = 1.2  # از خواندن کامل Redis در فاصله‌های خیلی کوتاه (مثلاً کلیک‌های پی‌درپی دکمه‌های تلگرام) جلوگیری می‌کند

async def refresh_links_and_subs(force: bool = False):
    """قبل از هر پاسخ به کاربر (لیست/مصرف لینک) صدا زده می‌شود تا اگر لینکی توسط
    instance دیگری ساخته/حذف/ویرایش شده، همین‌جا هم دیده شود — این دقیقاً همان
    چیزی است که باعث می‌شد کانفیگ‌های تازه‌ساخته «بیایند و بروند».

    برای جلوگیری از خواندن کامل Redis در هر تک تعامل (مخصوصاً کلیک‌های سریع
    دکمه‌های تلگرام که باعث کندی/هنگ محسوس می‌شد)، اگر کمتر از
    _REFRESH_THROTTLE_SECONDS از آخرین رفرش واقعی گذشته باشد، از حافظه‌ی
    فعلی استفاده می‌شود؛ با force=True می‌توان این رفتار را دور زد."""
    global _LAST_REFRESH_TS
    r = await get_redis()
    if not r:
        return
    now = time.monotonic()
    if not force and (now - _LAST_REFRESH_TS) < _REFRESH_THROTTLE_SECONDS:
        return
    try:
        links_raw = await r.hgetall(REDIS_LINKS_KEY)
        subs_raw = await r.hgetall(REDIS_SUBS_KEY)
        async with LINKS_LOCK:
            LINKS.clear()
            for uid, raw in links_raw.items():
                try:
                    LINKS[uid] = json.loads(raw)
                except Exception:
                    pass
        async with SUBS_LOCK:
            SUBS.clear()
            for sid, raw in subs_raw.items():
                try:
                    SUBS[sid] = json.loads(raw)
                except Exception:
                    pass
        _LAST_REFRESH_TS = now
    except Exception as e:
        logger.warning(f"Could not refresh state from Redis: {e}")

async def save_state():
    """کل LINKS/SUBS فعلی حافظه را در Redis می‌نویسد. چون HSET است (نه SET یک
    بلوک واحد)، فیلدهایی که در Redis هستند ولی در حافظه‌ی این instance نیستند
    (مثلاً لینکی که یک instance دیگر تازه ساخته) پاک نمی‌شوند."""
    async with SAVE_LOCK:
        r = await get_redis()
        if not r:
            return
        try:
            if LINKS:
                await r.hset(REDIS_LINKS_KEY, mapping={uid: json.dumps(d, ensure_ascii=False) for uid, d in LINKS.items()})
            if SUBS:
                await r.hset(REDIS_SUBS_KEY, mapping={sid: json.dumps(s, ensure_ascii=False) for sid, s in SUBS.items()})
            if AUTH["password_hash"] is not None:
                await r.set(REDIS_PASSWORD_KEY, AUTH["password_hash"])
        except Exception as e:
            logger.warning(f"Could not save state to Redis: {e}")

async def redis_delete_link(uid: str):
    r = await get_redis()
    if r:
        try:
            await r.hdel(REDIS_LINKS_KEY, uid)
        except Exception as e:
            logger.warning(f"Could not delete link {uid} from Redis: {e}")

async def redis_delete_sub(sub_id: str):
    r = await get_redis()
    if r:
        try:
            await r.hdel(REDIS_SUBS_KEY, sub_id)
        except Exception as e:
            logger.warning(f"Could not delete sub {sub_id} from Redis: {e}")

async def save_telegram_config():
    r = await get_redis()
    if not r:
        return
    try:
        await r.set(REDIS_TG_KEY, json.dumps(TG_CONFIG, ensure_ascii=False))
    except Exception as e:
        logger.warning(f"Could not save telegram config to Redis: {e}")

async def tg_call(token: str, method: str, **params):
    """یک متد از Telegram Bot API را صدا می‌زند (sendMessage/getMe/setWebhook/...).
    برای جلوگیری از هنگ کردن ربات روی یک درخواست کند، تایم‌اوت کوتاه‌تر شده و
    یک بار retry سبک (فقط برای خطاهای شبکه/تایم‌اوت، نه خطاهای منطقی تلگرام
    مثل 400) انجام می‌شود."""
    if not token or not http_client:
        return None
    url = TG_API_BASE.format(token=token, method=method)
    last_err = None
    for attempt in range(2):
        try:
            resp = await http_client.post(url, json=params, timeout=httpx.Timeout(8.0, connect=4.0))
            return resp.json()
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
            last_err = e
            continue
        except Exception as e:
            logger.warning(f"Telegram API call failed ({method}): {e}")
            return None
    logger.warning(f"Telegram API call failed after retry ({method}): {last_err}")
    return None

async def tg_send(token: str, chat_id, text: str):
    await tg_call(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)

def tg_webhook_secret(token: str) -> str:
    return hashlib.sha256(f"tgwh:{token}:{CONFIG['secret']}".encode()).hexdigest()[:40]

# اگر پردازش یک آپدیت کمی طول بکشد، تلگرام همان update_id را دوباره ارسال
# می‌کند (retry). بدون دِدوپ، این یعنی همان دکمه/دستور دوباره اجرا می‌شود که
# هم باعث پیام‌های تکراری و هم فشار اضافه روی Redis/CPU و در نتیجه هنگ محسوس
# می‌شد. یک حافظه‌ی کوچک و سبک از آخرین update_idهای دیده‌شده نگه می‌داریم.
_TG_SEEN_UPDATE_IDS: deque = deque()
_TG_SEEN_UPDATE_SET: set = set()
_TG_SEEN_MAX = 1000
_TG_DEDUP_LOCK = asyncio.Lock()

async def _tg_is_duplicate_update(update_id) -> bool:
    if update_id is None:
        return False
    async with _TG_DEDUP_LOCK:
        if update_id in _TG_SEEN_UPDATE_SET:
            return True
        _TG_SEEN_UPDATE_IDS.append(update_id)
        _TG_SEEN_UPDATE_SET.add(update_id)
        while len(_TG_SEEN_UPDATE_IDS) > _TG_SEEN_MAX:
            old = _TG_SEEN_UPDATE_IDS.popleft()
            _TG_SEEN_UPDATE_SET.discard(old)
        return False

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()

# پروتکل‌های پشتیبانی‌شده برای هر کانفیگ
PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"

# Fingerprint (uTLS) های قابل انتخاب برای هر کانفیگ
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"

# پیش‌فرض ALPN بر اساس نوع ترابرد (اگر کاربر مقدار دستی نده)
DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535

def log_activity(kind: str, message: str, level: str = "info"):
    """ثبت یک رخداد در لاگ فعالیت‌ها (ساخت/حذف/ویرایش کانفیگ، ورود، و...)."""
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "x4g_session"
SESSION_TTL = 60 * 60 * 24 * 365

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

_admin_pw_env = os.environ.get("ADMIN_PASSWORD")
# اگر ADMIN_PASSWORD صراحتاً ست شده باشد همان استفاده می‌شود؛ در غیر این صورت هیچ
# رمز پیش‌فرضی وجود ندارد و کاربر باید در اولین ورود، خودش یک رمز انتخاب کند
# (به همین دلیل password_hash در حالت اولیه None است، نه هش یک رمز ثابت).
AUTH = {"password_hash": hash_password(_admin_pw_env) if _admin_pw_env else None}
# نکته: روی Vercel هر request ممکن است به یک نمونه‌ی متفاوت برخورد کند، پس سشن‌ها
# باید در Redis ذخیره شوند (نه در دیکشنری این حافظه)، وگرنه کاربر به‌طور نامنظم لاگ‌اوت می‌شود.
SESSIONS: dict = {}  # fallback محلی وقتی Redis تنظیم نشده (برای تست لوکال)
SESSIONS_LOCK = asyncio.Lock()

# ── Telegram Bot ────────────────────────────────────────────────────────────
REDIS_TG_KEY = "x4g:telegram"
TG_CONFIG: dict = {"token": None, "admin_id": None, "enabled": False, "bot_username": None}
TG_API_BASE = "https://api.telegram.org/bot{token}/{method}"

def _session_key(token: str) -> str:
    return f"x4g:session:{token}"

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    r = await get_redis()
    if r:
        await r.set(_session_key(token), "1", ex=SESSION_TTL)
    else:
        async with SESSIONS_LOCK:
            SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    r = await get_redis()
    if r:
        return bool(await r.get(_session_key(token)))
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    r = await get_redis()
    if r:
        await r.delete(_session_key(token))
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    if REDIS_URL and not aioredis:
        logger.warning("پکیج redis نصب نیست؛ به requirements.txt اضافه کنید تا persistence کار کند.")
    await get_redis()
    await load_state()
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"X4G v9.1 started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    
def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "X4G",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
) -> str:
    """می‌سازد VLESS share-link متناسب با پروتکل انتخاب‌شده (WS کلاسیک یا یکی از مدهای XHTTP).
    fingerprint / alpn / port در صورت ندادن، از پیش‌فرض‌های خود پروتکل استفاده می‌شوند."""
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_val = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_val = port or DEFAULT_PORT
    if not (MIN_PORT <= port_val <= MAX_PORT):
        port_val = DEFAULT_PORT

    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    else:
        # xhttp-packet-up / xhttp-stream-up / xhttp-stream-one
        mode = protocol.replace("xhttp-", "")  # packet-up | stream-up | stream-one
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{port_val}?{query}#{quote(remark)}"

def vless_link_for_link(link: dict, uid: str, host: str) -> str:
    """generate_vless_link رو با تنظیمات دستی همون کانفیگ (fingerprint/alpn/port) صدا می‌زنه."""
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    return generate_vless_link(
        uid, host,
        remark=f"X4G-{link.get('label','')}",
        protocol=proto,
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        port=link.get("port"),
    )

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def unique_ips_for_uuid(uuid: str) -> set:
    """آی‌پی‌های یکتای همین لحظه متصل به یک UUID خاص (بر اساس dict اتصالات زنده)."""
    return {c.get("ip") for c in connections.values() if c.get("uuid") == uuid and c.get("ip")}

def is_ip_allowed(link: dict | None, uuid: str, ip: str) -> bool:
    """محدودیت تعداد آی‌پی/کاربر هم‌زمان برای هر کانفیگ. ip_limit=0 یعنی نامحدود.
    اگر همین آی‌پی از قبل روی این کانفیگ سشن باز داشته باشه، همیشه مجازه (برای چند اتصال
    هم‌زمان از یک دستگاه/مرورگر مشکلی پیش نمیاد)."""
    if link is None:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    if ip in ips:
        return True
    return len(ips) < limit

def client_ip(request: Request) -> str:
    """آی‌پی واقعی کلاینت رو با احتساب هدرهای پراکسی (Railway/Cloudflare) برمی‌گردونه."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"

# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                    "fingerprint": DEFAULT_FINGERPRINT,
                    "alpn": "",
                    "port": DEFAULT_PORT,
                    "ip_limit": 0,
                }
                await save_state()
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "X4G", "version": "9.1", "status": "active", "channel": "https://t.me/Farajian2004f"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription (single link) ────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link:
        await refresh_links_and_subs()
        async with LINKS_LOCK:
            link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host()
    vless = vless_link_for_link(link, uuid, host)
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": quote(link["label"]), "support-url": "https://t.me/Farajian2004f"})

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = get_host()
    async with LINKS_LOCK:
        lines = [
            vless_link_for_link(d, uid, host)
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ══════════════════════════════════════════════════════════════════════════════
# SUB GROUP endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    await refresh_links_and_subs()
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    await save_state()
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(_=Depends(require_auth)):
    await refresh_links_and_subs()
    host = get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    await refresh_links_and_subs()
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    await save_state()
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    await refresh_links_and_subs()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    await redis_delete_sub(sub_id)
    await save_state()
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    await refresh_links_and_subs()
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    await save_state()
    return {"ok": True}

# ── Public sub-group subscription file ───────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    await refresh_links_and_subs()
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        lines = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                lines.append(vless_link_for_link(link, lid, host))

    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "support-url": "https://t.me/Farajian2004f",
            "profile-update-interval": "12",
        }
    )

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if AUTH["password_hash"] is None:
        raise HTTPException(status_code=409, detail="ابتدا باید یک رمز عبور برای پنل انتخاب کنید")
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {
        "authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE)),
        "needs_setup": AUTH["password_hash"] is None,
    }

@app.post("/api/setup-password")
async def api_setup_password(request: Request):
    """فقط در اولین راه‌اندازی (وقتی هنوز هیچ رمزی ثبت نشده) قابل استفاده است؛
    رمز انتخابی کاربر برای همیشه ذخیره می‌شود تا زمانی که خودش از طریق
    change-password آن را عوض کند."""
    if AUTH["password_hash"] is not None:
        raise HTTPException(status_code=400, detail="رمز عبور قبلاً تنظیم شده است")
    body = await request.json()
    ip = client_ip(request)
    pw = str(body.get("password", ""))
    if len(pw) < 4:
        raise HTTPException(status_code=400, detail="رمز عبور باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(pw)
    await save_state()
    token = await create_session()
    log_activity("auth", f"رمز عبور اولیه پنل تنظیم شد از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    r = await get_redis()
    if r:
        keys = [k async for k in r.scan_iter(match="x4g:session:*")]
        if keys:
            await r.delete(*keys)
        await r.set(_session_key(token), "1", ex=SESSION_TTL)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    return {"ok": True}

# ── Backup / Restore ──────────────────────────────────────────────────────────
BACKUP_VERSION = 1

@app.get("/api/backup")
async def api_backup(_=Depends(require_auth)):
    """یک بکاپ کامل JSON از تمام داده‌های پنل (لینک‌ها، گروه‌های ساب و هش رمز عبور)
    برمی‌گرداند تا کاربر بتواند آن را دانلود و بعداً بازیابی کند."""
    await refresh_links_and_subs()
    async with LINKS_LOCK:
        links_snap = dict(LINKS)
    async with SUBS_LOCK:
        subs_snap = dict(SUBS)
    payload = {
        "app": "X4G",
        "backup_version": BACKUP_VERSION,
        "created_at": datetime.now().isoformat(),
        "host": get_host(),
        "data": {
            "links": links_snap,
            "subs": subs_snap,
            "password_hash": AUTH["password_hash"],
        },
    }
    filename = f"x4g-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    log_activity("system", "یک بکاپ کامل از داده‌های پنل گرفته شد", "ok")
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.post("/api/restore")
async def api_restore(request: Request, _=Depends(require_auth)):
    """داده‌های پنل (لینک‌ها/گروه‌های ساب/رمز عبور) را از یک فایل بکاپ که قبلاً با
    /api/backup گرفته شده بازیابی می‌کند. این عملیات تمام داده‌های فعلی را
    جایگزین می‌کند (هم در حافظه و هم در Redis)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="فایل بکاپ نامعتبر است (JSON نیست)")

    data = body.get("data") if isinstance(body, dict) and "data" in body else body
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="ساختار فایل بکاپ نامعتبر است")

    new_links = data.get("links")
    new_subs = data.get("subs")
    new_pw_hash = data.get("password_hash")

    if not isinstance(new_links, dict) or not isinstance(new_subs, dict):
        raise HTTPException(status_code=400, detail="فایل بکاپ فاقد اطلاعات لینک‌ها/گروه‌هاست")

    r = await get_redis()

    async with LINKS_LOCK:
        LINKS.clear()
        LINKS.update(new_links)
    async with SUBS_LOCK:
        SUBS.clear()
        SUBS.update(new_subs)
    if new_pw_hash:
        AUTH["password_hash"] = new_pw_hash

    # اول کل Hashهای قدیمی روی Redis پاک می‌شوند تا رکوردهایی که در بکاپ جدید
    # نیستند باقی نمانند، سپس داده‌ی تازه نوشته می‌شود.
    if r:
        try:
            await r.delete(REDIS_LINKS_KEY)
            await r.delete(REDIS_SUBS_KEY)
        except Exception as e:
            logger.warning(f"Could not clear old state before restore: {e}")

    await save_state()
    global _default_link_created
    _default_link_created = True
    log_activity("system", f"داده‌های پنل از فایل بکاپ بازیابی شد ({len(new_links)} لینک، {len(new_subs)} گروه)", "warn")
    return {"ok": True, "links_count": len(new_links), "subs_count": len(new_subs)}

# ── Telegram Bot ──────────────────────────────────────────────────────────────
@app.get("/api/telegram/settings")
async def get_telegram_settings(_=Depends(require_auth)):
    token = TG_CONFIG.get("token")
    masked = (token[:6] + "…" + token[-4:]) if token and len(token) > 12 else None
    return {
        "configured": bool(token),
        "token_masked": masked,
        "admin_id": TG_CONFIG.get("admin_id"),
        "enabled": bool(TG_CONFIG.get("enabled")),
        "bot_username": TG_CONFIG.get("bot_username"),
    }

@app.post("/api/telegram/settings")
async def update_telegram_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    token = str(body.get("token") or "").strip()
    admin_id = str(body.get("admin_id") or "").strip()
    enabled = bool(body.get("enabled"))

    # اگر فیلد توکن خالی فرستاده شده ولی قبلاً یک توکن ذخیره شده، همان مقدار قبلی
    # حفظ می‌شود (برای وقتی کاربر فقط می‌خواهد آیدی ادمین یا وضعیت را عوض کند).
    if not token and TG_CONFIG.get("token"):
        token = TG_CONFIG["token"]

    if enabled:
        if not token:
            raise HTTPException(status_code=400, detail="برای فعال‌سازی، توکن ربات را وارد کنید")
        if not admin_id or not admin_id.lstrip("-").isdigit():
            raise HTTPException(status_code=400, detail="آیدی عددی ادمین معتبر نیست")

    bot_username = TG_CONFIG.get("bot_username")
    host = get_host()

    if enabled:
        me = await tg_call(token, "getMe")
        if not me or not me.get("ok"):
            raise HTTPException(status_code=400, detail="توکن ربات نامعتبر است یا تلگرام در دسترس نیست")
        bot_username = me["result"].get("username")
        secret = tg_webhook_secret(token)
        wh = await tg_call(token, "setWebhook", url=f"https://{host}/api/telegram/webhook/{secret}", allowed_updates=["message", "callback_query"])
        if not wh or not wh.get("ok"):
            raise HTTPException(status_code=400, detail="ثبت webhook ناموفق بود؛ آدرس پنل باید https و در دسترس عموم باشد")
    elif token:
        await tg_call(token, "deleteWebhook")

    TG_CONFIG["token"] = token or None
    TG_CONFIG["admin_id"] = admin_id or None
    TG_CONFIG["enabled"] = enabled
    TG_CONFIG["bot_username"] = bot_username
    await save_telegram_config()
    log_activity("system", f"ربات تلگرام {'فعال' if enabled else 'غیرفعال'} شد", "ok" if enabled else "warn")
    return {"ok": True, "bot_username": bot_username, "enabled": enabled}

def _is_number(s: str) -> bool:
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False

# ── Telegram — Inline Keyboard UI ──────────────────────────────────────────
TG_PAGE_SIZE = 6

def tg_home_text() -> str:
    return "🤖 <b>پنل مدیریت X4G</b>\nیکی از گزینه‌های زیر را انتخاب کنید 👇"

def tg_main_menu_kb() -> dict:
    return {
        "inline_keyboard": [
            [{"text": "📊 وضعیت پنل", "callback_data": "status"}, {"text": "📋 کانفیگ‌ها", "callback_data": "links:0"}],
            [{"text": "➕ کانفیگ جدید", "callback_data": "newcfg"}, {"text": "🌐 گروه‌های ساب", "callback_data": "subs:0"}],
            [{"text": "🔄 رفرش", "callback_data": "menu"}, {"text": "ℹ️ راهنما", "callback_data": "help"}],
        ]
    }

def tg_back_kb(extra_rows: list | None = None) -> dict:
    rows = [list(r) for r in (extra_rows or [])]
    rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

def tg_help_text() -> str:
    return (
        "ℹ️ <b>راهنما</b>\n\n"
        "از دکمه‌های شیشه‌ای زیر برای مدیریت پنل استفاده کنید:\n"
        "📊 <b>وضعیت پنل</b> — آمار لحظه‌ای\n"
        "📋 <b>کانفیگ‌ها</b> — لیست، فعال/غیرفعال، حذف\n"
        "➕ <b>کانفیگ جدید</b> — انتخاب حجم و مدت با دکمه\n"
        "🌐 <b>گروه‌های ساب</b> — مشاهده گروه‌های ساب\n\n"
        "دستورات متنی هم قابل استفاده‌اند:\n"
        "<code>/newconfig نام حجم_GB روز</code>\n"
        "<code>/on uuid</code> · <code>/off uuid</code> · <code>/del uuid</code>\n"
        "<code>/find متن</code> — جستجوی کانفیگ بر اساس نام\n"
        "<code>/ping</code> — تست سرعت اتصال ربات\n"
        "<code>/id</code> — گرفتن Chat ID"
    )

async def tg_status_text() -> str:
    await refresh_links_and_subs()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    active = sum(1 for l in snap.values() if is_link_allowed(l))
    return (
        "📊 <b>وضعیت پنل</b>\n\n"
        f"🔌 اتصالات فعال: {len(connections)}\n"
        f"📈 ترافیک کل: {round(stats['total_bytes'] / (1024 ** 2), 2)} MB\n"
        f"⏱ آپ‌تایم: {uptime()}\n"
        f"🔗 کانفیگ‌ها: {len(snap)} (فعال: {active})\n"
        f"🌐 گروه‌های ساب: {len(SUBS)}"
    )

async def tg_links_page(page: int):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    items = sorted(snap.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    pages = max(1, (total + TG_PAGE_SIZE - 1) // TG_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    chunk = items[page * TG_PAGE_SIZE:(page + 1) * TG_PAGE_SIZE]
    rows = []
    for uid, d in chunk:
        status = "🟢" if is_link_allowed(d) else "🔴"
        rows.append([{"text": f"{status} {d.get('label', '—')[:28]}", "callback_data": f"link:{uid}"}])
    nav = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"links:{page - 1}"})
    if page < pages - 1:
        nav.append({"text": "بعدی ▶️", "callback_data": f"links:{page + 1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "➕ کانفیگ جدید", "callback_data": "newcfg"}])
    rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
    if not items:
        text = "📋 هیچ کانفیگی وجود ندارد.\nبرای ساخت یکی، دکمه زیر را بزنید."
    else:
        text = f"📋 <b>کانفیگ‌ها</b> ({total} مورد) — صفحه {page + 1}/{pages}\nروی هرکدام بزنید برای مدیریت."
    return text, {"inline_keyboard": rows}

def tg_link_detail(uid: str):
    d = LINKS.get(uid)
    if not d:
        return "این کانفیگ دیگر وجود ندارد.", tg_back_kb()
    host = get_host()
    allowed = is_link_allowed(d)
    used = fmt_bytes(d.get("used_bytes", 0))
    limit = "∞" if d.get("limit_bytes", 0) == 0 else fmt_bytes(d["limit_bytes"])
    exp = d.get("expires_at")
    exp_str = "نامحدود" if not exp else exp[:10]
    vless = vless_link_for_link(d, uid, host)
    text = (
        f"{'🟢 فعال' if allowed else '🔴 غیرفعال'} <b>{d.get('label')}</b>\n"
        f"UUID: <code>{uid}</code>\n"
        f"مصرف: {used} / {limit}\n"
        f"انقضا: {exp_str}\n\n"
        f"<code>{vless}</code>"
    )
    toggle_btn = (
        {"text": "🔴 غیرفعال کن", "callback_data": f"linkoff:{uid}"}
        if d.get("active", True)
        else {"text": "🟢 فعال کن", "callback_data": f"linkon:{uid}"}
    )
    rows = [
        [toggle_btn, {"text": "🗑 حذف", "callback_data": f"linkdel:{uid}"}],
        [{"text": "📋 لیست کانفیگ‌ها", "callback_data": "links:0"}],
        [{"text": "🔙 بازگشت به منو", "callback_data": "menu"}],
    ]
    return text, {"inline_keyboard": rows}

def tg_quota_kb() -> dict:
    opts = [("نامحدود", "0"), ("500 MB", "0.5"), ("1 GB", "1"), ("5 GB", "5"), ("10 GB", "10"), ("50 GB", "50")]
    rows, row = [], []
    for label, val in opts:
        row.append({"text": label, "callback_data": f"nq:{val}"})
        if len(row) == 3:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

def tg_expiry_kb(gb: str) -> dict:
    opts = [("نامحدود", "0"), ("۷ روز", "7"), ("۳۰ روز", "30"), ("۹۰ روز", "90")]
    rows, row = [], []
    for label, val in opts:
        row.append({"text": label, "callback_data": f"ne:{gb}:{val}"})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

async def tg_create_quick_config(limit_gb: float, days: int, label: str | None = None):
    limit_bytes = 0 if limit_gb <= 0 else parse_size_to_bytes(limit_gb, "GB")
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    label = (label or f"تلگرام #{secrets.token_hex(2)}")[:60]
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
            "created_at": datetime.now().isoformat(), "active": True,
            "expires_at": expires_at, "note": "ساخته‌شده از تلگرام", "is_default": False,
            "sub_id": None, "protocol": DEFAULT_PROTOCOL, "fingerprint": DEFAULT_FINGERPRINT,
            "alpn": "", "port": DEFAULT_PORT, "ip_limit": 0,
        }
        new_link = LINKS[uid]
    await save_state()
    log_activity("link", f"کانفیگ «{label}» از تلگرام ساخته شد", "ok")
    return uid, new_link

def tg_subs_page(page: int):
    items = sorted(SUBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    pages = max(1, (total + TG_PAGE_SIZE - 1) // TG_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    chunk = items[page * TG_PAGE_SIZE:(page + 1) * TG_PAGE_SIZE]
    rows = []
    for sid, s in chunk:
        rows.append([{"text": f"🌐 {s.get('name', '—')[:26]} ({len(s.get('link_ids', []))})", "callback_data": f"sub:{sid}"}])
    nav = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"subs:{page - 1}"})
    if page < pages - 1:
        nav.append({"text": "بعدی ▶️", "callback_data": f"subs:{page + 1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
    if not items:
        text = "🌐 هیچ گروه سابی وجود ندارد.\n(از داخل پنل وب می‌توانید گروه بسازید.)"
    else:
        text = f"🌐 <b>گروه‌های ساب</b> ({total} مورد) — صفحه {page + 1}/{pages}"
    return text, {"inline_keyboard": rows}

def tg_sub_detail(sid: str):
    s = SUBS.get(sid)
    if not s:
        return "این گروه دیگر وجود ندارد.", tg_back_kb()
    host = get_host()
    link_ids = s.get("link_ids", [])
    active_count = sum(1 for lid in link_ids if is_link_allowed(LINKS.get(lid)))
    text = (
        f"🌐 <b>{s.get('name')}</b>\n"
        f"{s.get('desc') or ''}\n\n"
        f"تعداد کانفیگ: {len(link_ids)} (فعال: {active_count})\n"
        f"رمز: {'دارد 🔒' if s.get('password_hash') else 'ندارد'}\n\n"
        f"لینک عمومی:\n<code>https://{host}/p/{s['uuid_key']}</code>"
    )
    rows = [
        [{"text": "🌐 همه گروه‌ها", "callback_data": "subs:0"}],
        [{"text": "🔙 بازگشت به منو", "callback_data": "menu"}],
    ]
    return text, {"inline_keyboard": rows}

async def tg_edit_or_send(token: str, chat_id, message_id, text: str, kb: dict | None = None):
    """ابتدا سعی می‌کند پیام قبلی را ویرایش کند (برای ناوبری روان با دکمه‌ها)؛
    اگر ویرایش ممکن نبود (مثلاً پیام خیلی قدیمی یا اولین پیام)، پیام جدید می‌فرستد.
    اگر محتوای جدید دقیقاً همان محتوای قبلی باشد (خطای Telegram not modified)،
    از ارسال پیام تکراری صرف‌نظر می‌شود."""
    if message_id:
        r = await tg_call(token, "editMessageText", chat_id=chat_id, message_id=message_id,
                           text=text, parse_mode="HTML", reply_markup=kb, disable_web_page_preview=True)
        if r and r.get("ok"):
            return
        if r and "not modified" in str(r.get("description", "")).lower():
            return
    await tg_call(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML",
                  reply_markup=kb, disable_web_page_preview=True)

# ── Telegram — Text Commands (برای کاربران حرفه‌ای) ────────────────────────
async def handle_telegram_command(token: str, chat_id, text: str):
    if not text:
        return
    parts = text.strip().split()
    cmd = parts[0].lower().split("@")[0]
    args = parts[1:]

    if cmd in ("/start", "/menu"):
        await tg_call(token, "sendMessage", chat_id=chat_id, text=tg_home_text(),
                      parse_mode="HTML", reply_markup=tg_main_menu_kb())
        return

    if cmd == "/help":
        await tg_call(token, "sendMessage", chat_id=chat_id, text=tg_help_text(),
                      parse_mode="HTML", reply_markup=tg_back_kb())
        return

    if cmd == "/ping":
        t0 = time.monotonic()
        r = await get_redis()
        redis_ms = None
        if r:
            rt0 = time.monotonic()
            try:
                await r.ping()
                redis_ms = round((time.monotonic() - rt0) * 1000)
            except Exception:
                redis_ms = -1
        tg_t0 = time.monotonic()
        me = await tg_call(token, "getMe")
        tg_ms = round((time.monotonic() - tg_t0) * 1000)
        total_ms = round((time.monotonic() - t0) * 1000)
        redis_txt = "متصل نیست ⚠️" if redis_ms is None else (f"{redis_ms} ms" if redis_ms >= 0 else "خطا ⚠️")
        tg_txt = f"{tg_ms} ms" if me and me.get("ok") else "خطا ⚠️"
        await tg_call(token, "sendMessage", chat_id=chat_id, text=(
            "🏓 <b>Ping</b>\n\n"
            f"⚡️ Telegram API: {tg_txt}\n"
            f"🗄 Redis: {redis_txt}\n"
            f"⏱ کل پردازش: {total_ms} ms"
        ), parse_mode="HTML")
        return

    if cmd == "/id":
        await tg_call(token, "sendMessage", chat_id=chat_id,
                      text=f"🆔 Chat ID شما: <code>{chat_id}</code>", parse_mode="HTML")
        return

    if cmd == "/status":
        await tg_call(token, "sendMessage", chat_id=chat_id, text=await tg_status_text(),
                      parse_mode="HTML", reply_markup=tg_back_kb([[{"text": "🔄 بروزرسانی", "callback_data": "status"}]]))
        return

    if cmd == "/list":
        text_out, kb = await tg_links_page(0)
        await tg_call(token, "sendMessage", chat_id=chat_id, text=text_out, parse_mode="HTML", reply_markup=kb)
        return

    if cmd == "/find":
        query = " ".join(args).strip().lower()
        if not query:
            await tg_send(token, chat_id, "لطفاً بعد از /find یک عبارت برای جستجو بنویسید.\nمثال: <code>/find تلگرام</code>")
            return
        async with LINKS_LOCK:
            matches = [(uid, d) for uid, d in LINKS.items() if query in (d.get("label", "") or "").lower()]
        matches.sort(key=lambda kv: kv[1].get("created_at", ""), reverse=True)
        if not matches:
            await tg_send(token, chat_id, f"چیزی برای «{query}» پیدا نشد.")
            return
        rows = [[{"text": f"{'🟢' if is_link_allowed(d) else '🔴'} {d.get('label', '—')[:28]}", "callback_data": f"link:{uid}"}]
                for uid, d in matches[:15]]
        rows.append([{"text": "🔙 بازگشت به منو", "callback_data": "menu"}])
        extra = f"\n(فقط ۱۵ مورد اول از {len(matches)} نتیجه نمایش داده شد)" if len(matches) > 15 else ""
        await tg_call(token, "sendMessage", chat_id=chat_id,
                      text=f"🔍 نتایج جستجو برای «{query}» ({len(matches)} مورد){extra}",
                      parse_mode="HTML", reply_markup={"inline_keyboard": rows})
        return

    if cmd == "/newconfig":
        label = args[0] if len(args) >= 1 else None
        limit_gb = float(args[1]) if len(args) >= 2 and _is_number(args[1]) else 0
        days = int(args[2]) if len(args) >= 3 and args[2].isdigit() else 0
        uid, new_link = await tg_create_quick_config(limit_gb, days, label)
        text_out, kb = tg_link_detail(uid)
        await tg_call(token, "sendMessage", chat_id=chat_id, text="✅ کانفیگ جدید ساخته شد!\n\n" + text_out,
                      parse_mode="HTML", reply_markup=kb)
        return

    if cmd in ("/on", "/off", "/del"):
        if not args:
            await tg_send(token, chat_id, "لطفاً UUID یا چند کاراکتر اول آن را وارد کنید.")
            return
        prefix = args[0]
        async with LINKS_LOCK:
            match = next((u for u in LINKS if u.startswith(prefix)), None)
        if not match:
            await tg_send(token, chat_id, "کانفیگی با این UUID پیدا نشد.")
            return
        if cmd == "/del":
            async with LINKS_LOCK:
                label = LINKS[match].get("label", match)
                sub_id = LINKS[match].get("sub_id")
                del LINKS[match]
            if sub_id:
                async with SUBS_LOCK:
                    if sub_id in SUBS:
                        ids = SUBS[sub_id].get("link_ids", [])
                        if match in ids:
                            ids.remove(match)
            await redis_delete_link(match)
            await save_state()
            log_activity("link", f"کانفیگ «{label}» از تلگرام حذف شد", "err")
            text_out, kb = await tg_links_page(0)
            await tg_call(token, "sendMessage", chat_id=chat_id, text=f"🗑 کانفیگ «{label}» حذف شد.\n\n" + text_out,
                          parse_mode="HTML", reply_markup=kb)
        else:
            active = cmd == "/on"
            async with LINKS_LOCK:
                LINKS[match]["active"] = active
            await save_state()
            log_activity("link", f"کانفیگ «{LINKS[match].get('label', match)}» از تلگرام {'فعال' if active else 'غیرفعال'} شد", "ok" if active else "warn")
            text_out, kb = tg_link_detail(match)
            await tg_call(token, "sendMessage", chat_id=chat_id, text=text_out, parse_mode="HTML", reply_markup=kb)
        return

    await tg_call(token, "sendMessage", chat_id=chat_id, text="دستور نامعتبر. برای منو /menu را بفرستید.",
                  parse_mode="HTML", reply_markup=tg_main_menu_kb())

# ── Telegram — Callback Query (دکمه‌های شیشه‌ای) ───────────────────────────
async def handle_telegram_callback(token: str, cq: dict):
    data = cq.get("data") or ""
    msg = cq.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    message_id = msg.get("message_id")
    from_id = cq.get("from", {}).get("id")
    cq_id = cq.get("id")

    admin_id = TG_CONFIG.get("admin_id")
    if not admin_id or str(from_id) != str(admin_id):
        await tg_call(token, "answerCallbackQuery", callback_query_id=cq_id, text="⛔ دسترسی غیرمجاز", show_alert=True)
        return

    # نکته‌ی مهم برای رفع «هنگ» دکمه‌ها: تا وقتی answerCallbackQuery نرسد،
    # تلگرام چرخ‌وفلک لودینگ را روی دکمه نگه می‌دارد. قبلاً این تایید در
    # انتهای پردازش (بعد از refresh از Redis و ویرایش پیام) ارسال می‌شد که
    # حس هنگ‌کردن ایجاد می‌کرد. حالا بی‌درنگ و بدون انتظار ارسال می‌شود و
    # ادامه‌ی پردازش (رفرش/ویرایش پیام) موازی با آن انجام می‌شود.
    asyncio.create_task(tg_call(token, "answerCallbackQuery", callback_query_id=cq_id))

    await refresh_links_and_subs()
    ack_text = ""
    try:
        if data in ("menu", "back"):
            await tg_edit_or_send(token, chat_id, message_id, tg_home_text(), tg_main_menu_kb())
        elif data == "help":
            await tg_edit_or_send(token, chat_id, message_id, tg_help_text(), tg_back_kb())
        elif data == "status":
            await tg_edit_or_send(token, chat_id, message_id, await tg_status_text(),
                                   tg_back_kb([[{"text": "🔄 بروزرسانی", "callback_data": "status"}]]))
        elif data.startswith("links:"):
            page = int(data.split(":", 1)[1] or 0)
            text_out, kb = await tg_links_page(page)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
        elif data.startswith("linkon:") or data.startswith("linkoff:"):
            active = data.startswith("linkon:")
            uid = data.split(":", 1)[1]
            async with LINKS_LOCK:
                exists = uid in LINKS
                if exists:
                    LINKS[uid]["active"] = active
                    label = LINKS[uid].get("label", uid)
            if exists:
                await save_state()
                log_activity("link", f"کانفیگ «{label}» از تلگرام {'فعال' if active else 'غیرفعال'} شد", "ok" if active else "warn")
                ack_text = "🟢 فعال شد" if active else "🔴 غیرفعال شد"
            text_out, kb = tg_link_detail(uid)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
        elif data.startswith("linkdelok:"):
            uid = data.split(":", 1)[1]
            async with LINKS_LOCK:
                exists = uid in LINKS
                label = LINKS[uid].get("label", uid) if exists else uid
                sub_id = LINKS[uid].get("sub_id") if exists else None
                if exists:
                    del LINKS[uid]
            if sub_id:
                async with SUBS_LOCK:
                    if sub_id in SUBS:
                        ids = SUBS[sub_id].get("link_ids", [])
                        if uid in ids:
                            ids.remove(uid)
            if exists:
                await redis_delete_link(uid)
                await save_state()
                log_activity("link", f"کانفیگ «{label}» از تلگرام حذف شد", "err")
                ack_text = "🗑 حذف شد"
            text_out, kb = await tg_links_page(0)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
        elif data.startswith("linkdel:"):
            uid = data.split(":", 1)[1]
            label = LINKS.get(uid, {}).get("label", uid)
            kb = {"inline_keyboard": [
                [{"text": "✅ بله، حذف کن", "callback_data": f"linkdelok:{uid}"}, {"text": "❌ انصراف", "callback_data": f"link:{uid}"}],
            ]}
            await tg_edit_or_send(token, chat_id, message_id, f"⚠️ آیا از حذف «{label}» مطمئن هستید؟", kb)
        elif data.startswith("link:"):
            uid = data.split(":", 1)[1]
            text_out, kb = tg_link_detail(uid)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
        elif data == "newcfg":
            await tg_edit_or_send(token, chat_id, message_id, "📦 حجم مصرفی کانفیگ را انتخاب کنید:", tg_quota_kb())
        elif data.startswith("nq:"):
            gb = data.split(":", 1)[1]
            gb_label = "نامحدود" if gb == "0" else f"{gb} GB"
            await tg_edit_or_send(token, chat_id, message_id, f"📦 حجم: {gb_label}\n⏳ مدت اعتبار را انتخاب کنید:", tg_expiry_kb(gb))
        elif data.startswith("ne:"):
            _, gb, days = data.split(":")
            uid, _new_link = await tg_create_quick_config(float(gb), int(days))
            ack_text = "✅ کانفیگ ساخته شد"
            text_out, kb = tg_link_detail(uid)
            await tg_edit_or_send(token, chat_id, message_id, "✅ کانفیگ جدید ساخته شد!\n\n" + text_out, kb)
        elif data.startswith("subs:"):
            page = int(data.split(":", 1)[1] or 0)
            text_out, kb = tg_subs_page(page)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
        elif data.startswith("sub:"):
            sid = data.split(":", 1)[1]
            text_out, kb = tg_sub_detail(sid)
            await tg_edit_or_send(token, chat_id, message_id, text_out, kb)
    except Exception as e:
        logger.warning(f"Telegram callback error: {e}")
        # چون از قبل (بی‌درنگ) به callback جواب داده شده، در صورت خطا یک پیام
        # جدید برای اطلاع ادمین ارسال می‌شود تا کاربر بی‌خبر نماند.
        if chat_id:
            await tg_send(token, chat_id, "⚠️ خطایی هنگام پردازش رخ داد. دوباره تلاش کنید.")

@app.post("/api/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request, background_tasks: BackgroundTasks):
    """این endpoint باید در سریع‌ترین حالت ممکن به تلگرام پاسخ ۲۰۰ بدهد؛
    وگرنه تلگرام همان آپدیت را دوباره ارسال می‌کند و پردازش تکراری/انباشته
    باعث کند و هنگ به‌نظر رسیدن ربات می‌شود. به همین دلیل پردازش واقعی
    (که شامل چند فراخوانی Redis و چند فراخوانی API تلگرام است) به یک
    background task منتقل شده و اینجا فوراً {"ok": true} برمی‌گردد."""
    token = TG_CONFIG.get("token")
    if not token or not TG_CONFIG.get("enabled") or secret != tg_webhook_secret(token):
        raise HTTPException(status_code=404, detail="not found")
    try:
        update = await request.json()
    except Exception:
        return {"ok": True}

    if await _tg_is_duplicate_update(update.get("update_id")):
        # آپدیت تکراری (retry تلگرام به‌خاطر تأخیر در پاسخ قبلی) — نادیده گرفته می‌شود
        return {"ok": True}

    background_tasks.add_task(_process_telegram_update, token, update)
    return {"ok": True}

async def _process_telegram_update(token: str, update: dict):
    """پردازش واقعی آپدیت تلگرام، جدا از چرخه‌ی پاسخ‌دهی به وبهوک."""
    t0 = time.monotonic()
    try:
        if "callback_query" in update:
            await handle_telegram_callback(token, update["callback_query"])
            return

        message = update.get("message") or update.get("edited_message")
        if not message:
            return

        chat_id = message.get("chat", {}).get("id")
        from_id = message.get("from", {}).get("id")
        text = (message.get("text") or "").strip()

        admin_id = TG_CONFIG.get("admin_id")
        if not admin_id or str(from_id) != str(admin_id):
            if chat_id:
                await tg_send(token, chat_id, "⛔ شما اجازه‌ی استفاده از این ربات را ندارید.")
            return

        await refresh_links_and_subs()
        await handle_telegram_command(token, chat_id, text)
    except Exception as e:
        logger.warning(f"Telegram update processing failed: {e}")
    finally:
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms > 3000:
            logger.warning(f"Telegram update took {elapsed_ms:.0f}ms to process")

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
    }

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections (with IP) ────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    """
    خروجی این endpoint حالا بر اساس IP گروه‌بندی شده:
    هر آی‌پی فقط یک آیتم نمایش داده می‌شود، با جمع بایت‌های تمام سشن‌های
    باز روی همان آی‌پی و تعداد سشن‌های فعال آن آی‌پی.
    raw_count همچنان تعداد واقعی اتصالات باز (سشن‌های خام، مثلاً ۴۰ تا
    اتصال هم‌زمان یک موبایل) را برمی‌گرداند.
    """
    async with LINKS_LOCK:
        snap = dict(LINKS)

    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca

    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "connections": result,
        "count": len(result),          # تعداد آی‌پی‌های یکتا
        "raw_count": len(connections), # تعداد کل اتصالات باز (بدون گروه‌بندی)
    }

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    await refresh_links_and_subs()
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(body.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT
    alpn = str(body.get("alpn") or "").strip()[:100]
    try:
        port = int(body.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    if not (MIN_PORT <= port <= MAX_PORT):
        port = DEFAULT_PORT
    try:
        ip_limit = int(body.get("ip_limit") or 0)
    except (TypeError, ValueError):
        ip_limit = 0
    if ip_limit < 0:
        ip_limit = 0

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
            "fingerprint": fingerprint,
            "alpn": alpn,
            "port": port,
            "ip_limit": ip_limit,
        }

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    await save_state()
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": vless_link_for_link(LINKS[uid], uid, host),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    await refresh_links_and_subs()
    host = get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": vless_link_for_link(d, uid, host),
            "sub_url": f"https://{host}/sub/{uid}",
            "connected_ips": len(unique_ips_for_uuid(uid)),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    await refresh_links_and_subs()
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "fingerprint" in body:
            fp = str(body.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
            link["fingerprint"] = fp if fp in FINGERPRINTS else DEFAULT_FINGERPRINT
        if "alpn" in body:
            link["alpn"] = str(body.get("alpn") or "").strip()[:100]
        if "port" in body:
            try:
                p = int(body.get("port") or DEFAULT_PORT)
            except (TypeError, ValueError):
                p = DEFAULT_PORT
            link["port"] = p if (MIN_PORT <= p <= MAX_PORT) else DEFAULT_PORT
        if "ip_limit" in body:
            try:
                il = int(body.get("ip_limit") or 0)
            except (TypeError, ValueError):
                il = 0
            link["ip_limit"] = max(0, il)
        if any(k in body for k in ("label", "note", "limit_value", "expires_days", "fingerprint", "alpn", "port", "ip_limit")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    await save_state()
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    await refresh_links_and_subs()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    await redis_delete_link(uid)
    await save_state()
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay — جدا شده به relay_vless.py (دست نخورده)
# ══════════════════════════════════════════════════════════════════════════════

from relay_vless import (
    RELAY_BUF,
    parse_vless_header,
    check_and_use,
    relay_ws_to_tcp,
    relay_tcp_to_ws,
    websocket_tunnel,
)

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

# ══════════════════════════════════════════════════════════════════════════════
# XHTTP — Siz10a XHTTP Ultra (ترابرد جدید، جدا از VLESS/WS، هر ۳ مد)
# ══════════════════════════════════════════════════════════════════════════════
from xhttp_siz10 import router as xhttp_router
app.include_router(xhttp_router)

# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    await refresh_links_and_subs()
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    await refresh_links_and_subs()
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)

    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
            "expires_at": link.get("expires_at"),
            "vless_link": vless_link_for_link(link, lid, host),
            "sub_url": f"https://{host}/sub/{lid}",
            "connections": conn_count,
            "ip_limit": link.get("ip_limit", 0),
        })

    total_used = sum(l["used_bytes"] for l in links_out)
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
    }

# ── HTML Pages (login + dashboard) ───────────────────────────────────────────
from pages import LOGIN_HTML, DASHBOARD_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await refresh_links_and_subs()
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
