from fastapi import FastAPI, APIRouter, HTTPException, Header, Depends, Response, Request, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, validator, EmailStr
from typing import List, Optional, Literal, Dict, Any
from pathlib import Path as SysPath
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os
import logging
import uuid
import hashlib
import secrets
import json
from collections import defaultdict, deque
from time import time
from functools import wraps
import base64
import hmac

# -----------------------------------------------------------------------------
# ENV & DB
# -----------------------------------------------------------------------------
ROOT_DIR = SysPath(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

AUTH_LITE_DEBUG = os.environ.get("AUTH_LITE_DEBUG", "true").lower() == "true"
PLUS_UNDO = os.environ.get("PLUS_UNDO", "false").lower() == "true"
GOLD_SEE_LIKES = os.environ.get("GOLD_SEE_LIKES", "false").lower() == "true"

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRES_DAYS = int(os.environ.get("JWT_EXPIRES_DAYS", "7"))
REFRESH_EXPIRES_DAYS = int(os.environ.get("REFRESH_EXPIRES_DAYS", "30"))

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("FROM_EMAIL")

# PROD flag
IS_PROD = os.environ.get("ENV", "dev").lower() == "prod"

# -----------------------------------------------------------------------------
# APP
# -----------------------------------------------------------------------------
app = FastAPI(title="SkillSwap API", version="0.1.0")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("skillswap")

# -----------------------------------------------------------------------------
# TINY IN-MEMORY RATE LIMITER (IP + route)
# -----------------------------------------------------------------------------
_RL_STORE: Dict[str, deque] = defaultdict(deque)

def rate_limit(max_calls: int, per_seconds: int, key_func=None):
    def deco(handler):
        @wraps(handler)
        async def wrapper(*args, **kwargs):
            # Retrouver Request parmi les args/kwargs injectés par FastAPI
            request: Optional[Request] = kwargs.get("request")
            if request is None:
                for a in args:
                    if isinstance(a, Request):
                        request = a
                        break
            if request is None:
                # si Request introuvable, on laisse passer (évite de casser l'endpoint)
                return await handler(*args, **kwargs)

            now = time()
            ip = request.client.host if request.client else "unknown"
            k = key_func(request) if key_func else f"{ip}:{request.url.path}"
            dq = _RL_STORE[k]
            while dq and now - dq[0] > per_seconds:
                dq.popleft()
            if len(dq) >= max_calls:
                raise HTTPException(status_code=429, detail="rate_limited")
            dq.append(now)
            return await handler(*args, **kwargs)
        return wrapper
    return deco

# -----------------------------------------------------------------------------
# SECURITY HEADERS MIDDLEWARE
# -----------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Limiter la taille des bodies via Content-Length (1MB)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > 1_000_000:
        return Response(status_code=413, content="Payload Too Large")

    resp = await call_next(request)

    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' https:; connect-src 'self' https:; frame-ancestors 'none';"
    )
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=15552000; includeSubDomains; preload"
    return resp

# -----------------------------------------------------------------------------
# MODELS
# -----------------------------------------------------------------------------
class AuthRequest(BaseModel):
    email: str

class AuthVerify(BaseModel):
    email: str
    code: str

class AuthRefresh(BaseModel):
    refreshToken: str

# Email+Password
class AuthRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: Optional[str] = Field(None, max_length=80)

class AuthLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class MeUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=80)
    age: Optional[int] = Field(None, ge=13, le=120)
    bio: Optional[str] = Field(None, max_length=500)
    skillsTeach: Optional[List[str]] = None
    skillsLearn: Optional[List[str]] = None
    photos: Optional[List[str]] = None
    locationCity: Optional[str] = Field(None, max_length=80)

class SettingsUpdate(BaseModel):
    distanceKm: Optional[int] = Field(None, ge=1, le=200)
    ageRange: Optional[List[int]] = None  # [min,max]
    visibility: Optional[Literal["public", "private"]] = "public"
    timezone: Optional[str] = "Asia/Jerusalem"
    notifications: Optional[bool] = True
    # GeoJSON Point
    location: Optional[Dict[str, Any]] = None

    @validator("ageRange")
    def _check_age_range(cls, v):
        if v is None:
            return v
        if not isinstance(v, list) or len(v) != 2:
            raise ValueError("ageRange must be [min,max]")
        lo, hi = int(v[0]), int(v[1])
        if lo < 13 or hi > 120 or lo > hi:
            raise ValueError("invalid ageRange bounds")
        return [lo, hi]

class SwipePayload(BaseModel):
    targetUserId: str
    action: Literal["like", "pass"] = "like"

class MessageCreate(BaseModel):
    text: Optional[str] = ""
    imageUrl: Optional[str] = None
    clientSessionId: Optional[str] = None

class SessionCreate(BaseModel):
    matchId: str
    startAt: datetime
    durationMin: Optional[int] = None
    endAt: Optional[datetime] = None
    locationType: Literal["online", "in_person"]
    locationValue: str
    creditValue: Optional[int] = None
    teacherId: Optional[str] = None
    learnerId: Optional[str] = None

class SessionUpdate(BaseModel):
    status: Literal["confirmed", "cancelled"]

class RatingCreate(BaseModel):
    sessionId: str
    stars: int
    comment: Optional[str] = ""
    teachingQuality: Optional[int] = Field(None, ge=1, le=5)
    communication: Optional[int] = Field(None, ge=1, le=5)
    punctuality: Optional[int] = Field(None, ge=1, le=5)
    overallExperience: Optional[int] = Field(None, ge=1, le=5)
    skillRated: Optional[str] = None
    reviewText: Optional[str] = Field(None, max_length=500)

# -----------------------------------------------------------------------------
# INDEXES
# -----------------------------------------------------------------------------
async def ensure_indexes():
    await db.users.create_index("deviceId", name="deviceId_idx")
    await db.users.create_index("email", unique=True, sparse=True, name="email_unique_idx")

    await db.settings.create_index("userId", name="userId_idx")
    try:
        await db.settings.create_index([("location", "2dsphere")], name="settings_location_2dsphere")
    except Exception:
        pass

    await db.swipes.create_index([("userId", 1), ("targetUserId", 1)], name="swipe_pair_idx")

    await db.matches.create_index("usersKey", unique=True, name="usersKey_unique")
    await db.matches.create_index([("users", 1), ("lastMessageAt", -1)], name="matches_user_last_idx")

    await db.messages.create_index([("matchId", 1), ("ts", -1)], name="messages_match_ts_idx")
    await db.messages.create_index(
        [("matchId", 1), ("senderId", 1), ("clientSessionId", 1)],
        name="msg_idem_idx", unique=True, sparse=True
    )

    await db.auth_codes.create_index("expiresAt", expireAfterSeconds=0, name="authcode_ttl")
    await db.auth_codes.create_index([("email", 1), ("windowHour", 1)], name="authcode_hour_idx")

    await db.sessions.create_index([("matchId", 1), ("status", 1)], name="sessions_match_status_idx")
    await db.sessions.create_index([("participants", 1), ("startAt", 1)], name="sessions_participant_start_idx")

    await db.ratings.create_index([("sessionId", 1), ("raterId", 1)], unique=True, name="rating_unique_idx")
    await db.ratings.create_index("rateeId", name="ratings_ratee_idx")

    await db.idempotency.create_index([("key", 1), ("userId", 1)], unique=True, name="idem_key_user_unique")
    await db.idempotency.create_index("expiresAt", expireAfterSeconds=0, name="idem_ttl")

    # Credit transactions indexes
    await db.credit_transactions.create_index([("userId", 1), ("createdAt", -1)], name="credit_trans_user_ts_idx")
    await db.credit_transactions.create_index("sessionId", name="credit_trans_session_idx")

# -----------------------------------------------------------------------------
# UTILS (idempotency, ics, time, moderation, export)
# -----------------------------------------------------------------------------
async def check_idempotency(key: Optional[str], user_id: str):
    if not key:
        return None
    return await db.idempotency.find_one({"key": key, "userId": user_id})

async def save_idempotency(key: Optional[str], user_id: str, payload: Dict[str, Any]):
    if not key:
        return
    try:
        await db.idempotency.insert_one({
            "_id": str(uuid.uuid4()),
            "key": key,
            "userId": user_id,
            "payload": payload,
            "createdAt": datetime.utcnow(),
            "expiresAt": datetime.utcnow() + timedelta(hours=24),
        })
    except Exception:
        pass

_DEF_CRLF = "\r\n"

def _escape_ics(text: str) -> str:
    if text is None:
        return ""
    return text.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")

def _fold_lines(s: str, limit: int = 75) -> str:
    out = []
    for line in s.split("\n"):
        b = line.encode("utf-8")
        if len(b) <= limit:
            out.append(line)
        else:
            start = 0
            while start < len(b):
                chunk = b[start:start+limit]
                out.append(chunk.decode("utf-8", errors="ignore") if start == 0 else " " + chunk.decode("utf-8", errors="ignore"))
                start += limit
    return _DEF_CRLF.join(out)

def _now_utc():
    return datetime.utcnow()

def to_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# --- Modération messages (mini) ---
BANNED_MSG_WORDS = {"insulte1", "insulte2", "con"}

def _contains_banned(text: str) -> bool:
    if not text:
        return False
    t = text.casefold()
    return any(b in t for b in BANNED_MSG_WORDS)

# --- Export JSON default encoder ---
def _iso(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

# -----------------------------------------------------------------------------
# AUTH HELPERS (JWT + OTP + PASSWORD)
# -----------------------------------------------------------------------------
CODE_TTL_MIN = 10
MAX_CODES_PER_HOUR = 5
PWD_MIN_LEN = 8

def mask_email(e: str) -> str:
    try:
        name, dom = e.split("@")
        return name[0] + "***@" + dom
    except Exception:
        return e

def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def create_token(user_id: str, kind: str = "access", exp_days: Optional[int] = None) -> str:
    assert kind in ("access", "refresh")
    if exp_days is None:
        exp_days = JWT_EXPIRES_DAYS if kind == "access" else REFRESH_EXPIRES_DAYS
    payload = {
        "sub": user_id,
        "typ": kind,
        "iat": int(_now_utc().timestamp()),
        "exp": int((_now_utc() + timedelta(days=exp_days)).timestamp()),
        "jti": secrets.token_hex(12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except JWTError as e:
        raise HTTPException(status_code=401, detail="invalid_token") from e

# ---- Password hashing with stdlib scrypt ----
def hash_password(password: str) -> Dict[str, str]:
    if not isinstance(password, str) or len(password) < PWD_MIN_LEN:
        raise HTTPException(status_code=400, detail="password_too_short")
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return {
        "passwordAlgo": "scrypt",
        "passwordSalt": base64.b64encode(salt).decode("ascii"),
        "passwordHash": base64.b64encode(dk).decode("ascii"),
    }

def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

async def get_or_create_user_by_email(email: str) -> dict:
    u = await db.users.find_one({"email": email})
    if u:
        return u
    new_id = str(uuid.uuid4())
    doc = {
        "_id": new_id,
        "email": email,
        "createdAt": _now_utc(),
        "name": email.split("@")[0].capitalize(),
        "skillsTeach": [],
        "skillsLearn": [],
        "photos": [],
        "avgRating": 0.0,
        "ratingsCount": 0,
        "creditBalance": 100,
        "creditEarned": 0,
        "creditSpent": 0,
    }
    await db.users.insert_one(doc)
    return doc

async def send_email_code(email: str, code: str):
    # Pas de code en clair en prod
    if IS_PROD:
        logger.info("[AUTH] Code envoyé à %s", mask_email(email))
    else:
        logger.info("[AUTH] Code pour %s: %s", mask_email(email), code)

    if SENDGRID_API_KEY and FROM_EMAIL:
        try:
            import requests  # lazy import
            requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"},
                json={
                    "personalizations": [{"to": [{"email": email}]}],
                    "from": {"email": FROM_EMAIL},
                    "subject": "Votre code SkillSwap",
                    "content": [{"type": "text/plain", "value": f"Code valable {CODE_TTL_MIN} min: {code}"}],
                },
                timeout=7,
            )
        except Exception:
            logger.warning("SendGrid error")  # pas de PII

# -----------------------------------------------------------------------------
# AUTH DEPENDENCY
# -----------------------------------------------------------------------------
async def auth_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
        payload = decode_token(token)
        if payload.get("typ") != "access":
            raise HTTPException(status_code=401, detail="invalid_token_type")
        uid = payload.get("sub")
        if not uid:
            raise HTTPException(status_code=401, detail="invalid_sub")
        u = await db.users.find_one({"_id": uid})
        if not u or u.get("isDeleted"):
            raise HTTPException(status_code=401, detail="user_not_found")

        class U: ...
        out = U()
        out.id = u["_id"]
        out.email = u.get("email")
        return out

    if AUTH_LITE_DEBUG:
        device_id = request.headers.get("X-Device-Id")
        if not device_id:
            raise HTTPException(status_code=401, detail="missing_auth")
        u = await db.users.find_one({"deviceId": device_id})
        if not u:
            new_id = str(uuid.uuid4())
            doc = {
                "_id": new_id,
                "deviceId": device_id,
                "createdAt": _now_utc(),
                "name": f"web-{device_id[-4:]}",
                "skillsTeach": [],
                "skillsLearn": [],
                "photos": [],
                "avgRating": 0.0,
                "ratingsCount": 0,
                "creditBalance": 100,
                "creditEarned": 0,
                "creditSpent": 0,
            }
            await db.users.insert_one(doc)
            u = doc

        class U: ...
        out = U()
        out.id = u["_id"]
        out.email = u.get("email")
        return out

    raise HTTPException(status_code=401, detail="missing_bearer")

# -----------------------------------------------------------------------------
# SERIALIZERS
# -----------------------------------------------------------------------------
def to_user(u: dict) -> dict:
    if not u:
        return {}
    return {
        "id": u["_id"],
        "email": u.get("email"),
        "name": u.get("name"),
        "age": u.get("age"),
        "bio": u.get("bio"),
        "skillsTeach": u.get("skillsTeach", []),
        "skillsLearn": u.get("skillsLearn", []),
        "photos": u.get("photos", []),
        "avgRating": round(float(u.get("avgRating", 0.0)), 2),
        "ratingsCount": int(u.get("ratingsCount", 0)),
        "locationCity": u.get("locationCity"),
        "creditBalance": int(u.get("creditBalance", 100)),
        "creditEarned": int(u.get("creditEarned", 0)),
        "creditSpent": int(u.get("creditSpent", 0)),
    }

def to_settings(s: dict) -> dict:
    s = s or {}
    return {
        "distanceKm": s.get("distanceKm", 25),
        "ageRange": s.get("ageRange", [18, 99]),
        "visibility": s.get("visibility", "public"),
        "timezone": s.get("timezone", "Asia/Jerusalem"),
        "notifications": bool(s.get("notifications", True)),
        "location": s.get("location"),
    }

async def session_to_model(doc: dict) -> dict:
    return {
        "id": doc["_id"],
        "matchId": doc["matchId"],
        "participants": doc.get("participants", []),
        "proposedBy": doc.get("proposedBy"),
        "startAt": to_aware_utc(doc["startAt"]).isoformat(),
        "endAt": to_aware_utc(doc["endAt"]).isoformat(),
        "locationType": doc.get("locationType"),
        "locationValue": doc.get("locationValue"),
        "status": doc.get("status"),
        "creditValue": doc.get("creditValue"),
        "teacherId": doc.get("teacherId"),
        "learnerId": doc.get("learnerId"),
        "creditsProcessed": doc.get("creditsProcessed", False),
        "createdAt": doc.get("createdAt").isoformat() if doc.get("createdAt") else None,
        "updatedAt": doc.get("updatedAt").isoformat() if doc.get("updatedAt") else None,
    }

# -----------------------------------------------------------------------------
# SIMPLE UTILS
# -----------------------------------------------------------------------------
def jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set([x.lower() for x in a or []]), set([x.lower() for x in b or []])
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb) or 1
    return inter / union

# -----------------------------------------------------------------------------
# ROUTES: HEALTH & AUTH (OTP + Password)
# -----------------------------------------------------------------------------
@api.get("/")
async def root_ping():
    return {"ok": True, "ts": _now_utc().isoformat(), "mode": "debug" if AUTH_LITE_DEBUG else "jwt"}

@api.get("/healthz")
async def health():
    return {"status": "ok", "time": _now_utc().isoformat()}

# ---------- OTP (email code) ----------
@api.post("/auth/request-code")
@rate_limit(10, 300)  # 10 req / 5 min / IP (en plus de MAX_CODES_PER_HOUR)
async def auth_request_code(payload: AuthRequest, request: Request):
    email = (payload.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="invalid_email")

    window = _now_utc().replace(minute=0, second=0, microsecond=0)
    count = await db.auth_codes.count_documents({"email": email, "windowHour": window})
    if count >= MAX_CODES_PER_HOUR:
        raise HTTPException(status_code=429, detail="rate_limited")

    code = f"{secrets.randbelow(10**6):06d}"
    doc = {
        "_id": str(uuid.uuid4()),
        "email": email,
        "codeHash": hash_code(code),
        "expiresAt": _now_utc() + timedelta(minutes=CODE_TTL_MIN),
        "windowHour": window,
        "ip": request.client.host if request.client else None,
        "used": False,
        "createdAt": _now_utc(),
    }
    await db.auth_codes.insert_one(doc)
    await send_email_code(email, code)
    return {"sent": True, "to": mask_email(email)}

@api.post("/auth/verify-code")
@rate_limit(60, 300)  # micro RL IP: 60/5min
async def auth_verify_code(payload: AuthVerify):
    email = (payload.email or "").strip().lower()
    code = (payload.code or "").strip()
    if not email or "@" not in email or not code.isdigit() or len(code) != 6:
        raise HTTPException(status_code=400, detail="invalid_input")

    rec = await db.auth_codes.find_one(
        {"email": email, "codeHash": hash_code(code), "used": False, "expiresAt": {"$gt": _now_utc()}},
        sort=[("createdAt", -1)],
    )
    if not rec:
        raise HTTPException(status_code=400, detail="invalid_or_expired_code")

    await db.auth_codes.update_one({"_id": rec["_id"]}, {"$set": {"used": True, "usedAt": _now_utc()}})
    user = await get_or_create_user_by_email(email)

    access = create_token(user["_id"], kind="access", exp_days=JWT_EXPIRES_DAYS)
    refresh = create_token(user["_id"], kind="refresh", exp_days=REFRESH_EXPIRES_DAYS)
    return {"accessToken": access, "refreshToken": refresh, "user": {"id": user["_id"], "email": user.get("email")}}

# ---------- Password (register/login) ----------
@api.post("/auth/register")
@rate_limit(10, 300)
async def auth_register(payload: AuthRegister, request: Request):
    email = payload.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing and existing.get("isDeleted"):
        raise HTTPException(status_code=403, detail="account_deleted")
    if existing and existing.get("passwordHash"):
        raise HTTPException(status_code=409, detail="email_exists")

    creds = hash_password(payload.password)
    if existing:
        await db.users.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "passwordAlgo": creds["passwordAlgo"],
                "passwordSalt": creds["passwordSalt"],
                "passwordHash": creds["passwordHash"],
                "name": existing.get("name") or (payload.name or email.split("@")[0].capitalize()),
            }}
        )
        user = await db.users.find_one({"_id": existing["_id"]})
    else:
        user = {
            "_id": str(uuid.uuid4()),
            "email": email,
            "createdAt": _now_utc(),
            "name": payload.name or email.split("@")[0].capitalize(),
            "skillsTeach": [],
            "skillsLearn": [],
            "photos": [],
            "avgRating": 0.0,
            "ratingsCount": 0,
            "creditBalance": 100,
            "creditEarned": 0,
            "creditSpent": 0,
            **creds,
        }
        await db.users.insert_one(user)
        await db.settings.insert_one({"userId": user["_id"], "distanceKm": 25, "ageRange": [18, 99], "visibility": "public", "notifications": True})

    access = create_token(user["_id"], kind="access")
    refresh = create_token(user["_id"], kind="refresh")
    return {"accessToken": access, "refreshToken": refresh, "user": {"id": user["_id"], "email": user.get("email")}}

@api.post("/auth/login")
@rate_limit(30, 300)
async def auth_login(payload: AuthLogin, request: Request):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or user.get("isDeleted"):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    if not user.get("passwordHash") or not user.get("passwordSalt"):
        raise HTTPException(status_code=401, detail="invalid_credentials")
    ok = verify_password(payload.password, user["passwordSalt"], user["passwordHash"])
    if not ok:
        raise HTTPException(status_code=401, detail="invalid_credentials")
    access = create_token(user["_id"], kind="access")
    refresh = create_token(user["_id"], kind="refresh")
    return {"accessToken": access, "refreshToken": refresh, "user": {"id": user["_id"], "email": user.get("email")}}

@api.post("/auth/refresh")
@rate_limit(120, 300)  # 120/5min
async def auth_refresh(payload: AuthRefresh):
    rt = (payload.refreshToken or "").strip()
    if not rt:
        raise HTTPException(status_code=400, detail="missing_refresh")
    data = decode_token(rt)
    if data.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="invalid_token_type")
    uid = data.get("sub")
    u = await db.users.find_one({"_id": uid})
    if not u or u.get("isDeleted"):
        raise HTTPException(status_code=401, detail="user_not_found")
    access = create_token(uid, kind="access", exp_days=JWT_EXPIRES_DAYS)
    new_refresh = create_token(uid, kind="refresh", exp_days=REFRESH_EXPIRES_DAYS)
    return {"accessToken": access, "refreshToken": new_refresh}

# -----------------------------------------------------------------------------
# ROUTES: ME
# -----------------------------------------------------------------------------
@api.get("/me")
async def get_me(user=Depends(auth_user)):
    u = await db.users.find_one({"_id": user.id})
    s = await db.settings.find_one({"userId": user.id})
    return {"user": to_user(u), "settings": to_settings(s)}

@api.put("/me")
async def update_me(payload: MeUpdate, user=Depends(auth_user)):
    upd = {k: v for k, v in payload.dict(exclude_none=True).items()}

    def norm_list(xs):
        return [x.strip() for x in xs or [] if x and x.strip()]

    if "skillsTeach" in upd:
        upd["skillsTeach"] = list(dict.fromkeys(norm_list(upd["skillsTeach"])))[:20]
    if "skillsLearn" in upd:
        upd["skillsLearn"] = list(dict.fromkeys(norm_list(upd["skillsLearn"])))[:20]

    if "photos" in upd:
        photos = norm_list(upd["photos"])[:6]
        for uurl in photos:
            if not str(uurl).startswith("https://"):
                raise HTTPException(status_code=400, detail="photo_url_must_be_https")
        upd["photos"] = photos

    if "bio" in upd and upd["bio"] and len(upd["bio"]) > 500:
        raise HTTPException(status_code=400, detail="bio_too_long")

    # Check profile completeness before update
    old_user = await db.users.find_one({"_id": user.id})
    was_complete = (
        old_user.get("name") and
        old_user.get("age") and
        old_user.get("bio") and
        len(old_user.get("skillsTeach", [])) > 0 and
        len(old_user.get("skillsLearn", [])) > 0 and
        len(old_user.get("photos", [])) > 0
    )
    
    await db.users.update_one({"_id": user.id}, {"$set": upd})
    u = await db.users.find_one({"_id": user.id})
    
    # Check if profile is now complete and award bonus
    is_complete = (
        u.get("name") and
        u.get("age") and
        u.get("bio") and
        len(u.get("skillsTeach", [])) > 0 and
        len(u.get("skillsLearn", [])) > 0 and
        len(u.get("photos", [])) > 0
    )
    
    # Award profile completion bonus (one time only)
    if not was_complete and is_complete:
        bonus = 20
        await db.users.update_one(
            {"_id": user.id},
            {"$inc": {"creditBalance": bonus, "creditEarned": bonus}}
        )
        await db.credit_transactions.insert_one({
            "_id": str(uuid.uuid4()),
            "userId": user.id,
            "fromUserId": None,
            "toUserId": user.id,
            "amount": bonus,
            "type": "bonus",
            "reason": "Profile completion bonus",
            "balanceAfter": u.get("creditBalance", 100) + bonus,
            "createdAt": _now_utc(),
        })
        # Refresh user data to include new balance
        u = await db.users.find_one({"_id": user.id})
    
    return {"user": to_user(u)}

@api.put("/me/settings")
async def update_settings(payload: SettingsUpdate, user=Depends(auth_user)):
    s = payload.dict(exclude_none=True)

    if "distanceKm" in s:
        d = int(s["distanceKm"])
        if d < 1 or d > 200:
            raise HTTPException(status_code=400, detail="distance_out_of_range")

    if "ageRange" in s:
        a = s["ageRange"]
        if not isinstance(a, list) or len(a) != 2:
            raise HTTPException(status_code=400, detail="age_range_invalid")
        lo, hi = int(a[0]), int(a[1])
        if lo < 13 or hi > 120 or lo > hi:
            raise HTTPException(status_code=400, detail="age_range_bounds")
        s["ageRange"] = [lo, hi]

    if "location" in s and s["location"]:
        loc = s["location"]
        if loc.get("type") != "Point" or not isinstance(loc.get("coordinates"), list) or len(loc["coordinates"]) != 2:
            raise HTTPException(status_code=400, detail="invalid_location")
        try:
            lon, lat = float(loc["coordinates"][0]), float(loc["coordinates"][1])
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_location")
        if not (-180 <= lon <= 180 and -90 <= lat <= 90):
            raise HTTPException(status_code=400, detail="invalid_location_bounds")
        s["location"] = {"type": "Point", "coordinates": [lon, lat]}

    await db.settings.update_one({"userId": user.id}, {"$set": {"userId": user.id, **s}}, upsert=True)
    sdoc = await db.settings.find_one({"userId": user.id})
    return {"settings": to_settings(sdoc)}

@api.get("/me/export")
async def export_me(user=Depends(auth_user)):
    """
    Export RGPD complet : profil, settings, swipes (par moi & vers moi), matches, messages envoyés,
    sessions (toutes où je participe), ratings (donnés & reçus). Renvoie un JSON téléchargeable.
    """
    uid = user.id

    u = await db.users.find_one({"_id": uid}) or {}
    s = await db.settings.find_one({"userId": uid}) or {}

    swipes_mine = [doc async for doc in db.swipes.find({"userId": uid}).sort("ts", 1)]
    swipes_towards_me = [doc async for doc in db.swipes.find({"targetUserId": uid}).sort("ts", 1)]
    matches = [m async for m in db.matches.find({"users": {"$in": [uid]}}).sort("createdAt", 1)]
    my_messages = [m async for m in db.messages.find({"senderId": uid}).sort("ts", 1)]
    sessions = [sdoc async for sdoc in db.sessions.find({"participants": {"$in": [uid]}}).sort("startAt", 1)]
    ratings_given = [r async for r in db.ratings.find({"raterId": uid}).sort("createdAt", 1)]
    ratings_received = [r async for r in db.ratings.find({"rateeId": uid}).sort("createdAt", 1)]

    payload = {
        "exportedAt": _now_utc().isoformat(),
        "user": to_user(u),
        "settings": to_settings(s),
        "swipes": {"byMe": swipes_mine, "towardsMe": swipes_towards_me},
        "matches": matches,
        "messages": {"sentByMe": my_messages},
        "sessions": sessions,
        "ratings": {"given": ratings_given, "received": ratings_received},
    }

    return JSONResponse(
        content=json.loads(json.dumps(payload, default=_iso)),
        headers={"Content-Disposition": f'attachment; filename="skillswap_export_{uid}.json"'}
    )

@api.delete("/me")
async def delete_me(user=Depends(auth_user)):
    """
    RGPD suppression/anonymisation (MVP):
    - Anonymiser mes messages envoyés : content -> "[deleted]", imageUrl -> None
    - Annuler mes sessions FUTURES (proposed/confirmed, startAt > now)
    - Supprimer mes ratings (raterId==me OU rateeId==me)
    - Supprimer mes swipes envers/vers moi + settings + auth codes (optionnel)
    - Laisser les matches (pour l'autre) mais 'tombstone' mon user => compte inutilisable
    """
    uid = user.id
    now = _now_utc()

    # Récupérer l'email AVANT anonymisation pour nettoyer ses codes OTP
    me_doc = await db.users.find_one({"_id": uid}) or {}
    my_email = me_doc.get("email")

    await db.messages.update_many({"senderId": uid}, {"$set": {"content": "[deleted]", "imageUrl": None}})

    await db.sessions.update_many(
        {"participants": {"$in": [uid]}, "startAt": {"$gt": now}, "status": {"$in": ["proposed", "confirmed"]}},
        {"$set": {"status": "cancelled", "updatedAt": now}}
    )

    await db.ratings.delete_many({"$or": [{"raterId": uid}, {"rateeId": uid}]})
    await db.swipes.delete_many({"$or": [{"userId": uid}, {"targetUserId": uid}]})
    if my_email:
        await db.auth_codes.delete_many({"email": my_email})
    await db.settings.delete_many({"userId": uid})

    await db.users.update_one(
        {"_id": uid},
        {"$set": {
            "isDeleted": True,
            "deletedAt": now,
            "email": None,
            "name": "[deleted]",
            "bio": None,
            "photos": [],
            "skillsTeach": [],
            "skillsLearn": [],
            "passwordHash": None,
            "passwordSalt": None,
            "passwordAlgo": None,
        }}
    )

    return {"deleted": True}

# -----------------------------------------------------------------------------
# ROUTES: CANDIDATES (utilise préférences basiques)
# -----------------------------------------------------------------------------
@api.get("/candidates")
async def candidates(cursor: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=50), user=Depends(auth_user)):
    swiped = await db.swipes.distinct("targetUserId", {"userId": user.id})

    s = await db.settings.find_one({"userId": user.id}) or {}
    age_rng = s.get("ageRange", [18, 99])
    q = {
        "_id": {"$ne": user.id, "$nin": swiped},
        "$or": [{"age": {"$exists": False}}, {"age": {"$gte": age_rng[0], "$lte": age_rng[1]}}],
    }

    cur = db.users.find(q).skip(cursor).limit(limit)

    out = []
    async for u in cur:
        out.append({
            "id": u["_id"],
            "name": u.get("name"),
            "age": u.get("age"),
            "bio": u.get("bio"),
            "skillsTeach": u.get("skillsTeach", []),
            "skillsLearn": u.get("skillsLearn", []),
            "photos": u.get("photos", []),
            "distanceKm": 5,
            "score": round(0.5 + 0.5 * jaccard(u.get("skillsTeach", []), u.get("skillsLearn", [])), 2),
        })
    return {"candidates": out, "nextCursor": cursor + len(out)}

# -----------------------------------------------------------------------------
# ROUTES: SWIPE / MATCH
# -----------------------------------------------------------------------------
@api.post("/swipe")
async def swipe(payload: SwipePayload, user=Depends(auth_user), idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    rec = await check_idempotency(idempotency_key, user.id)
    if rec and rec.get("payload", {}).get("swipeId"):
        sid = rec["payload"]["swipeId"]
        old = await db.swipes.find_one({"_id": sid})
        if old:
            mat = await db.matches.find_one({"usersKey": "|".join(sorted([user.id, payload.targetUserId]))})
            return {"ok": True, "matched": bool(mat)}

    doc = {"_id": str(uuid.uuid4()), "userId": user.id, "targetUserId": payload.targetUserId, "action": payload.action, "ts": _now_utc()}
    await db.swipes.insert_one(doc)

    matched = False
    if payload.action == "like":
        other_like = await db.swipes.find_one({"userId": payload.targetUserId, "targetUserId": user.id, "action": "like"})
        if other_like:
            users_sorted = sorted([user.id, payload.targetUserId])
            users_key = "|".join(users_sorted)
            existing = await db.matches.find_one({"usersKey": users_key})
            if not existing:
                mdoc = {"_id": str(uuid.uuid4()), "users": users_sorted, "usersKey": users_key, "createdAt": _now_utc(), "lastMessageAt": _now_utc(), "lastMessage": None}
                await db.matches.insert_one(mdoc)
            matched = True

    await save_idempotency(idempotency_key, user.id, {"swipeId": doc["_id"]})
    return {"ok": True, "matched": matched}

@api.get("/matches")
async def list_matches(user=Depends(auth_user)):
    cur = db.matches.find({"users": {"$in": [user.id]}}).sort("lastMessageAt", -1)
    out = []
    async for m in cur:
        other_id = [u for u in m["users"] if u != user.id]
        other_id = other_id[0] if other_id else None
        other = await db.users.find_one({"_id": other_id}) if other_id else None
        other_payload = to_user(other) if other else {"id": other_id, "name": "Compte supprimé", "photos": []}
        out.append({
            "id": m["_id"],
            "users": m.get("users", []),
            "user": other_payload,
            "lastMessage": m.get("lastMessage"),
            "lastMessageAt": m.get("lastMessageAt").isoformat() if m.get("lastMessageAt") else None,
        })
    return {"matches": out}

# -----------------------------------------------------------------------------
# ROUTES: MESSAGES (post-match only, modération, pagination, idempotence)
# -----------------------------------------------------------------------------
@api.get("/matches/{match_id}/messages")
async def get_messages(match_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), user=Depends(auth_user)):
    m = await db.matches.find_one({"_id": match_id, "users": {"$in": [user.id]}})
    if not m:
        raise HTTPException(status_code=404, detail="match_not_found")

    total = await db.messages.count_documents({"matchId": match_id})
    cur = db.messages.find({"matchId": match_id}).sort("ts", 1).skip(cursor).limit(limit)

    items = []
    async for d in cur:
        items.append({"id": d["_id"], "senderId": d["senderId"], "content": d.get("content"), "imageUrl": d.get("imageUrl"), "ts": d["ts"].isoformat()})

    next_cursor = cursor + len(items)
    has_more = next_cursor < total
    return {"messages": items, "nextCursor": next_cursor, "hasMore": has_more, "total": total}

@api.post("/matches/{match_id}/messages")
async def post_message(match_id: str, payload: MessageCreate, user=Depends(auth_user)):
    m = await db.matches.find_one({"_id": match_id, "users": {"$in": [user.id]}})
    if not m:
        raise HTTPException(status_code=404, detail="match_not_found")

    text = (payload.text or "").strip()
    if not text and not payload.imageUrl:
        raise HTTPException(status_code=400, detail="empty_message")

    if text and len(text) > 2000:
        raise HTTPException(status_code=400, detail="message_too_long")
    if _contains_banned(text):
        raise HTTPException(status_code=400, detail="message_blocked")

    window = datetime.utcnow() - timedelta(seconds=60)
    recent = await db.messages.count_documents({"matchId": match_id, "senderId": user.id, "ts": {"$gte": window}})
    if recent >= 30:
        raise HTTPException(status_code=429, detail="rate_limited")

    mid = str(uuid.uuid4())
    doc = {
        "_id": mid,
        "matchId": match_id,
        "senderId": user.id,
        "content": text,
        "imageUrl": payload.imageUrl,
        "clientSessionId": payload.clientSessionId or None,
        "ts": datetime.utcnow(),
    }
    try:
        await db.messages.insert_one(doc)
    except Exception:
        if payload.clientSessionId:
            old = await db.messages.find_one({"matchId": match_id, "senderId": user.id, "clientSessionId": payload.clientSessionId})
            if old:
                doc = old
                mid = old["_id"]
        else:
            raise

    await db.matches.update_one(
        {"_id": match_id},
        {"$set": {"lastMessageAt": doc["ts"], "lastMessage": {"text": doc["content"], "imageUrl": doc["imageUrl"]}}},
    )

    return {"message": {"id": mid, "fromUserId": user.id, "text": doc["content"], "imageUrl": doc.get("imageUrl"), "ts": doc["ts"].isoformat()}}

# -----------------------------------------------------------------------------
# ROUTES: SESSIONS
# -----------------------------------------------------------------------------
@api.get("/sessions")
async def list_sessions(matchId: str = Query(...), user=Depends(auth_user)):
    m = await db.matches.find_one({"_id": matchId, "users": {"$in": [user.id]}})
    if not m:
        raise HTTPException(status_code=404, detail="match_not_found")
    cur = db.sessions.find({"matchId": matchId}).sort("startAt", 1)
    out = []
    async for s in cur:
        out.append(await session_to_model(s))
    return {"sessions": out}

@api.post("/sessions", status_code=201)
async def create_session(payload: SessionCreate, user=Depends(auth_user), idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    rec = await check_idempotency(idempotency_key, user.id)
    if rec and rec.get("payload", {}).get("sessionId"):
        sid = rec["payload"]["sessionId"]
        doc = await db.sessions.find_one({"_id": sid})
        if doc:
            return {"session": await session_to_model(doc)}

    now = _now_utc()
    start_at = payload.startAt
    if (start_at - now) < timedelta(minutes=10):
        raise HTTPException(status_code=400, detail="start_too_soon")
    if payload.durationMin and int(payload.durationMin) not in (30, 60, 90):
        raise HTTPException(status_code=400, detail="duration_invalid")
    if payload.locationType == "online":
        if not (payload.locationValue.startswith("https://")):
            raise HTTPException(status_code=400, detail="location_url_https_required")
    else:
        if len(payload.locationValue) > 80:
            raise HTTPException(status_code=400, detail="location_text_too_long")

    match = await db.matches.find_one({"_id": payload.matchId, "users": {"$in": [user.id]}})
    if not match:
        raise HTTPException(status_code=404, detail="match_not_found")
    participants = match.get("users", [])

    end_at = payload.endAt or (payload.startAt + timedelta(minutes=int(payload.durationMin or 60)))
    
    # Calculate credit value if not provided
    credit_value = payload.creditValue
    if credit_value is None:
        duration_hours = (end_at - start_at).total_seconds() / 3600
        credit_value = int(duration_hours * 10)  # 10 credits per hour base rate
    
    # Validate credit value is positive
    if credit_value < 0:
        raise HTTPException(status_code=400, detail="credit_value_must_be_positive")
    
    # Determine teacher and learner
    teacher_id = payload.teacherId or user.id
    learner_id = payload.learnerId
    if not learner_id:
        # If not specified, the other participant is the learner
        learner_id = [p for p in participants if p != teacher_id][0] if len(participants) == 2 else user.id
    
    # Check if learner has enough credits
    if learner_id != user.id:
        learner = await db.users.find_one({"_id": learner_id}, {"creditBalance": 1})
    else:
        learner = await db.users.find_one({"_id": user.id}, {"creditBalance": 1})
    
    if not learner:
        raise HTTPException(status_code=404, detail="learner_not_found")
    
    learner_balance = int(learner.get("creditBalance", 0))
    if learner_balance < credit_value:
        raise HTTPException(status_code=400, detail="insufficient_credits")
    
    doc = {
        "_id": str(uuid.uuid4()),
        "matchId": payload.matchId,
        "participants": participants,
        "startAt": start_at,
        "endAt": end_at,
        "locationType": payload.locationType,
        "locationValue": payload.locationValue,
        "status": "proposed",
        "proposedBy": user.id,
        "creditValue": credit_value,
        "teacherId": teacher_id,
        "learnerId": learner_id,
        "icsPath": None,
        "createdAt": now,
        "updatedAt": now,
    }
    await db.sessions.insert_one(doc)
    await save_idempotency(idempotency_key, user.id, {"sessionId": doc["_id"]})
    return {"session": await session_to_model(doc)}

@api.patch("/sessions/{session_id}")
async def update_session(session_id: str, payload: SessionUpdate, user=Depends(auth_user)):
    doc = await db.sessions.find_one({"_id": session_id, "participants": {"$in": [user.id]}})
    if not doc:
        raise HTTPException(status_code=404, detail="session_not_found")

    if user.id == doc.get("proposedBy") and payload.status in ("confirmed", "cancelled"):
        raise HTTPException(status_code=400, detail="proposer_cannot_decide")

    if payload.status == "confirmed":
        start_at = doc.get("startAt")
        end_at = doc.get("EndAt") or doc.get("endAt")
        if end_at is None:
            end_at = start_at + timedelta(minutes=60)

        overlap_q = {
            "participants": {"$in": [p for p in doc.get("participants", [])]},
            "status": "confirmed",
            "$expr": {"$and": [{"$lt": ["$startAt", end_at]}, {"$gt": ["$EndAt", start_at]}]},
        }
        alt_overlap_q = {
            "participants": {"$in": [p for p in doc.get("participants", [])]},
            "status": "confirmed",
            "$expr": {"$and": [{"$lt": ["$startAt", end_at]}, {"$gt": ["$endAt", start_at]}]},
        }
        exists = await db.sessions.find_one(overlap_q) or await db.sessions.find_one(alt_overlap_q)
        if exists:
            raise HTTPException(status_code=409, detail="overlap")

        res = await db.sessions.update_one(
            {"_id": session_id, "status": "proposed", "participants": {"$in": [user.id]}},
            {"$set": {"status": "confirmed", "updatedAt": _now_utc()}},
        )
        if res.matched_count == 0:
            raise HTTPException(status_code=409, detail="already_updated")
        doc = await db.sessions.find_one({"_id": session_id})
        return {"session": await session_to_model(doc)}

    if payload.status == "cancelled":
        res = await db.sessions.update_one(
            {"_id": session_id, "participants": {"$in": [user.id]}},
            {"$set": {"status": "cancelled", "updatedAt": _now_utc()}},
        )
        if res.matched_count == 0:
            raise HTTPException(status_code=409, detail="already_updated")
        doc = await db.sessions.find_one({"_id": session_id})
        return {"session": await session_to_model(doc)}

    raise HTTPException(status_code=400, detail="invalid_status")

@api.get("/sessions/{session_id}/ics")
async def get_session_ics(session_id: str, user=Depends(auth_user)):
    doc = await db.sessions.find_one({"_id": session_id, "participants": {"$in": [user.id]}})
    if not doc:
        raise HTTPException(status_code=404, detail="session_not_found")
    if doc.get("status") != "confirmed":
        raise HTTPException(status_code=400, detail="session_not_confirmed")

    startZ = to_aware_utc(doc["startAt"]).strftime("%Y%m%dT%H%M%SZ")
    endZ = to_aware_utc(doc["endAt"]).strftime("%Y%m%dT%H%M%SZ")
    nowZ = _now_utc().strftime("%Y%m%dT%H%M%SZ")
    location = _escape_ics(doc.get("locationValue") or "")
    lines = [
        "BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//SkillSwap//MVP//FR","BEGIN:VEVENT",
        f"UID:{doc.get('_id')}@skillswap",f"DTSTAMP:{nowZ}",f"DTSTART:{startZ}",f"DTEND:{endZ}",
        "SUMMARY:SkillSwap session","DESCRIPTION:Session SkillSwap",f"LOCATION:{location}",
        "END:VEVENT","END:VCALENDAR",
    ]
    raw = "\n".join(lines)
    content = _fold_lines(raw).replace("\n", _DEF_CRLF)
    return PlainTextResponse(content, media_type="text/calendar", headers={
        "Content-Disposition": "attachment; filename=skillswap.ics"
    })

# -----------------------------------------------------------------------------
# ROUTES: RATINGS
# -----------------------------------------------------------------------------
@api.get("/ratings/session/{session_id}/my")
async def my_rating_for_session(session_id: str, user=Depends(auth_user)):
    r = await db.ratings.find_one({"sessionId": session_id, "raterId": user.id})
    if not r:
        return {"rated": False}
    return {
        "rated": True,
        "rating": {"id": r["_id"], "stars": r["stars"], "comment": r.get("comment", "")},
    }

@api.post("/ratings", status_code=201)
async def create_rating(
    payload: RatingCreate,
    user=Depends(auth_user),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Idempotence
    rec = await check_idempotency(idempotency_key, user.id)
    if rec and rec.get("payload", {}).get("ratingId"):
        rid = rec["payload"]["ratingId"]
        r = await db.ratings.find_one({"_id": rid})
        if r:
            return {
                "rating": {
                    "id": r["_id"],
                    "sessionId": r["sessionId"],
                    "raterId": r["raterId"],
                    "rateeId": r["rateeId"],
                    "stars": r["stars"],
                    "comment": r.get("comment", ""),
                }
            }

    # Validations
    if payload.stars < 1 or payload.stars > 5:
        raise HTTPException(status_code=400, detail="stars_range")
    if payload.comment and len(payload.comment) > 300:
        raise HTTPException(status_code=400, detail="comment_too_long")

    BANNED_WORDS = {"con", "insulte1", "insulte2"}
    if payload.comment and any(b in payload.comment.casefold() for b in BANNED_WORDS):
        raise HTTPException(status_code=400, detail="comment_blocked")

    # Session éligible
    sess = await db.sessions.find_one({"_id": payload.sessionId, "participants": {"$in": [user.id]}})
    if not sess:
        raise HTTPException(status_code=404, detail="session_not_found")
    if sess.get("status") != "confirmed":
        raise HTTPException(status_code=400, detail="session_not_confirmed")
    if _now_utc() < sess.get("endAt") + timedelta(hours=1):
        raise HTTPException(status_code=400, detail="too_early")

    # Déduire le ratee
    participants = [str(x) for x in sess.get("participants", [])]
    other = [p for p in participants if p != user.id]
    if not other:
        raise HTTPException(status_code=400, detail="ratee_missing")
    ratee_id = other[0]

    # Unicité
    exists = await db.ratings.find_one({"sessionId": payload.sessionId, "raterId": user.id})
    if exists:
        raise HTTPException(status_code=409, detail="already_rated")

    # Créer la note
    rid = str(uuid.uuid4())
    doc = {
        "_id": rid,
        "sessionId": payload.sessionId,
        "raterId": user.id,
        "rateeId": ratee_id,
        "stars": int(payload.stars),
        "comment": payload.comment or "",
        "teachingQuality": payload.teachingQuality,
        "communication": payload.communication,
        "punctuality": payload.punctuality,
        "overallExperience": payload.overallExperience,
        "skillRated": payload.skillRated,
        "reviewText": payload.reviewText,
        "createdAt": _now_utc(),
    }
    await db.ratings.insert_one(doc)

    # Mise à jour atomique de la moyenne et du compteur
    await db.users.update_one(
        {"_id": ratee_id},
        [
            {
                "$set": {
                    "avgRating": {
                        "$divide": [
                            {
                                "$add": [
                                    {
                                        "$multiply": [
                                            {"$ifNull": ["$avgRating", 0]},
                                            {"$ifNull": ["$ratingsCount", 0]},
                                        ]
                                    },
                                    int(payload.stars),
                                ]
                            },
                            {"$add": [{"$ifNull": ["$ratingsCount", 0]}, 1]},
                        ]
                    },
                    "ratingsCount": {"$add": [{"$ifNull": ["$ratingsCount", 0]}, 1]},
                }
            }
        ],
    )

    await save_idempotency(idempotency_key, user.id, {"ratingId": rid})
    
    # Check if session has credit value and both users have rated
    session = await db.sessions.find_one({"_id": payload.sessionId})
    if session and session.get("creditValue") and session.get("teacherId") and session.get("learnerId"):
        # Count ratings for this session
        rating_count = await db.ratings.count_documents({"sessionId": payload.sessionId})
        
        # If both users have now rated, process credit transfer
        if rating_count == 2:
            teacher_id = session["teacherId"]
            learner_id = session["learnerId"]
            credit_value = int(session["creditValue"])
            
            # Transfer credits from learner to teacher
            await db.users.update_one(
                {"_id": learner_id},
                {
                    "$inc": {
                        "creditBalance": -credit_value,
                        "creditSpent": credit_value
                    }
                }
            )
            
            await db.users.update_one(
                {"_id": teacher_id},
                {
                    "$inc": {
                        "creditBalance": credit_value,
                        "creditEarned": credit_value
                    }
                }
            )
            
            # Record transaction
            transaction_id = str(uuid.uuid4())
            learner = await db.users.find_one({"_id": learner_id}, {"creditBalance": 1})
            teacher = await db.users.find_one({"_id": teacher_id}, {"creditBalance": 1})
            
            # Transaction for learner (spending)
            await db.credit_transactions.insert_one({
                "_id": str(uuid.uuid4()),
                "userId": learner_id,
                "fromUserId": learner_id,
                "toUserId": teacher_id,
                "amount": -credit_value,
                "sessionId": payload.sessionId,
                "type": "session_payment",
                "reason": f"Session payment to {session.get('teacherId')}",
                "balanceAfter": learner.get("creditBalance", 0) if learner else 0,
                "createdAt": _now_utc(),
            })
            
            # Transaction for teacher (earning)
            await db.credit_transactions.insert_one({
                "_id": str(uuid.uuid4()),
                "userId": teacher_id,
                "fromUserId": learner_id,
                "toUserId": teacher_id,
                "amount": credit_value,
                "sessionId": payload.sessionId,
                "type": "session_payment",
                "reason": f"Session payment from {session.get('learnerId')}",
                "balanceAfter": teacher.get("creditBalance", 0) if teacher else 0,
                "createdAt": _now_utc(),
            })
            
            # Update session status to indicate credits processed
            await db.sessions.update_one(
                {"_id": payload.sessionId},
                {"$set": {"creditsProcessed": True, "creditsProcessedAt": _now_utc()}}
            )
            
            # Award bonus credits for high ratings
            if int(payload.stars) >= 5:
                await db.users.update_one(
                    {"_id": ratee_id},
                    {"$inc": {"creditBalance": 5, "creditEarned": 5}}
                )
                await db.credit_transactions.insert_one({
                    "_id": str(uuid.uuid4()),
                    "userId": ratee_id,
                    "fromUserId": None,
                    "toUserId": ratee_id,
                    "amount": 5,
                    "sessionId": payload.sessionId,
                    "type": "bonus",
                    "reason": "High rating bonus (5 stars)",
                    "balanceAfter": (teacher.get("creditBalance", 0) if teacher and teacher_id == ratee_id else learner.get("creditBalance", 0)) + 5 if learner or teacher else 5,
                    "createdAt": _now_utc(),
                })
            
            # Award first session bonus (for both teacher and learner)
            for participant_id in [teacher_id, learner_id]:
                # Check if this is their first completed session
                completed_sessions = await db.ratings.count_documents({"rateeId": participant_id})
                if completed_sessions == 1:  # This is their first rating received
                    bonus = 10
                    await db.users.update_one(
                        {"_id": participant_id},
                        {"$inc": {"creditBalance": bonus, "creditEarned": bonus}}
                    )
                    participant = await db.users.find_one({"_id": participant_id}, {"creditBalance": 1})
                    await db.credit_transactions.insert_one({
                        "_id": str(uuid.uuid4()),
                        "userId": participant_id,
                        "fromUserId": None,
                        "toUserId": participant_id,
                        "amount": bonus,
                        "sessionId": payload.sessionId,
                        "type": "bonus",
                        "reason": "First session completion bonus",
                        "balanceAfter": participant.get("creditBalance", 0) if participant else 0,
                        "createdAt": _now_utc(),
                    })
    
    return {
        "rating": {
            "id": rid,
            "sessionId": payload.sessionId,
            "raterId": user.id,
            "rateeId": ratee_id,
            "stars": int(payload.stars),
            "comment": payload.comment or "",
        }
    }

# -----------------------------------------------------------------------------
# ROUTES: CREDITS
# -----------------------------------------------------------------------------
@api.get("/credits/balance")
@rate_limit(100, 60)
async def get_credit_balance(user: Any = Depends(get_current_user)):
    u = await db.users.find_one({"_id": user.id}, {
        "creditBalance": 1,
        "creditEarned": 1,
        "creditSpent": 1
    })
    return {
        "creditBalance": int(u.get("creditBalance", 100)),
        "creditEarned": int(u.get("creditEarned", 0)),
        "creditSpent": int(u.get("creditSpent", 0)),
    }

@api.get("/credits/history")
@rate_limit(100, 60)
async def get_credit_history(
    user: Any = Depends(get_current_user),
    limit: int = Query(30, ge=1, le=100),
    cursor: Optional[str] = None
):
    query = {"userId": user.id}
    
    # Cursor-based pagination
    if cursor:
        try:
            cursor_date = datetime.fromisoformat(cursor)
            query["createdAt"] = {"$lt": cursor_date}
        except Exception:
            pass
    
    transactions = await db.credit_transactions.find(query).sort("createdAt", -1).limit(limit).to_list(length=limit)
    
    result = []
    for tx in transactions:
        result.append({
            "id": tx["_id"],
            "amount": tx["amount"],
            "type": tx["type"],
            "reason": tx.get("reason", ""),
            "sessionId": tx.get("sessionId"),
            "fromUserId": tx.get("fromUserId"),
            "toUserId": tx.get("toUserId"),
            "balanceAfter": tx.get("balanceAfter"),
            "createdAt": tx["createdAt"].isoformat(),
        })
    
    next_cursor = None
    if len(result) == limit and result:
        next_cursor = result[-1]["createdAt"]
    
    return {
        "transactions": result,
        "nextCursor": next_cursor
    }

# -----------------------------------------------------------------------------
# REGISTER ROUTER & MIDDLEWARE
# -----------------------------------------------------------------------------
app.include_router(api)

# CORS strict: refuse '*' en prod, oblige des domaines explicites
raw_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
if IS_PROD:
    if not raw_origins:
        raise RuntimeError("CORS_ORIGINS doit être défini en prod")
    if "*" in raw_origins:
        raise RuntimeError("CORS_ORIGINS ne peut pas contenir '*' en prod")
else:
    raw_origins = raw_origins or ["*"]  # tolérant en dev

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=raw_origins,
    allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type","Idempotency-Key","X-Device-Id"],
    expose_headers=["Content-Disposition"],
    max_age=3600,
)

# -----------------------------------------------------------------------------
# LIFECYCLE
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_seed():
    # Verrou: pas de mode debug device-id en prod
    if IS_PROD and AUTH_LITE_DEBUG:
        raise RuntimeError("AUTH_LITE_DEBUG doit être false en prod")
    await ensure_indexes()
    logger.info("Indexes ensured")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    logger.info("Mongo client closed")
