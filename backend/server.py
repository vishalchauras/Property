from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
import os
import re
import secrets
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, Field, field_validator

load_dotenv()

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
JWT_SECRET = os.getenv("JWT_SECRET", "local-development-only-secret-change-me")
ACCESS_TOKEN_MINUTES = max(5, int(os.getenv("ACCESS_TOKEN_MINUTES", "60")))
DEV_OTP = os.getenv("DEV_OTP", "123456")
client = AsyncIOMotorClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"), tz_aware=True)
db = client[os.getenv("DB_NAME", "real_estate_mvp")]
api = APIRouter(prefix="/api/v1")


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


def clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            ("id" if key == "_id" else key): clean(item)
            for key, item in value.items()
            if key != "_id" or "id" not in value
        }
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def issue_token(user_id: str) -> str:
    expiry = now() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": user_id, "exp": expiry}, JWT_SECRET, algorithm="HS256")


async def get_current_user(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
        user_id = payload["sub"]
    except (jwt.PyJWTError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    account = await db.users.find_one({"_id": user_id})
    if not account:
        raise HTTPException(status_code=401, detail="User account not found")
    return account


async def get_optional_user(authorization: Optional[str] = Header(default=None)) -> Optional[dict]:
    if not authorization:
        return None
    return await get_current_user(authorization)


def require_roles(*roles: str):
    async def check_role(account: dict = Depends(get_current_user)) -> dict:
        if account.get("role") not in roles and account.get("role") != "admin":
            raise HTTPException(status_code=403, detail="This action is not available for your account")
        return account

    return check_role


async def blocked_user_ids(user_id: str) -> list[str]:
    return [
        entry["target_id"]
        async for entry in db.blocks.find({"user_id": user_id}, {"target_id": 1})
    ]


async def notify(user_id: str, kind: str, message: str, target_id: Optional[str] = None) -> None:
    await db.notifications.insert_one(
        {
            "_id": new_id(),
            "user_id": user_id,
            "type": kind,
            "message": message,
            "target_id": target_id,
            "read": False,
            "created_at": now(),
        }
    )


class Role(str, Enum):
    customer = "customer"
    owner = "owner"
    broker = "broker"


class OTPRequest(BaseModel):
    phone: str = Field(min_length=7, max_length=16)

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"\+?[0-9]{7,15}", value):
            raise ValueError("Enter a valid phone number")
        return value


class OTPVerify(OTPRequest):
    otp: str = Field(min_length=4, max_length=8)
    name: str = Field(default="New User", min_length=1, max_length=80)
    role: Role = Role.customer

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class PropertyInput(BaseModel):
    title: str = Field(min_length=3, max_length=140)
    price: float = Field(gt=0)
    city: str = Field(min_length=2, max_length=100)
    locality: str = Field(min_length=2, max_length=120)
    category: str = Field(default="Apartment", max_length=60)
    listing_type: str = Field(default="Sale", max_length=30)
    bhk: Optional[int] = Field(default=None, ge=0, le=20)
    area_sqft: Optional[float] = Field(default=None, gt=0)
    description: str = Field(default="", max_length=5000)
    image_url: Optional[str] = Field(default=None, max_length=2000)
    verified: Optional[bool] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("title", "city", "locality", "category", "listing_type", mode="before")
    @classmethod
    def trim_required_strings(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("image_url", mode="before")
    @classmethod
    def validate_image_url(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if isinstance(value, str):
            value = value.strip()
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("Image URL must use HTTP or HTTPS")
        return value


class ReelInput(BaseModel):
    title: str = Field(min_length=2, max_length=140)
    media_url: str = Field(min_length=8, max_length=2000)
    caption: str = Field(default="", max_length=2000)
    property_id: Optional[str] = None

    @field_validator("title", "media_url", mode="before")
    @classmethod
    def trim_strings(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("property_id", mode="before")
    @classmethod
    def normalize_property_id(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("media_url")
    @classmethod
    def validate_media_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Media URL must use HTTP or HTTPS")
        return value


class EnquiryInput(BaseModel):
    property_id: str
    message: str = Field(default="", max_length=2000)
    phone: Optional[str] = Field(default=None, max_length=16)


class StatusInput(BaseModel):
    status: str


class RequirementInput(BaseModel):
    city: str = Field(min_length=2, max_length=100)
    locality: Optional[str] = Field(default=None, max_length=120)
    property_type: str = Field(default="Apartment", max_length=60)
    budget: Optional[float] = Field(default=None, gt=0)
    bhk: Optional[int] = Field(default=None, ge=0, le=20)
    listing_type: str = Field(default="Buy", max_length=30)

    @field_validator("city", "locality", "property_type", "listing_type", mode="before")
    @classmethod
    def trim_requirement_strings(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class ReportInput(BaseModel):
    target_type: str = Field(min_length=1, max_length=30)
    target_id: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=1000)

    @field_validator("target_type", "target_id", "reason", mode="before")
    @classmethod
    def trim_report_strings(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class CommentInput(BaseModel):
    text: str = Field(min_length=1, max_length=1000)

    @field_validator("text", mode="before")
    @classmethod
    def trim_comment(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class ProfileInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    bio: str = Field(default="", max_length=500)
    avatar_url: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class AnalyticsInput(BaseModel):
    event: str = Field(min_length=1, max_length=80)
    properties: dict[str, Any] = Field(default_factory=dict, max_length=50)

    @field_validator("event", mode="before")
    @classmethod
    def trim_event(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


async def initialize_database() -> None:
    await db.users.create_index("phone", unique=True)
    await db.otps.create_index("phone", unique=True)
    await db.otps.create_index("expires_at", expireAfterSeconds=0)
    await db.properties.create_index([("created_at", -1)])
    await db.properties.create_index([("city", 1), ("locality", 1), ("price", 1)])
    await db.reels.create_index([("status", 1), ("created_at", -1)])
    unique_targets = {
        "reel_likes": "reel_id",
        "saved_reels": "reel_id",
        "saved_properties": "property_id",
        "follows": "target_id",
        "blocks": "target_id",
    }
    for collection, target_field in unique_targets.items():
        await db[collection].create_index(
            [("user_id", 1), (target_field, 1)],
            unique=True,
        )
    await db.enquiries.create_index([("owner_id", 1), ("created_at", -1)])
    await db.notifications.create_index([("user_id", 1), ("created_at", -1)])
    await db.comments.create_index([("reel_id", 1), ("created_at", 1)])
    await db.requirements.create_index([("user_id", 1), ("created_at", -1)])
    await db.reports.create_index([("status", 1), ("created_at", -1)])
    await db.analytics_events.create_index([("created_at", -1)])
    if os.getenv("SEED_DEMO_DATA", "false").lower() == "true":
        await seed_demo_data()


async def seed_demo_data() -> None:
    if await db.properties.count_documents({}):
        return
    owner_id = "demo-property-owner"
    await db.users.update_one(
        {"_id": owner_id},
        {"$setOnInsert": {"phone": "+919999999999", "name": "PropertyFeed Demo", "role": "owner", "verified": True, "created_at": now()}},
        upsert=True,
    )
    property_id = "demo-property-1"
    await db.properties.update_one(
        {"_id": property_id},
        {"$setOnInsert": {
            "_id": property_id,
            "owner_id": owner_id,
            "title": "Sunlit 3 BHK in Bandra",
            "price": 42500000,
            "city": "Mumbai",
            "locality": "Bandra West",
            "category": "Apartment",
            "listing_type": "Sale",
            "bhk": 3,
            "area_sqft": 1560,
            "description": "A bright, spacious home close to the best of Bandra.",
            "image_url": "https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?w=1200",
            "verified": True,
            "created_at": now(),
        }},
        upsert=True,
    )
    await db.reels.update_one(
        {"_id": "demo-reel-1"},
        {"$setOnInsert": {
            "_id": "demo-reel-1",
            "user_id": owner_id,
            "property_id": property_id,
            "title": "A light-filled Bandra home",
            "caption": "Tour this thoughtfully designed 3 BHK.",
            "media_url": "https://images.unsplash.com/photo-1600607687939-ce8a6c25118c?w=1200",
            "likes": 0,
            "status": "published",
            "created_at": now(),
        }},
        upsert=True,
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    if ENVIRONMENT == "production" and (
        len(JWT_SECRET) < 32 or JWT_SECRET == "local-development-only-secret-change-me"
    ):
        raise RuntimeError("Set JWT_SECRET to a random value of at least 32 characters in production")
    try:
        await initialize_database()
        yield
    finally:
        client.close()


app = FastAPI(title="PropertyFeed API", version="1.0.0", lifespan=lifespan)
configured_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "http://localhost:8081").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
async def health() -> dict:
    await db.command("ping")
    return {"status": "ok"}


@api.post("/auth/request-otp")
async def request_otp(data: OTPRequest) -> dict:
    if ENVIRONMENT != "development":
        raise HTTPException(status_code=503, detail="OTP delivery is not configured for this environment")
    await db.otps.update_one(
        {"phone": data.phone},
        {"$set": {"otp": DEV_OTP, "expires_at": now() + timedelta(minutes=5)}},
        upsert=True,
    )
    return {"message": "Development OTP ready", "development_otp": DEV_OTP}


@api.post("/auth/verify-otp")
async def verify_otp(data: OTPVerify) -> dict:
    record = await db.otps.find_one({"phone": data.phone})
    if not record or not secrets.compare_digest(record["otp"], data.otp) or record["expires_at"] < now():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    await db.otps.delete_one({"_id": record["_id"]})
    account = await db.users.find_one({"phone": data.phone})
    if not account:
        account = {
            "_id": new_id(),
            "phone": data.phone,
            "name": data.name.strip(),
            "role": data.role.value,
            "verified": data.role == Role.customer,
            "bio": "",
            "created_at": now(),
        }
        await db.users.insert_one(account)
    return {
        "access_token": issue_token(account["_id"]),
        "token_type": "bearer",
        "user": clean(account),
    }


@api.get("/me")
async def me(account: dict = Depends(get_current_user)) -> dict:
    return clean(account)


@api.patch("/me")
async def update_me(data: ProfileInput, account: dict = Depends(get_current_user)) -> dict:
    changes = data.model_dump()
    await db.users.update_one({"_id": account["_id"]}, {"$set": changes})
    account.update(changes)
    return clean(account)


@api.get("/properties")
async def list_properties(
    search: Optional[str] = None,
    city: Optional[str] = None,
    locality: Optional[str] = None,
    listing_type: Optional[str] = None,
    category: Optional[str] = None,
    min_price: Optional[float] = Query(default=None, ge=0),
    max_price: Optional[float] = Query(default=None, ge=0),
    bhk: Optional[int] = Query(default=None, ge=0, le=20),
    verified: Optional[bool] = None,
    limit: int = Query(default=30, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    account: Optional[dict] = Depends(get_optional_user),
) -> list[dict]:
    if min_price is not None and max_price is not None and min_price > max_price:
        raise HTTPException(status_code=422, detail="min_price cannot exceed max_price")
    query: dict[str, Any] = {}
    if search and search.strip():
        safe_search = re.escape(search.strip())
        query["$or"] = [
            {key: {"$regex": safe_search, "$options": "i"}}
            for key in ("title", "city", "locality")
        ]
    for key, value in (
        ("city", city),
        ("locality", locality),
        ("listing_type", listing_type),
        ("category", category),
        ("bhk", bhk),
        ("verified", verified),
    ):
        if value is not None:
            query[key] = value
    if account:
        hidden_users = await blocked_user_ids(account["_id"])
        if hidden_users:
            query["owner_id"] = {"$nin": hidden_users}
    if min_price is not None or max_price is not None:
        query["price"] = {}
        if min_price is not None:
            query["price"]["$gte"] = min_price
        if max_price is not None:
            query["price"]["$lte"] = max_price
    results = await db.properties.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [clean(item) for item in results]


@api.post("/properties")
async def create_property(
    data: PropertyInput,
    account: dict = Depends(require_roles("owner", "broker")),
) -> dict:
    values = data.model_dump(exclude={"verified"})
    item = {
        **values,
        "_id": new_id(),
        "owner_id": account["_id"],
        "verified": False,
        "created_at": now(),
    }
    await db.properties.insert_one(item)
    return clean(item)


@api.get("/properties/{property_id}")
async def get_property(
    property_id: str,
    account: Optional[dict] = Depends(get_optional_user),
) -> dict:
    item = await db.properties.find_one({"_id": property_id})
    if not item:
        raise HTTPException(status_code=404, detail="Property not found")
    if account and await db.blocks.find_one({"user_id": account["_id"], "target_id": item["owner_id"]}):
        raise HTTPException(status_code=404, detail="Property not found")
    return clean(item)


@api.post("/properties/{property_id}/save")
async def save_property(property_id: str, account: dict = Depends(get_current_user)) -> dict:
    if not await db.properties.find_one({"_id": property_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Property not found")
    await db.saved_properties.update_one(
        {"user_id": account["_id"], "property_id": property_id},
        {"$setOnInsert": {"created_at": now()}},
        upsert=True,
    )
    return {"saved": True}


@api.delete("/properties/{property_id}/save")
async def unsave_property(property_id: str, account: dict = Depends(get_current_user)) -> dict:
    await db.saved_properties.delete_one({"user_id": account["_id"], "property_id": property_id})
    return {"saved": False}


@api.get("/saved/properties")
async def saved_properties(account: dict = Depends(get_current_user)) -> list[dict]:
    saved = await db.saved_properties.find({"user_id": account["_id"]}).sort("created_at", -1).to_list(100)
    ids = [item["property_id"] for item in saved]
    properties = await db.properties.find({"_id": {"$in": ids}}).to_list(100) if ids else []
    hidden_users = await blocked_user_ids(account["_id"])
    if hidden_users:
        properties = [item for item in properties if item.get("owner_id") not in hidden_users]
    by_id = {item["_id"]: clean(item) for item in properties}
    return [by_id[item_id] for item_id in ids if item_id in by_id]


@api.get("/reels")
async def list_reels(
    limit: int = Query(default=30, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    account: dict = Depends(get_current_user),
) -> list[dict]:
    hidden_users = await blocked_user_ids(account["_id"])
    query: dict[str, Any] = {"status": "published"}
    if hidden_users:
        query["user_id"] = {"$nin": hidden_users}
    result = await db.reels.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    reel_ids = [reel["_id"] for reel in result]
    property_ids = list({reel["property_id"] for reel in result if reel.get("property_id")})
    property_items = await db.properties.find({"_id": {"$in": property_ids}}).to_list(len(property_ids)) if property_ids else []
    property_by_id = {item["_id"]: clean(item) for item in property_items}
    liked_ids = {
        item["reel_id"]
        async for item in db.reel_likes.find({"user_id": account["_id"], "reel_id": {"$in": reel_ids}}, {"reel_id": 1})
    } if reel_ids else set()
    saved_ids = {
        item["reel_id"]
        async for item in db.saved_reels.find({"user_id": account["_id"], "reel_id": {"$in": reel_ids}}, {"reel_id": 1})
    } if reel_ids else set()
    author_ids = list({reel["user_id"] for reel in result})
    followed_ids = {
        item["target_id"]
        async for item in db.follows.find({"user_id": account["_id"], "target_id": {"$in": author_ids}}, {"target_id": 1})
    } if author_ids else set()
    out = []
    for reel in result:
        item = clean(reel)
        if reel.get("property_id"):
            item["property"] = property_by_id.get(reel["property_id"])
        item["liked"] = reel["_id"] in liked_ids
        item["saved"] = reel["_id"] in saved_ids
        item["followed"] = reel["user_id"] in followed_ids
        out.append(item)
    return out


@api.post("/reels")
async def create_reel(data: ReelInput, account: dict = Depends(require_roles("owner", "broker"))) -> dict:
    if data.property_id and not await db.properties.find_one(
        {"_id": data.property_id, "owner_id": account["_id"]}, {"_id": 1}
    ):
        raise HTTPException(status_code=404, detail="Your property was not found")
    item = {
        **data.model_dump(),
        "_id": new_id(),
        "user_id": account["_id"],
        "likes": 0,
        "status": "published",
        "created_at": now(),
    }
    await db.reels.insert_one(item)
    return clean(item)


@api.post("/reels/{reel_id}/like")
async def toggle_reel_like(reel_id: str, account: dict = Depends(get_current_user)) -> dict:
    if not await db.reels.find_one({"_id": reel_id, "status": "published"}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Reel not found")
    key = {"reel_id": reel_id, "user_id": account["_id"]}
    existing = await db.reel_likes.find_one(key)
    if existing:
        await db.reel_likes.delete_one(key)
        liked = False
    else:
        await db.reel_likes.insert_one({**key, "created_at": now()})
        liked = True
    count = await db.reel_likes.count_documents({"reel_id": reel_id})
    await db.reels.update_one({"_id": reel_id}, {"$set": {"likes": count}})
    return {"liked": liked, "count": count}


@api.post("/reels/{reel_id}/save")
async def save_reel(reel_id: str, account: dict = Depends(get_current_user)) -> dict:
    if not await db.reels.find_one({"_id": reel_id, "status": "published"}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="Reel not found")
    await db.saved_reels.update_one(
        {"reel_id": reel_id, "user_id": account["_id"]},
        {"$setOnInsert": {"created_at": now()}},
        upsert=True,
    )
    return {"saved": True}


@api.delete("/reels/{reel_id}/save")
async def unsave_reel(reel_id: str, account: dict = Depends(get_current_user)) -> dict:
    await db.saved_reels.delete_one({"reel_id": reel_id, "user_id": account["_id"]})
    return {"saved": False}


@api.get("/saved/reels")
async def saved_reels(account: dict = Depends(get_current_user)) -> list[dict]:
    saved = await db.saved_reels.find({"user_id": account["_id"]}).sort("created_at", -1).to_list(100)
    ids = [item["reel_id"] for item in saved]
    reels = await db.reels.find({"_id": {"$in": ids}, "status": "published"}).to_list(100) if ids else []
    hidden_users = await blocked_user_ids(account["_id"])
    if hidden_users:
        reels = [item for item in reels if item.get("user_id") not in hidden_users]
    by_id = {item["_id"]: clean(item) for item in reels}
    return [by_id[item_id] for item_id in ids if item_id in by_id]


@api.get("/reels/{reel_id}/comments")
async def list_comments(reel_id: str) -> list[dict]:
    comments = await db.comments.find({"reel_id": reel_id}).sort("created_at", 1).limit(100).to_list(100)
    author_ids = list({comment["user_id"] for comment in comments})
    authors = await db.users.find({"_id": {"$in": author_ids}}, {"name": 1}).to_list(len(author_ids)) if author_ids else []
    author_by_id = {author["_id"]: author for author in authors}
    result = []
    for comment in comments:
        author = author_by_id.get(comment["user_id"])
        item = clean(comment)
        item["author"] = {"id": comment["user_id"], "name": author.get("name", "User")} if author else None
        result.append(item)
    return result


@api.post("/reels/{reel_id}/comments")
async def create_comment(
    reel_id: str,
    data: CommentInput,
    account: dict = Depends(get_current_user),
) -> dict:
    reel = await db.reels.find_one({"_id": reel_id, "status": "published"})
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    item = {
        "_id": new_id(),
        "reel_id": reel_id,
        "user_id": account["_id"],
        "text": data.text.strip(),
        "created_at": now(),
    }
    await db.comments.insert_one(item)
    if reel["user_id"] != account["_id"]:
        await notify(reel["user_id"], "comment", f"{account['name']} commented on your reel", reel_id)
    item = clean(item)
    item["author"] = {"id": account["_id"], "name": account["name"]}
    return item


@api.get("/users/{target_id}")
async def public_profile(target_id: str, account: dict = Depends(get_current_user)) -> dict:
    if await db.blocks.find_one({"user_id": target_id, "target_id": account["_id"]}):
        raise HTTPException(status_code=404, detail="Profile not found")
    target = await db.users.find_one({"_id": target_id}, {"phone": 0})
    if not target:
        raise HTTPException(status_code=404, detail="Profile not found")
    result = clean(target)
    result["verified"] = bool(target.get("verified", False))
    result["followers"] = await db.follows.count_documents({"target_id": target_id})
    result["following"] = await db.follows.count_documents({"user_id": target_id})
    result["followed"] = bool(await db.follows.find_one({"user_id": account["_id"], "target_id": target_id}))
    return result


@api.post("/users/{target_id}/follow")
async def follow_user(target_id: str, account: dict = Depends(get_current_user)) -> dict:
    if target_id == account["_id"]:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")
    target = await db.users.find_one({"_id": target_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if await db.blocks.find_one({"user_id": target_id, "target_id": account["_id"]}):
        raise HTTPException(status_code=404, detail="User not found")
    key = {"user_id": account["_id"], "target_id": target_id}
    existing = await db.follows.find_one(key)
    if existing:
        await db.follows.delete_one(key)
        followed = False
    else:
        await db.follows.insert_one({**key, "created_at": now()})
        followed = True
        await notify(target_id, "follow", f"{account['name']} followed you", account["_id"])
    return {"followed": followed, "followers": await db.follows.count_documents({"target_id": target_id})}


@api.post("/users/{target_id}/block")
async def block_user(target_id: str, account: dict = Depends(get_current_user)) -> dict:
    if target_id == account["_id"]:
        raise HTTPException(status_code=400, detail="You cannot block yourself")
    if not await db.users.find_one({"_id": target_id}, {"_id": 1}):
        raise HTTPException(status_code=404, detail="User not found")
    await db.blocks.update_one(
        {"user_id": account["_id"], "target_id": target_id},
        {"$setOnInsert": {"created_at": now()}},
        upsert=True,
    )
    await db.follows.delete_many(
        {"$or": [{"user_id": account["_id"], "target_id": target_id}, {"user_id": target_id, "target_id": account["_id"]}]}
    )
    return {"blocked": True}


@api.delete("/users/{target_id}/block")
async def unblock_user(target_id: str, account: dict = Depends(get_current_user)) -> dict:
    await db.blocks.delete_one({"user_id": account["_id"], "target_id": target_id})
    return {"blocked": False}


@api.get("/blocks")
async def list_blocks(account: dict = Depends(get_current_user)) -> list[dict]:
    result = []
    async for block in db.blocks.find({"user_id": account["_id"]}).sort("created_at", -1):
        target = await db.users.find_one({"_id": block["target_id"]}, {"name": 1, "role": 1})
        if target:
            result.append({"id": block["target_id"], "name": target["name"], "role": target["role"]})
    return result


@api.post("/enquiries")
async def create_enquiry(data: EnquiryInput, account: dict = Depends(get_current_user)) -> dict:
    property_item = await db.properties.find_one({"_id": data.property_id})
    if not property_item:
        raise HTTPException(status_code=404, detail="Property not found")
    if property_item["owner_id"] == account["_id"]:
        raise HTTPException(status_code=400, detail="You cannot enquire about your own property")
    if await db.blocks.find_one(
        {"$or": [
            {"user_id": property_item["owner_id"], "target_id": account["_id"]},
            {"user_id": account["_id"], "target_id": property_item["owner_id"]},
        ]}
    ):
        raise HTTPException(status_code=404, detail="Property not found")
    item = {
        "_id": new_id(),
        "property_id": data.property_id,
        "customer_id": account["_id"],
        "owner_id": property_item["owner_id"],
        "message": data.message.strip(),
        "phone": data.phone or account.get("phone"),
        "status": "New",
        "created_at": now(),
    }
    await db.enquiries.insert_one(item)
    await notify(
        property_item["owner_id"],
        "enquiry",
        f"{account['name']} enquired about {property_item['title']}",
        item["_id"],
    )
    return clean(item)


@api.get("/leads")
async def get_leads(account: dict = Depends(require_roles("owner", "broker"))) -> list[dict]:
    result = []
    leads = await db.enquiries.find({"owner_id": account["_id"]}).sort("created_at", -1).limit(100).to_list(100)
    customer_ids = list({lead["customer_id"] for lead in leads})
    property_ids = list({lead["property_id"] for lead in leads})
    customers = await db.users.find({"_id": {"$in": customer_ids}}, {"name": 1, "phone": 1}).to_list(len(customer_ids)) if customer_ids else []
    properties = await db.properties.find({"_id": {"$in": property_ids}}, {"title": 1, "locality": 1}).to_list(len(property_ids)) if property_ids else []
    customers_by_id = {customer["_id"]: clean(customer) for customer in customers}
    properties_by_id = {property_item["_id"]: clean(property_item) for property_item in properties}
    for lead in leads:
        item = clean(lead)
        item["customer"] = customers_by_id.get(lead["customer_id"])
        item["property"] = properties_by_id.get(lead["property_id"])
        result.append(item)
    return result


@api.patch("/leads/{lead_id}/status")
async def update_lead_status(
    lead_id: str,
    data: StatusInput,
    account: dict = Depends(require_roles("owner", "broker")),
) -> dict:
    allowed = {"New", "Contacted", "Interested", "Site Visit", "Negotiation", "Closed", "Not Relevant"}
    if data.status not in allowed:
        raise HTTPException(status_code=422, detail="Invalid lead status")
    result = await db.enquiries.update_one(
        {"_id": lead_id, "owner_id": account["_id"]},
        {"$set": {"status": data.status, "updated_at": now()}},
    )
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Lead not found")
    return {"status": data.status}


@api.post("/requirements")
async def create_requirement(data: RequirementInput, account: dict = Depends(get_current_user)) -> dict:
    item = {
        **data.model_dump(),
        "_id": new_id(),
        "user_id": account["_id"],
        "created_at": now(),
    }
    await db.requirements.insert_one(item)
    return clean(item)


@api.get("/requirements")
async def list_requirements(account: dict = Depends(get_current_user)) -> list[dict]:
    items = await db.requirements.find({"user_id": account["_id"]}).sort("created_at", -1).limit(50).to_list(50)
    return [clean(item) for item in items]


@api.get("/notifications")
async def list_notifications(account: dict = Depends(get_current_user)) -> list[dict]:
    items = await db.notifications.find({"user_id": account["_id"]}).sort("created_at", -1).limit(50).to_list(50)
    return [clean(item) for item in items]


@api.patch("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, account: dict = Depends(get_current_user)) -> dict:
    result = await db.notifications.update_one(
        {"_id": notification_id, "user_id": account["_id"]}, {"$set": {"read": True}}
    )
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"read": True}


@api.post("/reports")
async def create_report(data: ReportInput, account: dict = Depends(get_current_user)) -> dict:
    item = {
        **data.model_dump(),
        "_id": new_id(),
        "user_id": account["_id"],
        "status": "open",
        "created_at": now(),
    }
    await db.reports.insert_one(item)
    return {"message": "Report submitted"}


@api.post("/analytics/events")
async def record_analytics_event(data: AnalyticsInput, account: dict = Depends(get_current_user)) -> dict:
    await db.analytics_events.insert_one(
        {
            "_id": new_id(),
            "user_id": account["_id"],
            "event": data.event,
            "properties": data.properties,
            "created_at": now(),
        }
    )
    return {"recorded": True}


@api.get("/admin/overview")
async def admin_overview(account: dict = Depends(require_roles("admin"))) -> dict:
    return {
        "users": await db.users.count_documents({}),
        "properties": await db.properties.count_documents({}),
        "pending_properties": await db.properties.count_documents({"verified": False}),
        "pending_users": await db.users.count_documents({"role": {"$in": ["owner", "broker"]}, "verified": {"$ne": True}}),
        "reels": await db.reels.count_documents({}),
        "open_reports": await db.reports.count_documents({"status": "open"}),
        "events_last_7_days": await db.analytics_events.count_documents({"created_at": {"$gte": now() - timedelta(days=7)}}),
    }


@api.get("/admin/properties/pending")
async def admin_pending_properties(account: dict = Depends(require_roles("admin"))) -> list[dict]:
    items = await db.properties.find({"verified": False}).sort("created_at", 1).limit(100).to_list(100)
    return [clean(item) for item in items]


@api.get("/admin/users/pending")
async def admin_pending_users(account: dict = Depends(require_roles("admin"))) -> list[dict]:
    items = await db.users.find(
        {"role": {"$in": ["owner", "broker"]}, "verified": {"$ne": True}},
        {"phone": 1, "name": 1, "role": 1, "created_at": 1, "verified": 1},
    ).sort("created_at", 1).limit(100).to_list(100)
    return [clean(item) for item in items]


@api.patch("/admin/users/{user_id}/verification")
async def admin_verify_user(
    user_id: str,
    verified: bool,
    account: dict = Depends(require_roles("admin")),
) -> dict:
    target = await db.users.find_one({"_id": user_id, "role": {"$in": ["owner", "broker"]}})
    if not target:
        raise HTTPException(status_code=404, detail="Business account not found")
    await db.users.update_one({"_id": user_id}, {"$set": {"verified": verified}})
    if verified:
        await notify(user_id, "verification", "Your business account was verified", user_id)
    return {"verified": verified}


@api.patch("/admin/properties/{property_id}/verification")
async def admin_verify_property(
    property_id: str,
    verified: bool,
    account: dict = Depends(require_roles("admin")),
) -> dict:
    result = await db.properties.update_one({"_id": property_id}, {"$set": {"verified": verified}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Property not found")
    item = await db.properties.find_one({"_id": property_id})
    if verified:
        await notify(item["owner_id"], "verification", f"{item['title']} was verified", property_id)
    return {"verified": verified}


@api.get("/admin/reports")
async def admin_reports(account: dict = Depends(require_roles("admin"))) -> list[dict]:
    items = await db.reports.find().sort("created_at", -1).limit(100).to_list(100)
    return [clean(item) for item in items]


@api.patch("/admin/reports/{report_id}")
async def admin_update_report(
    report_id: str,
    status: str,
    account: dict = Depends(require_roles("admin")),
) -> dict:
    if status not in {"open", "reviewing", "resolved", "dismissed"}:
        raise HTTPException(status_code=422, detail="Invalid report status")
    result = await db.reports.update_one({"_id": report_id}, {"$set": {"status": status}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": status}


@api.get("/admin/analytics")
async def admin_analytics(account: dict = Depends(require_roles("admin"))) -> list[dict]:
    pipeline = [
        {"$match": {"created_at": {"$gte": now() - timedelta(days=30)}}},
        {"$group": {"_id": "$event", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    return [{"event": row["_id"], "count": row["count"]} async for row in db.analytics_events.aggregate(pipeline)]


app.include_router(api)
