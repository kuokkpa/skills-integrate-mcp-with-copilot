"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from datetime import datetime, timedelta, timezone
from hashlib import pbkdf2_hmac
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

security = HTTPBearer()

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-only-secret-change-me")
JWT_ALGORITHM = "HS256"

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}

users: dict[str, dict[str, str]] = {}
refresh_token_store: dict[str, dict[str, Any]] = {}


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _create_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(JWT_SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def _decode_jwt(token: str, expected_token_type: str) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid token format") from exc

    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    expected_signature = hmac.new(JWT_SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    provided_signature = _b64url_decode(encoded_signature)

    if not hmac.compare_digest(expected_signature, provided_signature):
        raise HTTPException(status_code=401, detail="Invalid token signature")

    payload = json.loads(_b64url_decode(encoded_payload).decode())
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

    if _utc_now() >= expires_at:
        raise HTTPException(status_code=401, detail="Token expired")

    if payload.get("type") != expected_token_type:
        raise HTTPException(status_code=401, detail="Invalid token type")

    return payload


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    pwd_hash = pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}:{pwd_hash.hex()}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    salt_hex, hash_hex = encoded_hash.split(":", maxsplit=1)
    salt = bytes.fromhex(salt_hex)
    expected_hash = bytes.fromhex(hash_hex)
    candidate_hash = pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return hmac.compare_digest(expected_hash, candidate_hash)


def _create_token_pair(username: str) -> dict[str, str]:
    now = _utc_now()
    access_exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    access_payload = {
        "sub": username,
        "type": "access",
        "exp": int(access_exp.timestamp()),
    }

    refresh_jti = secrets.token_hex(16)
    refresh_payload = {
        "sub": username,
        "type": "refresh",
        "jti": refresh_jti,
        "exp": int(refresh_exp.timestamp()),
    }

    access_token = _create_jwt(access_payload)
    refresh_token = _create_jwt(refresh_payload)

    refresh_token_store[refresh_jti] = {
        "username": username,
        "expires_at": refresh_exp,
        "revoked": False,
    }

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


def _require_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, str]:
    payload = _decode_jwt(credentials.credentials, expected_token_type="access")
    username = payload.get("sub")

    if not username or username not in users:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    return users[username]


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/auth/register")
def register(payload: RegisterRequest):
    if payload.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    for user in users.values():
        if user["email"] == payload.email:
            raise HTTPException(status_code=400, detail="Email already exists")

    users[payload.username] = {
        "username": payload.username,
        "email": payload.email,
        "password_hash": _hash_password(payload.password),
    }

    return {"message": "User registered successfully"}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = users.get(payload.username)

    if user is None or not _verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return _create_token_pair(payload.username)


@app.post("/auth/refresh")
def refresh_access_token(payload: RefreshRequest):
    token_payload = _decode_jwt(payload.refresh_token, expected_token_type="refresh")
    token_id = token_payload["jti"]
    username = token_payload["sub"]

    session = refresh_token_store.get(token_id)
    if session is None or session["revoked"]:
        raise HTTPException(status_code=401, detail="Refresh token revoked or invalid")

    if session["username"] != username or _utc_now() >= session["expires_at"]:
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

    refresh_token_store[token_id]["revoked"] = True
    return _create_token_pair(username)


@app.post("/auth/logout")
def logout(payload: LogoutRequest):
    token_payload = _decode_jwt(payload.refresh_token, expected_token_type="refresh")
    token_id = token_payload["jti"]
    session = refresh_token_store.get(token_id)

    if session is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    refresh_token_store[token_id]["revoked"] = True
    return {"message": "Logged out successfully"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str,
    email: str | None = None,
    current_user: dict[str, str] = Depends(_require_current_user),
):
    """Sign up a student for an activity"""
    signed_in_email = current_user["email"]
    target_email = email or signed_in_email

    if target_email != signed_in_email:
        raise HTTPException(status_code=403, detail="You can only sign up your own account")

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if target_email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(target_email)
    return {"message": f"Signed up {target_email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str | None = None,
    current_user: dict[str, str] = Depends(_require_current_user),
):
    """Unregister a student from an activity"""
    signed_in_email = current_user["email"]
    target_email = email or signed_in_email

    if target_email != signed_in_email:
        raise HTTPException(status_code=403, detail="You can only unregister your own account")

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if target_email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(target_email)
    return {"message": f"Unregistered {target_email} from {activity_name}"}
