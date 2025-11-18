import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

from database import db, create_document, get_documents

# App & CORS
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth settings
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MIN", "120"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ----------------------------
# Utils
# ----------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = Field(default="client")  # client, employee, admin

class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str

class AgentIn(BaseModel):
    name: str
    price: float = Field(..., ge=0)
    rating: float = Field(..., ge=0, le=5)
    skills: List[str] = []
    problems: List[str] = []
    description: Optional[str] = None
    featured: bool = True

class AgentOut(AgentIn):
    id: str

# Database helpers

def to_public_id(doc):
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d

# Auth dependencies
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": ObjectId(user_id)}) if db else None
    if user is None:
        raise credentials_exception
    return to_public_id(user)

def require_role(required: List[str]):
    async def _dep(user = Depends(get_current_user)):
        if user.get("role") not in required:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return _dep

# ----------------------------
# Basic routes
# ----------------------------
@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, 'name', 'unknown')
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# ----------------------------
# Auth endpoints
# ----------------------------
@app.post("/api/auth/register", response_model=UserPublic)
def register(user: UserCreate):
    if db is None:
        raise HTTPException(500, detail="Database not configured")
    existing = db.user.find_one({"email": user.email})
    if existing:
        raise HTTPException(400, detail="Email already registered")
    doc = {
        "name": user.name,
        "email": str(user.email).lower(),
        "password_hash": hash_password(user.password),
        "role": user.role if user.role in ["client","employee","admin"] else "client",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    inserted = db.user.insert_one(doc)
    return {
        "id": str(inserted.inserted_id),
        "name": doc["name"],
        "email": doc["email"],
        "role": doc["role"],
    }

@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(500, detail="Database not configured")
    user = db.user.find_one({"email": form_data.username.lower()})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    to_encode = {
        "sub": str(user["_id"]),
        "role": user.get("role", "client"),
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}

@app.get("/api/auth/me", response_model=UserPublic)
def me(current_user = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "name": current_user["name"],
        "email": current_user["email"],
        "role": current_user.get("role", "client"),
    }

# ----------------------------
# Agents endpoints
# ----------------------------
SAMPLE_AGENTS = [
    {"name": "Sales Copilot", "price": 99, "rating": 4.8, "skills": ["lead-qual","email","crm"], "problems": ["low-leads","slow-outreach"], "description": "Asystent sprzedaży"},
    {"name": "Support AutoPilot", "price": 149, "rating": 4.6, "skills": ["summarize","classify","routing"], "problems": ["ticket-backlog"], "description": "Automatyzacja wsparcia"},
    {"name": "Ops Orchestrator", "price": 249, "rating": 4.9, "skills": ["rpa","scheduler","etl"], "problems": ["manual-tasks"], "description": "Orkiestracja operacji"},
    {"name": "Research Scout", "price": 79, "rating": 4.5, "skills": ["web-browse","extract","cite"], "problems": ["slow-research"], "description": "Badania i ekstrakcja"},
]

@app.get("/api/agents", response_model=List[AgentOut])
def list_agents():
    if db is None:
        # No DB; return samples
        return [{"id": str(i), **a} for i, a in enumerate(SAMPLE_AGENTS)]
    # Seed once if empty
    if db.agent.count_documents({}) == 0:
        for a in SAMPLE_AGENTS:
            a_doc = {**a, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
            db.agent.insert_one(a_doc)
    docs = list(db.agent.find({}))
    return [AgentOut(**to_public_id(d)) for d in docs]

@app.post("/api/agents", response_model=AgentOut)
def create_agent(agent: AgentIn, _=Depends(require_role(["admin"]))):
    if db is None:
        raise HTTPException(500, detail="Database not configured")
    doc = agent.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    doc["updated_at"] = datetime.now(timezone.utc)
    ins = db.agent.insert_one(doc)
    doc["id"] = str(ins.inserted_id)
    return AgentOut(**doc)

@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: str, _=Depends(require_role(["admin"]))):
    if db is None:
        raise HTTPException(500, detail="Database not configured")
    try:
        res = db.agent.delete_one({"_id": ObjectId(agent_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid agent id")
    if res.deleted_count == 0:
        raise HTTPException(404, detail="Agent not found")
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
