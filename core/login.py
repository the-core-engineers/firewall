from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import sqlite3
import aiosqlite
import bcrypt
from jose import jwt, JWTError
from datetime import datetime, timedelta
import uuid

SECRET_KEY = "super-secret-firewall-key"  # In production, use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440 # 24 hours

DB_PATH = "firewall.db"

login_router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def get_password_hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def init_login_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Check if admin exists
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_hash = get_password_hash("admin")
        cursor.execute("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", 
                       (str(uuid.uuid4())[:8], "admin", default_hash))
    conn.commit()
    conn.close()

# Initialize sync so it runs on import
init_login_db()

@login_router.post("/login", response_model=Token)
async def login(req: LoginRequest):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT * FROM users WHERE username = ?", (req.username,))
        user = await cursor.fetchone()
        
        if not user or not verify_password(req.password, user[2]): # user[2] is password_hash
            raise HTTPException(status_code=401, detail="Incorrect username or password")
            
        access_token = create_access_token(
            data={"sub": user[1]}, 
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return username
