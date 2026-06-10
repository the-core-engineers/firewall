from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db, seed_db_async
from login import login_router

from api.rules import router as rules_router
from api.blocklist import router as blocklist_router
from api.settings import router as settings_router
from api.logs import router as logs_router
from api.capture import router as capture_router
from api.tester import router as tester_router

from engine import refresh_cache

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB sync tables
init_db()

@app.on_event("startup")
async def startup_event():
    # Seed db defaults async
    await seed_db_async()
    refresh_cache()

app.include_router(login_router)
app.include_router(rules_router)
app.include_router(blocklist_router)
app.include_router(settings_router)
app.include_router(logs_router)
app.include_router(capture_router)
app.include_router(tester_router)
