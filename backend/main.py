from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database import engine, Base, SessionLocal
from routers import auth, scans, hosts, users, policies
from models import user as user_model, scan as scan_model, host as host_model, policy as policy_model
from services.user_service import create_initial_admin
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    Base.metadata.create_all(bind=engine)
    # Create admin user
    db = SessionLocal()
    try:
        create_initial_admin(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="LinuxShield Pro",
    description="Linux Server Security Audit Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(hosts.router, prefix="/api/hosts", tags=["hosts"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(policies.router, prefix="/api/policies", tags=["policies"])

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0"}
