from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from vault_client import vault
import os

DB_HOST = os.getenv("DB_HOST", "10.50.30.2")
DB_NAME = os.getenv("DB_NAME", "imovies")
DB_ROLE = os.getenv("DB_VAULT_ROLE", "imovies_app")

def build_engine(creds: dict):
    dsn = f"mysql+pymysql://{creds['username']}:{creds['password']}@{DB_HOST}:3306/{DB_NAME}"
    return create_engine(dsn, pool_pre_ping=True, pool_size=5, max_overflow=10, future=True)

_ENGINE = None

def get_engine():
    global _ENGINE
    if _ENGINE is None:
        creds = vault.db_creds(DB_ROLE)
        _ENGINE = build_engine(creds)
    return _ENGINE

engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()
