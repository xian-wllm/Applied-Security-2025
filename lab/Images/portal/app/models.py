from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, BigInteger, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from db import Base

# Legacy users table (as in dump)
class LegacyUser(Base):
    __tablename__ = "users"
    uid = Column(String(64), primary_key=True)
    lastname = Column(String(64))
    firstname = Column(String(64))
    email = Column(String(64))
    pwd = Column(String(64))

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(255))

class UserRole(Base):
    __tablename__ = "user_roles"
    uid = Column(String(64), ForeignKey("users.uid"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)

class Cert(Base):
    __tablename__ = "certs"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    uid = Column(String(64), ForeignKey("users.uid"), nullable=False)
    role = Column(String(64), nullable=False)
    serial = Column(String(64), unique=True, nullable=False)
    cn = Column(String(255), nullable=False)
    ou = Column(String(50), nullable=False)
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    issuing_role = Column(String(64), nullable=False)
    pem = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

class Revocation(Base):
    __tablename__ = "revocations"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    serial = Column(String(64), unique=True, nullable=False)
    reason = Column(String(64), nullable=True)
    revoked_at = Column(DateTime, nullable=False)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    actor_uid = Column(String(64), nullable=True)
    actor_cert_serial = Column(String(64), nullable=True)
    action = Column(String(64), nullable=False)
    target = Column(String(128))
    meta = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())

class AdminStats(Base):
    __tablename__ = "admin_stats"
    id = Column(Integer, primary_key=True)
    total_issued = Column(BigInteger, nullable=False, default=0)
    total_revoked = Column(BigInteger, nullable=False, default=0)
    last_serial = Column(String(64))

class KeyArchive(Base):
    __tablename__ = "key_archive"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    uid = Column(String(64))
    serial = Column(String(64), unique=True, nullable=False)
    p12_b64 = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
