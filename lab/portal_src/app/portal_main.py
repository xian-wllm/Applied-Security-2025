import os, io, hashlib, datetime, hmac
import tempfile
import subprocess
from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, update
from sqlalchemy.orm import Session
from cryptography import x509
from cryptography.x509.oid import NameOID
from db import get_db
from models import LegacyUser, Role, UserRole, Cert, Revocation, AuditEvent, AdminStats, KeyArchive
from vault_client import vault

app = FastAPI(title="imovies portal")
templates = Jinja2Templates(directory="templates")

# ensure extension tables exist (legacy users is created by dump)
# Base.metadata.create_all(bind=engine, tables=[
#     Role.__table__, UserRole.__table__, Cert.__table__, Revocation.__table__,
#     AuditEvent.__table__, AdminStats.__table__, KeyArchive.__table__
# ])

# ---- secrets from Vault KV ----
secrets = vault.kv_get("kv/data/app/portal")
PKCS12_PASSWORD = secrets.get("pkcs12_password", "changeit")

_session_hex = secrets.get("session_secret", "")
_csrf_hex = secrets.get("csrf_secret", "")
_pwd_secret_hex = secrets.get("pwd_secret", "")

SESSION_KEY = bytes.fromhex(_session_hex) if _session_hex else os.urandom(32)
CSRF_KEY = bytes.fromhex(_csrf_hex) if _csrf_hex else os.urandom(32)
PWD_SECRET = bytes.fromhex(_pwd_secret_hex) if _pwd_secret_hex else os.urandom(32)

PBKDF2_ITER = 200_000  # fixed cost factor

# ---- session settings ----
SESSION_COOKIE_NAME = "imovies_session"
SESSION_LIFETIME = datetime.timedelta(hours=1)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _salt_for_uid(uid: str) -> bytes:
    # per-user salt derived from a secret, no DB column needed
    return hmac.new(PWD_SECRET, uid.encode(), hashlib.sha256).digest()


def hash_password(uid: str, password: str, iterations: int = PBKDF2_ITER) -> str:
    salt = _salt_for_uid(uid)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return dk.hex()  # 32 bytes -> 64 hex chars


def verify_password(uid: str, stored: str, password: str) -> tuple[bool, bool]:
    """
    Verify password against stored hash.

    Returns (ok, is_new_scheme):
      - ok = True if password matches
      - is_new_scheme = True if match via PBKDF2, False if via legacy SHA-256
    """
    try:
        # 1) Try new PBKDF2 scheme first
        new_hash = hash_password(uid, password)
        if hmac.compare_digest(new_hash, stored):
            return True, True

        # 2) Fallback to legacy plain sha256 (dump values)
        legacy_hash = sha256_hex(password)
        if hmac.compare_digest(legacy_hash, stored):
            return True, False

        return False, False
    except Exception:
        return False, False

# ---- signed cookie sessions ----
def _make_session_value(uid: str) -> str:
    now = int(datetime.datetime.utcnow().timestamp())
    payload = f"{uid}|{now}".encode()
    sig = hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()
    return f"{uid}|{now}|{sig}"


def _parse_session_value(value: str) -> str | None:
    try:
        uid, ts_str, sig = value.split("|", 2)
        payload = f"{uid}|{ts_str}".encode()
        expected = hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        ts = datetime.datetime.fromtimestamp(int(ts_str), datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) - ts > SESSION_LIFETIME:
            return None
        return uid
    except Exception:
        return None


def current_uid(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    return _parse_session_value(token)


# ---- CSRF protection (HMAC over session cookie) ----
def csrf_token_for(request: Request) -> str:
    sess = request.cookies.get(SESSION_COOKIE_NAME, "")
    msg = sess.encode()
    return hmac.new(CSRF_KEY, msg, hashlib.sha256).hexdigest()


def require_csrf(request: Request, token: str):
    expected = csrf_token_for(request)
    if not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "invalid CSRF token")


# ---- RBAC helpers ----
def user_has_role(db: Session, uid: str, role_name: str) -> bool:
    q = (
        select(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(UserRole.uid == uid, Role.name == role_name)
        .limit(1)
    )
    return db.execute(q).scalar() is not None

def get_available_roles_for_user(db, uid):
    roles = db.execute(
        select(Role.name)
        .join(UserRole)
        .where(UserRole.uid == uid)
    ).scalars().all()
    return roles

def is_cert_revoked(db: Session, serial: str) -> bool:
    """
    Check whether a certificate serial has been revoked.

    This uses our local Revocation table, which is kept in sync with Vault
    via vault.revoke() in the /revoke endpoint.
    """
    return db.scalar(
        select(Revocation.id).where(Revocation.serial == serial)
    ) is not None

def _normalize_proxy_serial(header_serial: str) -> str:
    """
    Normalize the serial as provided by NGINX ($ssl_client_serial) to the
    format we store in the DB (Vault's serial_number, colon-separated hex).

    NGINX: "3ABC9F12..."
    Vault: "3A:BC:9F:12:..."
    """
    s = (header_serial or "").strip()
    if not s:
        return s
    # If it already contains colons, assume it's Vault-style
    if ":" in s:
        return s
    s = s.upper()
    # If length is odd, something is off; just return as-is so it fails loudly
    if len(s) % 2 != 0:
        return s
    return ":".join(s[i:i + 2] for i in range(0, len(s), 2))

def admin_uid_from_cert(request: Request, db: Session) -> str | None:
    if request.headers.get("x-client-verify") != "SUCCESS":
        return None

    raw_serial = request.headers.get("x-client-serial")
    if not raw_serial:
        return None
    serial = _normalize_proxy_serial(raw_serial)

    # Reject revoked admin certs
    if is_cert_revoked(db, serial):
        return None

    uid = db.scalar(select(Cert.uid).where(Cert.serial == serial))
    if not uid:
        return None

    if not user_has_role(db, uid, "ca_admin"):
        return None
    return uid

@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    """
    Landing page with simple iMovies context and navigation.
    If a user session exists, expose the LegacyUser object to the template.
    """
    uid = current_uid(request)
    current_user = None
    csrf_token = None
    if uid:
        current_user = db.scalar(select(LegacyUser).where(LegacyUser.uid == uid))
        csrf_token = csrf_token_for(request)
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": csrf_token,
        },
    )

# -------- Authentication (password or certificate) --------
@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login_post(
    request: Request,
    uid: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    u = db.scalar(select(LegacyUser).where(LegacyUser.uid == uid))
    client_ip = request.client.host if request.client else None

    ok = False
    upgraded = False

    if u:
        ok, is_new = verify_password(uid, u.pwd, password)
        upgraded = (ok and not is_new)

    if not ok:
        db.add(AuditEvent(
            actor_uid=uid,
            action="login",
            target=uid,
            meta={"status": "fail", "ip": client_ip},
        ))
        db.commit()
        raise HTTPException(401, "invalid credentials")

    # upgrade from legacy hash to PBKDF2 if needed
    if upgraded:
        u.pwd = hash_password(uid, password)
        db.add(u)

    token = _make_session_value(uid)
    resp = RedirectResponse(url="/profile", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    db.add(AuditEvent(
        actor_uid=uid,
        action="login",
        target=uid,
        meta={"status": "ok", "ip": client_ip, "upgraded_hash": upgraded},
    ))
    db.commit()
    return resp

@app.post("/login-cert")
def login_cert(request: Request, db: Session = Depends(get_db)):
    """
    Login using a client certificate terminated at the reverse proxy.

    We trust the proxy to have verified the certificate against the CA,
    but we still enforce:
      - raw_serial is known (issued by this portal)
      - raw_serial is not revoked
    """
    if request.headers.get("x-client-verify") != "SUCCESS":
        raise HTTPException(403, "client cert required")

    raw_serial = request.headers.get("x-client-serial")
    if not raw_serial:
        raise HTTPException(400, "missing client serial")

    serial = _normalize_proxy_serial(raw_serial)
    client_ip = request.client.host if request.client else None

    # Reject revoked certs
    if is_cert_revoked(db, serial):
        db.add(
            AuditEvent(
                actor_uid=None,
                actor_cert_serial=serial,
                action="login_cert",
                target=None,
                meta={"status": "revoked", "ip": client_ip},
            )
        )
        db.commit()
        raise HTTPException(403, "certificate revoked")

    # Only allow certs we issued and recorded locally
    uid = db.scalar(select(Cert.uid).where(Cert.serial == serial))
    if not uid:
        db.add(
            AuditEvent(
                actor_uid=None,
                actor_cert_serial=serial,
                action="login_cert",
                target=None,
                meta={"status": "unknown_serial", "ip": client_ip},
            )
        )
        db.commit()
        raise HTTPException(403, "unknown certificate")

    token = _make_session_value(uid)
    resp = RedirectResponse(url="/profile", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    db.add(
        AuditEvent(
            actor_uid=uid,
            actor_cert_serial=serial,
            action="login_cert",
            target=uid,
            meta={"status": "ok", "ip": client_ip},
        )
    )
    db.commit()
    return resp

@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    """
    Terminate the current browser session and redirect to the home page.
    CSRF protection is required to avoid cross-site logout.
    """
    uid = current_uid(request)
    if uid:
        # Only enforce CSRF if there is an existing session cookie
        require_csrf(request, csrf_token)
        db.add(AuditEvent(actor_uid=uid, action="logout", target=uid))
        db.commit()

    resp = RedirectResponse(url="/", status_code=303)
    # Clear the session cookie
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp

# -------- Profile (view and correct legacy data) --------
@app.get("/profile", response_class=HTMLResponse)
def profile_get(request: Request, db: Session = Depends(get_db)):
    uid = current_uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)
    u = db.scalar(select(LegacyUser).where(LegacyUser.uid == uid))
    csrf_token = csrf_token_for(request)
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "u": u,
            "current_user": u,
            "csrf_token": csrf_token,
        },
    )

@app.post("/profile")
def profile_post(
    request: Request,
    lastname: str = Form(...),
    firstname: str = Form(...),
    email: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    uid = current_uid(request)
    if not uid:
        raise HTTPException(401, "login required")

    require_csrf(request, csrf_token)

    db.execute(
        update(LegacyUser)
        .where(LegacyUser.uid == uid)
        .values(lastname=lastname, firstname=firstname, email=email)
    )
    db.add(AuditEvent(actor_uid=uid, action="update_profile", target=uid))
    db.commit()
    return RedirectResponse("/enroll", status_code=303)

# -------- Enrollment (issue cert + PKCS#12 + key backup) --------

def _format_dt(dt: datetime.datetime) -> str:
    """
    Format a datetime for display (UTC, human-friendly).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")

def _format_time_remaining(now: datetime.datetime, not_after: datetime.datetime) -> str:
    """
    Compute a coarse-grained "time remaining" string.
    Handles both naive and timezone-aware datetimes by normalising to UTC.
    """
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
    else:
        not_after = not_after.astimezone(datetime.timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    else:
        now = now.astimezone(datetime.timezone.utc)

    delta = not_after - now
    if delta.total_seconds() <= 0:
        return "expired"

    days = delta.days
    if days > 0:
        return f"{days} day{'s' if days != 1 else ''}"

    hours = delta.seconds // 3600
    if hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''}"

    minutes = delta.seconds // 60
    return f"{minutes} min"

def _build_cert_view(cert: Cert, rev: Revocation | None, now: datetime.datetime) -> dict:
    """
    Build a dict with safe, user-friendly information about a certificate
    for template rendering.
    """

    # Normalise times to UTC and make them all timezone-aware
    not_before = cert.not_before
    not_after = cert.not_after

    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=datetime.timezone.utc)
    else:
        not_before = not_before.astimezone(datetime.timezone.utc)

    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
    else:
        not_after = not_after.astimezone(datetime.timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    else:
        now = now.astimezone(datetime.timezone.utc)

    # Determine revocation / expiry status
    is_revoked = rev is not None
    expired = not_after <= now
    soon_threshold = now + datetime.timedelta(days=30)

    if is_revoked:
        status = "Revoked"
        status_code = "revoked"
    elif expired:
        status = "Expired"
        status_code = "revoked"
    elif not_after <= soon_threshold:
        status = "Expiring soon"
        status_code = "expiring"
    else:
        status = "Active"
        status_code = "active"

    time_remaining = _format_time_remaining(now, not_after)

    serial = cert.serial
    if len(serial) > 16:
        serial_short = f"{serial[:8]}…{serial[-6:]}"
    else:
        serial_short = serial

    subject_display = cert.cn

    # Human-readable role label
    raw_role = cert.role or "employee"
    if raw_role == "employee":
        role_label = "Employee (standard user)"
    elif raw_role == "ca_admin":
        role_label = "CA Administrator"
    elif raw_role == "sys_admin":
        role_label = "System Administrator"
    else:
        role_label = raw_role

    return {
        "serial": serial,
        "serial_short": serial_short,
        "cn": cert.cn,
        "subject_display": subject_display,
        "not_before": _format_dt(not_before),
        "not_after": _format_dt(not_after),
        "time_remaining": time_remaining,
        "status": status,
        "status_code": status_code,
        "is_revoked": is_revoked,
        "revoked_at": _format_dt(rev.revoked_at) if rev else None,
        "issuing_role": cert.issuing_role,
        "role": raw_role,
        "role_label": role_label,
        "ou": cert.ou,
    }


@app.get("/enroll", response_class=HTMLResponse)
def enroll_get(request: Request, db: Session = Depends(get_db)):
    """
    Certificates management page:
      - lists all certificates for the current user
      - offers issuing a new certificate
    """
    uid = current_uid(request)
    if not uid:
        return RedirectResponse("/login", status_code=303)

    u = db.scalar(select(LegacyUser).where(LegacyUser.uid == uid))
    if not u:
        raise HTTPException(401, "unknown user")

    csrf_token = csrf_token_for(request)

    # Collect certs belonging to this user
    cert_rows = db.execute(
        select(Cert)
        .where(Cert.uid == uid)
        .order_by(Cert.created_at.desc())
    ).scalars().all()

    # Pre-fetch revocations in one query for efficiency
    rev_map: dict[str, Revocation] = {
        r.serial: r
        for r in db.execute(
            select(Revocation).where(Revocation.serial.in_([c.serial for c in cert_rows]))
        ).scalars().all()
    } if cert_rows else {}

    now = datetime.datetime.now(datetime.timezone.utc)
    certs_for_view = [
        _build_cert_view(c, rev_map.get(c.serial), now) for c in cert_rows
    ]

    available_roles = get_available_roles_for_user(db, uid)
    default_role = "employee"
    if default_role not in available_roles and available_roles:
        default_role = available_roles[0]

    return templates.TemplateResponse(
        "enroll.html",
        {
            "request": request,
            "u": u,
            "current_user": u,
            "csrf_token": csrf_token,
            "certs": certs_for_view,
            "available_roles": available_roles,
            "default_role": default_role,
        },
    )

@app.post("/enroll")
def enroll_post(
    request: Request,
    csrf_token: str = Form(...),
    p12_password: str = Form(""),
    p12_password_confirm: str = Form(""),
    cert_role: str = Form("employee"),
    db: Session = Depends(get_db),
):
    """
    Issue a new client certificate for the currently logged-in user.

    Subject information is derived from the legacy user data; the user
    cannot choose arbitrary CN/alt names.
    """
    uid = current_uid(request)
    if not uid:
        raise HTTPException(401, "login required")
    
    # Ensure user is allowed to request this role
    if not user_has_role(db, uid, cert_role):
        raise HTTPException(403, "You are not allowed to issue a certificate for this role")

    # Map UI role to Vault PKI role + OU
    role_to_vault = {
        "employee": "user_cert",
        "ca_admin": "ca_admin_cert",
        "sys_admin": "sys_admin_cert",
    }
    vault_role_name = role_to_vault.get(cert_role, "user_cert")
    ou_value = {
        "employee": "EMPLOYEE",
        "ca_admin": "CA_ADMIN",
        "sys_admin": "SYS_ADMIN",
    }.get(cert_role, cert_role.upper())

    require_csrf(request, csrf_token)

    u = db.scalar(select(LegacyUser).where(LegacyUser.uid == uid))
    if not u:
        raise HTTPException(401, "unknown user")

    # Derive subject information from current profile data
    common_name = f"{uid}.imovies.lan"
    alt_names = u.email or None

    # Issue cert with role-specific Vault PKI role
    data = vault.issue_cert(
        role=vault_role_name,
        cn=common_name,
        alt=alt_names,   
    )

    pem_cert, pem_key, serial = (
        data["certificate"],
        data["private_key"],
        data["serial_number"],
    )
    cert_obj = x509.load_pem_x509_certificate(pem_cert.encode())
    not_before, not_after = cert_obj.not_valid_before_utc, cert_obj.not_valid_after_utc

    # Extract OU from the subject (if present)
    try:
        ou_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        cert_ou = ou_attrs[0].value if ou_attrs else None
    except Exception:
        cert_ou = None

    # record issuance
    db.add(
        Cert(
            uid=uid,
            role=cert_role,
            serial=serial,
            cn=common_name,
            ou=cert_ou or ou_value,
            not_before=not_before,
            not_after=not_after,
            issuing_role=vault_role_name,
            pem=pem_cert,
        )
    )
    
    stats = db.get(AdminStats, 1) or AdminStats(id=1, total_issued=0, total_revoked=0)
    db.add(stats)
    stats.total_issued += 1
    stats.last_serial = serial
    db.add(
        AuditEvent(
            actor_uid=uid,
            action="issue",
            target=serial,
            meta={"cn": common_name, "role": cert_role, "pki_role": vault_role_name},
        )
    )
    db.commit()

    if p12_password:
        if p12_password != p12_password_confirm:
            raise HTTPException(400, "PKCS#12 passwords do not match")
        if len(p12_password) < 8:
            raise HTTPException(400, "PKCS#12 password must be at least 8 characters long")
        effective_p12_password = p12_password
    else:
        effective_p12_password = PKCS12_PASSWORD

    ca_chain_pems = data.get("ca_chain") or [data["issuing_ca"]]

    with tempfile.TemporaryDirectory() as td:
        key_path = os.path.join(td, "key.pem")
        cert_path = os.path.join(td, "cert.pem")
        chain_path = os.path.join(td, "chain.pem")

        # write private key
        with open(key_path, "w", encoding="ascii") as f:
            f.write(pem_key)

        # write leaf certificate
        with open(cert_path, "w", encoding="ascii") as f:
            f.write(pem_cert)

        # write CA chain (one file with all CA certs)
        with open(chain_path, "w", encoding="ascii") as f:
            for c in ca_chain_pems:
                f.write(c)
                if not c.endswith("\n"):
                    f.write("\n")

        cmd = [
            "openssl", "pkcs12", "-export",
            "-inkey", key_path,
            "-in", cert_path,
            "-certfile", chain_path,
            "-name", uid,  # or common_name, both are fine
            "-keypbe", "PBE-SHA1-3DES",
            "-certpbe", "PBE-SHA1-3DES",
            "-macalg", "sha256",
            f"-passout", f"pass:{effective_p12_password}",
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=False,  # raw bytes
        )
        p12 = result.stdout

    # secure backup using Vault transit
    ciphertext = vault.transit_encrypt("key-archive", p12)
    db.add(KeyArchive(uid=uid, serial=serial, p12_b64=ciphertext))
    db.commit()

    return StreamingResponse(
        io.BytesIO(p12),
        media_type="application/x-pkcs12",
        headers={"Content-Disposition": f'attachment; filename="{common_name}.p12"'},
    )

# -------- Revocation --------
@app.post("/revoke")
def revoke_post(
    request: Request,
    serial: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    # Try user session first
    uid = current_uid(request)
    admin_uid = admin_uid_from_cert(request, db)

    # If there is a browser session, enforce CSRF
    if uid:
        require_csrf(request, csrf_token)

    # Look up the cert being revoked
    cert = db.scalar(select(Cert).where(Cert.serial == serial))
    if not cert:
        raise HTTPException(404, "certificate not found")

    # Authorisation logic:
    # - CA admin (by admin cert) can revoke any certificate
    # - Otherwise, only the owner of the certificate can revoke it
    if admin_uid:
        actor_uid = admin_uid
        actor_cert_serial = request.headers.get("x-client-serial")
    elif uid and cert.uid == uid:
        actor_uid = uid
        actor_cert_serial = None
    else:
        raise HTTPException(403, "not allowed to revoke this certificate")

    # Perform revocation via Vault
    vault.revoke(serial)

    # Record in local DB
    now = datetime.datetime.now(datetime.timezone.utc)
    db.add(
        Revocation(
            serial=serial,
            reason="unspecified",
            revoked_at=now,
        )
    )
    stats = db.get(AdminStats, 1) or AdminStats(id=1, total_issued=0, total_revoked=0)
    db.add(stats)
    stats.total_revoked += 1
    db.add(
        AuditEvent(
            actor_uid=actor_uid,
            actor_cert_serial=actor_cert_serial,
            action="revoke",
            target=serial,
            meta={"revoked_at": now.isoformat()},
        )
    )
    db.commit()

    # For browser-based revocation, redirect back to the certificates page.
    # For API clients (e.g., admin tooling), preserve a JSON response.
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return RedirectResponse("/enroll", status_code=303)

    return {"status": "revoked", "serial": serial}

# -------- Admin (mTLS enforced at proxy) --------
@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    admin_uid = admin_uid_from_cert(request, db)  # checks role "ca_admin"
    if not admin_uid:
        raise HTTPException(403, "CA admin certificate required")

    tot_issued = db.scalar(select(func.count(Cert.id)))
    tot_revoked = db.scalar(select(func.count(Revocation.id)))
    last = db.execute(select(Cert.serial).order_by(Cert.id.desc()).limit(1)).scalar()

    db.add(
        AuditEvent(
            actor_uid=admin_uid,
            actor_cert_serial=request.headers.get("x-client-serial"),
            action="admin_dashboard",
            target=None,
        )
    )
    db.commit()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "tot_issued": tot_issued,
            "tot_revoked": tot_revoked,
            "last_serial": last or "n/a",
        },
    )