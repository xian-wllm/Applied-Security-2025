import os
import time
import threading
import base64
import requests

VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault.imovies.lan:8200")
ROLE_ID = os.getenv("APPROLE_ROLE_ID", "")
SECRET_ID = os.getenv("APPROLE_SECRET_ID", "")
PKI_MOUNT = os.getenv("PKI_MOUNT", "pki")

# TLS verification: prefer an explicit CA bundle, fall back to system CAs
VAULT_CACERT = os.getenv("VAULT_CACERT", "/srv/app/ca.crt")
if os.path.exists(VAULT_CACERT):
    REQUESTS_VERIFY = VAULT_CACERT
else:
    REQUESTS_VERIFY = True  # system trust store

class VaultClient:
    def __init__(self):
        self._tok = None
        self._exp = 0
        self._lock = threading.Lock()

    def _login(self):
        r = requests.post(
            f"{VAULT_ADDR}/v1/auth/approle/login",
            data={"role_id": ROLE_ID, "secret_id": SECRET_ID},
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        if not r.ok:
            try:
                print("AppRole login failed:", r.status_code, r.text, flush=True)
            except Exception:
                pass
            r.raise_for_status()
        a = r.json()["auth"]
        self._tok = a["client_token"]
        self._exp = int(time.time()) + int(a.get("lease_duration", 300)) - 30

    def token(self) -> str:
        with self._lock:
            if not self._tok or time.time() >= self._exp:
                self._login()
            return self._tok

    def _headers(self) -> dict:
        return {"X-Vault-Token": self.token()}

    # ---- KV v2 ----
    def kv_get(self, path: str) -> dict:
        r = requests.get(
            f"{VAULT_ADDR}/v1/{path}",
            headers=self._headers(),
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return d.get("data", d)

    # ---- Database creds ----
    def db_creds(self, role: str) -> dict:
        r = requests.get(
            f"{VAULT_ADDR}/v1/database/creds/{role}",
            headers=self._headers(),
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        if not r.ok:
            try:
                print("Vault db_creds failed:", r.status_code, r.text, flush=True)
            except Exception:
                pass
            r.raise_for_status()
        return r.json()["data"]

    # ---- PKI ----
    def issue_cert(self, role: str, cn: str, alt: str | None, ttl: str = "720h") -> dict:
        """
        Issue a certificate via Vault's PKI secrets engine.

        common_name (cn) is used as the certificate subject CN, and alt (if
        provided) is passed as alt_names (comma separated), which Vault maps
        to Subject Alternative Names (DNS or email), as documented in the
        official API.
        """
        p: dict[str, str] = {"common_name": cn, "ttl": ttl}
        if alt:
            p["alt_names"] = alt
        r = requests.post(
            f"{VAULT_ADDR}/v1/{PKI_MOUNT}/issue/{role}",
            headers=self._headers(),
            data=p,
            timeout=15,
            verify=REQUESTS_VERIFY,
        )
        if not r.ok:
            try:
                print("Vault PKI issue failed:", r.status_code, r.text, flush=True)
            except Exception:
                pass
            r.raise_for_status()
        return r.json()["data"]


    def revoke(self, serial: str) -> bool:
        r = requests.post(
            f"{VAULT_ADDR}/v1/{PKI_MOUNT}/revoke",
            headers=self._headers(),
            data={"serial_number": serial},
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        r.raise_for_status()
        return True

    # ---- Transit (for key archive) ----
    def transit_encrypt(self, key_name: str, plaintext: bytes) -> str:
        """Encrypt using transit, returns Vault ciphertext string (vault:v1:...)."""
        b64 = base64.b64encode(plaintext).decode()
        r = requests.post(
            f"{VAULT_ADDR}/v1/transit/encrypt/{key_name}",
            headers=self._headers(),
            data={"plaintext": b64},
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        r.raise_for_status()
        return r.json()["data"]["ciphertext"]

    def transit_decrypt(self, key_name: str, ciphertext: str) -> bytes:
        """Decrypt transit ciphertext, returns raw bytes."""
        r = requests.post(
            f"{VAULT_ADDR}/v1/transit/decrypt/{key_name}",
            headers=self._headers(),
            data={"ciphertext": ciphertext},
            timeout=10,
            verify=REQUESTS_VERIFY,
        )
        r.raise_for_status()
        b64 = r.json()["data"]["plaintext"]
        return base64.b64decode(b64)


vault = VaultClient()
