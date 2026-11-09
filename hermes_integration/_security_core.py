"""Shared security core (Stage 7J-A): canonical serialization, operator-authorization verification (Ed25519) and
request-integrity signing/verification (HMAC-SHA256). No custom cryptographic primitives: Ed25519 comes from the maintained
`cryptography` package, HMAC and SHA-256 from the standard library.

THIS FILE EXISTS TWICE, byte for byte: app/security_core.py (Builder) and hermes_integration/_security_core.py (Hermes).
tests/test_stage7ja.py fails if the two differ, so the verifiers cannot drift apart.

Three SEPARATE controls (never merged, never substituted for each other):
  1. TRANSPORT AUTHENTICATION  bearer token (app.auth): who may talk to the Builder at all.
  2. REQUEST INTEGRITY         HMAC-SHA256 over method, path, request id, timestamp, body hash and the operator-authorization
                               hash, with a key shared by Hermes and the Builder (NOT the bearer token): the request is from
                               a holder of the key, unmodified, fresh.
  3. OPERATOR AUTHORIZATION     Ed25519 signature by a key whose PRIVATE half exists only on the operator's machine; the Builder
                               and Hermes hold only the public registry. It binds one task, one request fingerprint, one
                               environment, a spend ceiling and an expiry. Nothing in a request body can assert it.
Nothing here signs a operator authorization: issuance lives in founder_tools/ and is never deployed with agents.

Signed content is the strict canonical JSON of the payload (sorted keys, no whitespace, ASCII only, no floats, no duplicate
keys, bounded size and depth) prefixed with a domain-separation string, so a signature for one purpose cannot be reused for
another. Refusals carry a stable code and never include secrets, payload values or key material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

FOUNDER_DOMAIN = b"SELAERON-FOUNDER-AUTH/1\n"
REQUEST_DOMAIN = "SELAERON-REQ/1"
SIGNATURE_PREFIX = "v1="
MAX_ARTIFACT_BYTES = 6144
MAX_REGISTRY_BYTES = 16384
MAX_HMAC_FILE_BYTES = 4096
SPEND_CEILING_MICRO_USD = 2_000_000          # 2.00 USD, the Builder's default per-task ceiling
MAX_AUTH_TTL_SECONDS = 86400
DEFAULT_SKEW = 60
DEFAULT_MAX_AGE = 300
EXECUTION_OPERATIONS = ("INSPECT", "PREPARE", "EXECUTE", "SPEND")
FOUNDER_ONLY_OPERATIONS = ("DEPLOY", "FINAL_APPROVAL")
ENVIRONMENTS = ("MOCK", "STAGING", "PRODUCTION")
PAYLOAD_KEYS = {"v", "authorization_id", "founder_ref", "mission_id", "task_id", "operations", "environment",
                "max_spend_micro_usd", "issued_at", "expires_at", "request_sha256", "correlation_id"}

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KID = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_FOUNDER_REF = re.compile(r"^founder:[a-z0-9._-]{1,40}$")
_MISSION = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
_CORR = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_B64 = re.compile(r"^[A-Za-z0-9_-]*$")
_DIGITS = re.compile(r"^[0-9]{1,10}$")


class SecurityRefusal(Exception):
    """A security check refused the request. `status`/`category`/`code` are safe to return to the caller."""

    def __init__(self, status: int, category: str, code: str):
        super().__init__(code)
        self.status, self.category, self.code = status, category, code


def _founder(code: str) -> SecurityRefusal:
    return SecurityRefusal(403, "FOUNDER_AUTHORIZATION", code)


def _auth(code: str) -> SecurityRefusal:
    return SecurityRefusal(401, "AUTH", code)


# ---- encoding and canonical serialization ------------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: Any, maxlen: int) -> bytes:
    """Strict base64url (no padding): bounded, alphabet-checked and canonical (re-encoding must give the same text)."""
    if not isinstance(text, str) or len(text) > maxlen or not _B64.fullmatch(text):
        raise ValueError("bad base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("bad base64url") from None
    if b64e(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def _check(obj: Any, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("too deep")
    if obj is None or isinstance(obj, (bool, str, int)):
        return
    if isinstance(obj, list):
        for item in obj:
            _check(item, depth + 1)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise ValueError("non-string key")
            _check(value, depth + 1)
        return
    raise ValueError("unsupported type (floats are not allowed)")


def canonical(obj: Any) -> bytes:
    """The one serialization that is signed: sorted keys, no whitespace, ASCII, no floats/NaN."""
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def parse_strict(raw: bytes, limit: int = MAX_ARTIFACT_BYTES) -> Any:
    """Parse untrusted JSON: bounded size, no duplicate keys, no floats or NaN/Infinity, bounded depth."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > limit:
        raise ValueError("too large")

    def pairs(items):
        out: Dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def refuse(_: Any):
        raise ValueError("float or constant not allowed")

    obj = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse)
    _check(obj)
    return obj


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- trust anchors ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustedKey:
    kid: str
    founder_ref: str
    public_key: bytes
    status: str            # active | revoked


@dataclass(frozen=True)
class FounderRegistry:
    keys: Dict[str, TrustedKey]


def _require_library() -> None:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
    except ImportError:
        raise RuntimeError("the 'cryptography' package is required for founder-authorization verification") from None


def load_registry(path: str) -> FounderRegistry:
    """Public keys only. Raises ValueError/RuntimeError/OSError: callers treat any failure as 'refuse to start'."""
    _require_library()
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_REGISTRY_BYTES:
        raise ValueError("founder registry is missing or too large")
    doc = parse_strict(p.read_bytes(), MAX_REGISTRY_BYTES)
    if (not isinstance(doc, dict) or set(doc) != {"schema", "keys"} or doc["schema"] != 1
            or not isinstance(doc["keys"], list) or not 1 <= len(doc["keys"]) <= 16):
        raise ValueError("founder registry has an invalid shape")
    keys: Dict[str, TrustedKey] = {}
    for entry in doc["keys"]:
        if not isinstance(entry, dict) or set(entry) != {"kid", "alg", "public_key", "founder_ref", "status"}:
            raise ValueError("founder registry entry has an invalid shape")
        if (entry["alg"] != "Ed25519" or not isinstance(entry["kid"], str) or not _KID.fullmatch(entry["kid"])
                or not isinstance(entry["founder_ref"], str) or not _FOUNDER_REF.fullmatch(entry["founder_ref"])
                or entry["status"] not in ("active", "revoked") or entry["kid"] in keys):
            raise ValueError("founder registry entry is invalid")
        raw = b64d(entry["public_key"], 64)
        if len(raw) != 32:
            raise ValueError("founder registry public key must be 32 bytes")
        keys[entry["kid"]] = TrustedKey(entry["kid"], entry["founder_ref"], raw, entry["status"])
    return FounderRegistry(keys)


def _verify_ed25519(public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise SecurityRefusal(503, "FOUNDER_AUTHORIZATION", "SIGNING_LIBRARY_UNAVAILABLE") from None
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- operator authorization ------------------------------------------------------------------------------------------
def validate_payload(p: Any) -> Dict[str, Any]:
    """Strict shape check of the signed payload. Contradictory or out-of-scope content is refused."""
    if not isinstance(p, dict) or set(p) != PAYLOAD_KEYS:
        raise _founder("FOUNDER_AUTH_MALFORMED")

    def integer(key: str) -> int:
        v = p[key]
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise _founder("FOUNDER_AUTH_MALFORMED")
        return v

    if p["v"] != 1 or not isinstance(p["authorization_id"], str) or not _HEX32.fullmatch(p["authorization_id"]):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if not isinstance(p["founder_ref"], str) or not _FOUNDER_REF.fullmatch(p["founder_ref"]):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if p["mission_id"] is not None and (not isinstance(p["mission_id"], str) or not _MISSION.fullmatch(p["mission_id"])):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    for key, rx in (("task_id", _HEX32), ("request_sha256", _HEX64), ("correlation_id", _CORR)):
        if not isinstance(p[key], str) or not rx.fullmatch(p[key]):
            raise _founder("FOUNDER_AUTH_MALFORMED")
    ops = p["operations"]
    if not isinstance(ops, list) or not ops or not all(isinstance(o, str) for o in ops) or ops != sorted(set(ops)):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if any(o in FOUNDER_ONLY_OPERATIONS for o in ops):
        raise _founder("UNSUPPORTED_OPERATION")       # deploy / final approval can never ride in an execution authorization
    if any(o not in EXECUTION_OPERATIONS for o in ops):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if p["environment"] not in ENVIRONMENTS:
        raise _founder("FOUNDER_AUTH_MALFORMED")
    spend, issued, expires = integer("max_spend_micro_usd"), integer("issued_at"), integer("expires_at")
    if spend > SPEND_CEILING_MICRO_USD:
        raise _founder("FOUNDER_AUTH_CONTRADICTORY")
    if expires <= issued or expires - issued > MAX_AUTH_TTL_SECONDS:
        raise _founder("FOUNDER_AUTH_CONTRADICTORY")
    if ("SPEND" in ops) != (spend > 0):
        raise _founder("FOUNDER_AUTH_CONTRADICTORY")  # a spend ceiling without a spend grant (or the reverse) is contradictory
    return p


def verify_founder_authorization(header: Optional[str], registry: FounderRegistry, *, expected: Mapping[str, Any],
                                 now: float, skew: int = DEFAULT_SKEW) -> Dict[str, Any]:
    """Verify one operator authorization (the base64url header value) for exactly the request described by `expected`:
    task_id, mission_id (or None), correlation_id, environment, operations (tuple), request_sha256, spend_micro_usd.
    Returns the verified payload or raises SecurityRefusal(403). Order: shape -> signature -> content -> time -> binding."""
    if header is None or header == "":
        raise _founder("FOUNDER_AUTH_MISSING")
    if not isinstance(header, str) or len(header) > MAX_ARTIFACT_BYTES * 4 // 3 + 8:
        raise _founder("FOUNDER_AUTH_TOO_LARGE")
    try:
        art = parse_strict(b64d(header, MAX_ARTIFACT_BYTES * 4 // 3 + 8))
    except (ValueError, UnicodeDecodeError):
        raise _founder("FOUNDER_AUTH_MALFORMED") from None
    if not isinstance(art, dict) or "payload" not in art:
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if "signature" not in art or art["signature"] in (None, "", {}):
        raise _founder("SIGNATURE_MISSING")
    sig = art["signature"]
    if set(art) != {"payload", "signature"} or not isinstance(sig, dict) or set(sig) != {"alg", "kid", "sig"}:
        raise _founder("FOUNDER_AUTH_MALFORMED")
    if sig["alg"] != "Ed25519":
        raise _founder("UNSUPPORTED_ALGORITHM")
    if not isinstance(sig["kid"], str) or not _KID.fullmatch(sig["kid"]):
        raise _founder("FOUNDER_AUTH_MALFORMED")
    key = registry.keys.get(sig["kid"])
    if key is None:
        raise _founder("UNKNOWN_KEY_ID")
    if key.status != "active":
        raise _founder("KEY_REVOKED")
    try:
        sig_bytes = b64d(sig["sig"], 100)
        message = FOUNDER_DOMAIN + canonical(art["payload"])
    except ValueError:
        raise _founder("SIGNATURE_INVALID") from None
    if len(sig_bytes) != 64 or not _verify_ed25519(key.public_key, sig_bytes, message):
        raise _founder("SIGNATURE_INVALID")
    p = validate_payload(art["payload"])
    if p["founder_ref"] != key.founder_ref:
        raise _founder("UNKNOWN_SIGNER")              # a valid signature by a key that does not belong to this identity
    if now + skew < p["issued_at"]:
        raise _founder("FUTURE_DATED")
    if now >= p["expires_at"]:
        raise _founder("EXPIRED")
    if p["task_id"] != expected["task_id"]:
        raise _founder("TASK_MISMATCH")
    if p["mission_id"] != expected["mission_id"]:
        raise _founder("MISSION_MISMATCH")
    if p["correlation_id"] != expected["correlation_id"]:
        raise _founder("CORRELATION_MISMATCH")
    if p["environment"] != expected["environment"]:
        raise _founder("ENVIRONMENT_MISMATCH")
    if p["request_sha256"] != expected["request_sha256"]:
        raise _founder("REQUEST_MODIFIED")
    missing = set(expected["operations"]) - set(p["operations"])
    if missing == {"SPEND"}:
        raise _founder("SPEND_NOT_AUTHORIZED")
    if missing:
        raise _founder("OPERATION_MISMATCH")
    if expected["spend_micro_usd"] > p["max_spend_micro_usd"]:
        raise _founder("SPEND_LIMIT_MISMATCH")
    return p


# ---- request integrity (HMAC-SHA256) ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class HmacKey:
    kid: str
    secret: bytes


def load_hmac_keys(path: str) -> Dict[str, HmacKey]:
    """Active shared request-signing keys. The file is a secret: its contents are never logged or returned."""
    p = Path(path)
    if not p.is_file() or p.stat().st_size > MAX_HMAC_FILE_BYTES:
        raise ValueError("request key file is missing or too large")
    doc = parse_strict(p.read_bytes(), MAX_HMAC_FILE_BYTES)
    if (not isinstance(doc, dict) or set(doc) != {"schema", "keys"} or doc["schema"] != 1
            or not isinstance(doc["keys"], list) or not 1 <= len(doc["keys"]) <= 4):
        raise ValueError("request key file has an invalid shape")
    keys: Dict[str, HmacKey] = {}
    seen = set()
    for entry in doc["keys"]:
        if (not isinstance(entry, dict) or set(entry) != {"kid", "secret", "status"}
                or entry["status"] not in ("active", "retired")):
            raise ValueError("request key entry has an invalid shape")
        if not isinstance(entry["kid"], str) or not _KID.fullmatch(entry["kid"]) or entry["kid"] in seen:
            raise ValueError("request key id is invalid")
        seen.add(entry["kid"])
        secret = b64d(entry["secret"], 128)
        if len(secret) < 32:
            raise ValueError("request key is too short")
        if entry["status"] == "active":
            keys[entry["kid"]] = HmacKey(entry["kid"], secret)
    if not keys:
        raise ValueError("no active request key")
    return keys


def string_to_sign(method: str, path: str, request_id: str, timestamp: int, body: bytes, founder_header: str,
                   kid: str) -> bytes:
    return "\n".join([REQUEST_DOMAIN, method.upper(), path, kid, request_id, str(timestamp), sha256_hex(body),
                      sha256_hex(founder_header.encode("ascii", "replace"))]).encode("ascii", "replace")


def sign_request(key: HmacKey, method: str, path: str, request_id: str, timestamp: int, body: bytes,
                 founder_header: str) -> str:
    mac = hmac.new(key.secret, string_to_sign(method, path, request_id, timestamp, body, founder_header, key.kid),
                   hashlib.sha256).hexdigest()
    return SIGNATURE_PREFIX + mac


def verify_request(keys: Mapping[str, HmacKey], headers: Mapping[str, str], method: str, path: str, body: bytes,
                   now: float, max_age: int = DEFAULT_MAX_AGE, skew: int = DEFAULT_SKEW) -> str:
    """Verify request integrity and freshness. Returns the request id or raises SecurityRefusal(401)."""
    request_id, ts_text = headers.get("x-request-id"), headers.get("x-request-timestamp")
    signature, kid = headers.get("x-request-signature"), headers.get("x-signature-key-id")
    founder_header = headers.get("x-founder-authorization") or ""
    if not signature:
        raise _auth("REQUEST_SIGNATURE_MISSING")
    if not (request_id and ts_text and kid):
        raise _auth("REQUEST_SIGNATURE_MALFORMED")
    if not _HEX32.fullmatch(request_id):
        raise _auth("REQUEST_ID_INVALID")
    if not _DIGITS.fullmatch(ts_text):
        raise _auth("REQUEST_TIMESTAMP_INVALID")
    if not signature.startswith(SIGNATURE_PREFIX):
        raise _auth("UNSUPPORTED_SIGNATURE_VERSION")
    if not _HEX64.fullmatch(signature[len(SIGNATURE_PREFIX):]):
        raise _auth("REQUEST_SIGNATURE_MALFORMED")
    key = keys.get(kid) if _KID.fullmatch(kid) else None
    if key is None:
        raise _auth("UNKNOWN_SIGNATURE_KEY")
    ts = int(ts_text)
    want = sign_request(key, method, path, request_id, ts, body, founder_header)
    if not hmac.compare_digest(want.encode("ascii"), signature.encode("ascii")):
        raise _auth("REQUEST_SIGNATURE_INVALID")
    if ts > now + skew:
        raise _auth("REQUEST_FUTURE")
    if now - ts > max_age:
        raise _auth("REQUEST_STALE")
    return request_id
