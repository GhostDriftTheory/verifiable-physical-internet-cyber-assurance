#!/usr/bin/env python3
"""VPI Cyber Assurance 2.0 public reference -- loopback-only reference implementation.

Three independent processes/SQLite databases/signing keys. NOT a production
network appliance. Private policy truth and compromised endpoints are outside
this protocol's proof boundary. See README.md before deploying or publishing.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from dataclasses import dataclass, asdict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

VERSION = "2.0.0-rc2"
DOMAIN = "VPI-CYBER-ASSURANCE/2"
SCOPE = "handoff.notice"
MAX_BODY = 262144
MAX_TTL = 30000
GRANT_TTL = 2000
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ZERO = "0" * 64
DROP = object()


# Admission decision over validated observations: REJECT=0, HOLD=1, ADMIT=2.
@dataclass(frozen=True)
class GateInput:
    enabled: bool
    eligible: bool
    peer_enabled: bool
    revision: int
    permit_revision: int
    peer_revision: int
    permit_peer_revision: int
    request_issued: int
    permit_issued: int
    now: int
    permit_expires: int
    request_expires: int
    source_verified: bool
    source_issued: int
    source_expires: int

    def __post_init__(self):
        for key, value in asdict(self).items():
            if key in {"enabled", "eligible", "peer_enabled", "source_verified"}:
                if type(value) is not bool:
                    raise ValueError("expected boolean: " + key)
            elif type(value) is not int or not 0 <= value < 2**63:
                raise ValueError("expected nonnegative bounded integer: " + key)

    def to_dict(self):
        return asdict(self)

def gate_decision(g: GateInput) -> int:
    if not g.enabled or not g.peer_enabled:
        return 0
    if g.revision != g.permit_revision or g.peer_revision != g.permit_peer_revision:
        return 0
    if not (g.request_issued <= g.permit_issued <= g.now < g.permit_expires <= g.request_expires):
        return 0
    if not g.eligible or not g.source_verified:
        return 1
    if not g.source_issued <= g.now < g.source_expires:
        return 1
    return 2


class ProtocolError(ValueError):
    def __init__(self, reason: str, verdict: str = "REJECT"):
        super().__init__(reason)
        self.reason, self.verdict = reason, verdict


class TransportError(RuntimeError):
    pass


def now_ms() -> int:
    return time.time_ns() // 1000000


def restricted(value: Any, depth: int = 0) -> None:
    """Explicit JSON subset; no floats, non-ASCII, NaN, or ambiguous numbers."""
    if depth > 24:
        raise ProtocolError("JSON_DEPTH")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) < value < 2**63:
            raise ProtocolError("INTEGER_RANGE")
        return
    if type(value) is str:
        if len(value) > 8192 or not value.isascii():
            raise ProtocolError("STRING_FORMAT")
        return
    if type(value) is list:
        if len(value) > 10000:
            raise ProtocolError("ARRAY_SIZE")
        for item in value:
            restricted(item, depth + 1)
        return
    if type(value) is dict:
        for k, v in value.items():
            if type(k) is not str or not k.isascii() or len(k) > 96:
                raise ProtocolError("KEY_FORMAT")
            restricted(v, depth + 1)
        return
    raise ProtocolError("JSON_TYPE")


def canonical(value: Any) -> bytes:
    restricted(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def loads(raw: bytes | str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict:
        out = {}
        for k, v in items:
            if k in out:
                raise ProtocolError("DUPLICATE_JSON_KEY")
            out[k] = v
        return out
    try:
        obj = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("JSON_CONSTANT")))
        restricted(obj)
        return obj
    except (UnicodeError, json.JSONDecodeError, RecursionError) as e:
        raise ProtocolError("BAD_JSON") from e


def exact(obj: Any, keys: set[str]) -> None:
    if type(obj) is not dict or set(obj) != keys:
        raise ProtocolError("SCHEMA")


def identifier(x: Any) -> None:
    if type(x) is not str or not IDENT.fullmatch(x):
        raise ProtocolError("IDENTIFIER")


def integer(x: Any, low: int = 0, high: int = 2**63 - 1) -> None:
    if type(x) is not int or not low <= x <= high:
        raise ProtocolError("INTEGER")


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(key: Ed25519PrivateKey, signer: str, body: dict) -> dict:
    message = {"domain": DOMAIN, "signer": signer, "body": body}
    return {"signer": signer, "body": body, "sig": key.sign(canonical(message)).hex()}


def verify(env: Any, keys: dict[str, str], expected: str | None = None) -> dict:
    exact(env, {"signer", "body", "sig"})
    signer = env["signer"]
    if type(signer) is not str or signer not in keys or (expected is not None and signer != expected):
        raise ProtocolError("SIGNER")
    if type(env["body"]) is not dict or type(env["sig"]) is not str or len(env["sig"]) != 128:
        raise ProtocolError("SIGNATURE_FORMAT")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[signer])).verify(
            bytes.fromhex(env["sig"]), canonical({"domain": DOMAIN, "signer": signer, "body": env["body"]}))
    except (ValueError, InvalidSignature) as e:
        raise ProtocolError("BAD_SIGNATURE") from e
    return env["body"]


def payload_check(p: Any) -> None:
    exact(p, {"reference", "units"})
    identifier(p["reference"])
    integer(p["units"], 1, 100000)


def op_identity(r: dict) -> dict:
    return {k: r[k] for k in ("source", "destination", "intent", "scope", "payload_hash")}


def request_check(env: Any, keys: dict[str, str], destination: str, payload: dict | None = None) -> dict:
    r = verify(env, keys)
    exact(r, {"kind", "version", "source", "destination", "intent", "scope", "payload_hash", "issued_ms", "expires_ms", "nonce", "source_revision", "source_peer_revision", "previous"})
    if r["kind"] != "request" or type(r["version"]) is not int or r["version"] != 2:
        raise ProtocolError("REQUEST_KIND")
    for x in (r["source"], r["destination"], r["intent"], r["nonce"]):
        identifier(x)
    if env["signer"] != r["source"] or r["destination"] != destination or r["source"] == destination:
        raise ProtocolError("REQUEST_TARGET")
    if r["scope"] != SCOPE or not isinstance(r["payload_hash"], str) or not HEX64.fullmatch(r["payload_hash"]):
        raise ProtocolError("SCOPE_OR_DIGEST")
    for k in ("issued_ms", "expires_ms", "source_revision", "source_peer_revision"):
        integer(r[k])
    if not 0 < r["expires_ms"] - r["issued_ms"] <= MAX_TTL:
        raise ProtocolError("REQUEST_LIFETIME")
    if payload is not None:
        payload_check(payload)
        if digest(payload) != r["payload_hash"]:
            raise ProtocolError("PAYLOAD_BINDING")
    if type(r["previous"]) is not list or len(r["previous"]) > len(keys) - 2:
        raise ProtocolError("LINEAGE")
    seen = {destination}
    for env_prev in r["previous"]:
        p = verify(env_prev, keys)
        if p.get("kind") != "receipt" or p.get("status") != "CANCELLED" or p.get("effect_id") is not None:
            raise ProtocolError("LINEAGE_NOT_CANCELLED")
        old = p.get("destination")
        if old not in keys or old == r["source"] or old in seen or env_prev["signer"] != old:
            raise ProtocolError("LINEAGE_DESTINATION")
        expected = dict(op_identity(r), destination=old)
        if any(p.get(k) != v for k, v in expected.items()) or p.get("op_hash") != digest(expected):
            raise ProtocolError("LINEAGE_BINDING")
        receipt_check(env_prev, keys, expected)
        if p["at_ms"] > r["issued_ms"]:
            raise ProtocolError("LINEAGE_TIME")
        seen.add(old)
    return r


def receipt_check(env: Any, keys: dict[str, str], r: dict) -> dict:
    p = verify(env, keys, r["destination"])
    exact(p, {"kind", "node", "source", "destination", "intent", "scope", "payload_hash", "op_hash", "status", "effect_id", "at_ms", "request_hash", "permit_hash", "authorization_hash"})
    if p["kind"] != "receipt" or p["node"] != r["destination"] or p["status"] not in ("COMMITTED", "CANCELLED"):
        raise ProtocolError("RECEIPT_KIND")
    if any(p[k] != v for k, v in op_identity(r).items()) or p["op_hash"] != digest(op_identity(r)):
        raise ProtocolError("RECEIPT_BINDING")
    integer(p["at_ms"])
    if type(p["request_hash"]) is not str or not HEX64.fullmatch(p["request_hash"]):
        raise ProtocolError("RECEIPT_REQUEST_HASH")
    if p["status"] == "COMMITTED":
        identifier(p["effect_id"])
        if (type(p["permit_hash"]) is not str or not HEX64.fullmatch(p["permit_hash"])
                or type(p["authorization_hash"]) is not str or not HEX64.fullmatch(p["authorization_hash"])):
            raise ProtocolError("RECEIPT_PERMIT_HASH")
    elif p["effect_id"] is not None or p["permit_hash"] is not None or p["authorization_hash"] is not None:
        raise ProtocolError("CANCEL_EFFECT")
    return p


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TransportError("REDIRECT_FORBIDDEN")


def http_json(url: str, data: dict | None = None, token: str | None = None, timeout: float = 3.0) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, None if data is None else canonical(data), headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise TransportError("RESPONSE_TOO_LARGE")
        result = loads(raw)
        if type(result) is not dict:
            raise TransportError("RESPONSE_SCHEMA")
        return result
    except urllib.error.HTTPError as e:
        raise TransportError("HTTP_" + str(e.code)) from e
    except (urllib.error.URLError, OSError, http.client.HTTPException, ProtocolError) as e:
        raise TransportError(type(e).__name__) from e


def atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(canonical(value))
    os.replace(temp, path)


class Agent:
    def __init__(self, node: str, directory: Path, network: Path, fault_mode: bool = False):
        identifier(node)
        if node not in ("A", "B", "C"):
            raise ProtocolError("REFERENCE_NODE_ONLY")
        self.node, self.directory, self.network_path, self.fault_mode = node, directory, network, fault_mode
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            directory.chmod(0o700)
        key_file, token_file = directory / "signing.key", directory / "admin.token"
        if not key_file.exists():
            k = Ed25519PrivateKey.generate()
            with key_file.open("xb") as f:
                f.write(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        self.key = Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
        if not token_file.exists():
            token_file.write_text(secrets.token_hex(32), encoding="ascii")
        self.admin = token_file.read_text(encoding="ascii")
        if os.name == "posix":
            key_file.chmod(0o600)
            token_file.chmod(0o600)
        self.db_path = directory / "state.sqlite3"
        self.out_lock = threading.RLock()
        with contextlib.closing(self.connect()) as db:
            db.executescript("""
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS inbound(source TEXT NOT NULL, intent TEXT NOT NULL, op_hash TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(source,intent));
              CREATE TABLE IF NOT EXISTS deliveries(source TEXT NOT NULL, intent TEXT NOT NULL, effect_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, PRIMARY KEY(source,intent));
              CREATE TABLE IF NOT EXISTS outbound(intent TEXT PRIMARY KEY, record TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, entry TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, envelope TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, intent TEXT NOT NULL, request_hash TEXT NOT NULL, envelope TEXT NOT NULL);
            """)
        with self.tx() as db:
            if self.meta(db, "state") is not None and self.meta(db, "protocol_version") != 2:
                raise ProtocolError("INCOMPATIBLE_RUNTIME_DIRECTORY")
            if self.meta(db, "state") is None:
                self.put_meta(db, "protocol_version", 2)
                state = {"enabled": True, "revision": 1, "eligible": True, "peers": {}}
                self.put_meta(db, "state", state)
                self.put_meta(db, "faults", {})
                self.put_meta(db, "last_ms", 0)
                # Deliberately local, non-exported canaries; no hash of these fields leaves this database.
                self.put_meta(db, "private_policy", {"internal_customer": "PRIVATE-" + node + "-" + secrets.token_hex(12), "margin_floor": 37, "warehouse_layout": "LOCAL-ONLY", "max_units": {"A": 10000, "B": 200, "C": 1000}.get(node, 100)})
                self.log(db, "INIT", {"state": state})

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def meta(db, k):
        row = db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return None if row is None else loads(row[0])

    @staticmethod
    def put_meta(db, k, v):
        db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, canonical(v).decode()))

    def network(self) -> dict:
        net = loads(self.network_path.read_bytes())
        if set(net) != {"A", "B", "C"}:
            raise ProtocolError("REFERENCE_THREE_NODES_ONLY")
        if self.node not in net:
            raise ProtocolError("UNTRUSTED_LOCAL_ID")
        if net[self.node]["public_key"] != public_hex(self.key):
            raise ProtocolError("LOCAL_KEY_MISMATCH")
        for n, info in net.items():
            identifier(n)
            if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", info["url"]):
                raise ProtocolError("NON_LOOPBACK_ROUTE")
        return net

    def keys(self) -> dict[str, str]:
        return {n: v["public_key"] for n, v in self.network().items()}

    def remote(self, destination: str, endpoint: str, data: dict) -> dict:
        net = self.network()
        if destination not in net or destination == self.node:
            raise ProtocolError("UNKNOWN_DESTINATION")
        return http_json(net[destination]["url"] + endpoint, data)

    def envelope(self, body: dict) -> dict:
        return signed(self.key, self.node, body)

    def log(self, db, event: str, data: dict) -> dict:
        row = db.execute("SELECT seq,entry FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq = 1 if row is None else row["seq"] + 1
        prev = ZERO if row is None else digest(loads(row["entry"]))
        env = self.envelope({"kind": "audit", "node": self.node, "seq": seq, "prev": prev, "at_ms": now_ms(), "event": event, "data": data})
        db.execute("INSERT INTO audit VALUES(?,?)", (seq, canonical(env).decode()))
        return env

    def timestamp(self, db) -> int:
        n = now_ms()
        if n < self.meta(db, "last_ms"):
            raise ProtocolError("CLOCK_ROLLBACK", "HOLD")
        self.put_meta(db, "last_ms", n)
        return n

    @staticmethod
    def peer(state: dict, node: str) -> dict:
        return state["peers"].get(node, {"enabled": True, "revision": 1})

    def gate(self, db, peer: str) -> tuple[dict, dict]:
        s = self.meta(db, "state")
        p = self.peer(s, peer)
        if not s["enabled"] or not p["enabled"]:
            raise ProtocolError("REVOKED")
        if not s["eligible"]:
            raise ProtocolError("LOCAL_CONDITION_UNMET", "HOLD")
        return s, p

    def private_condition(self, db, payload: dict) -> None:
        # Synthetic per-company capacity rule; only its signed outcome is shared.
        # This is an issuer assertion, NOT a zero-knowledge proof of the private rule.
        private = self.meta(db, "private_policy")
        if payload["units"] > private["max_units"]:
            raise ProtocolError("LOCAL_CONDITION_UNMET", "HOLD")

    def decision(self, db, verdict: str, reason: str, op_hash: str | None = None) -> dict:
        env = self.envelope({"kind": "decision", "node": self.node, "verdict": verdict, "reason": reason, "op_hash": op_hash, "at_ms": now_ms()})
        self.log(db, "DENY", {"decision": env})
        return env

    def approve(self, data: dict) -> dict:
        exact(data, {"request", "payload"})
        r = request_check(data["request"], self.keys(), self.node, data["payload"])
        with self.tx() as db:
            t = self.timestamp(db)
            if not r["issued_ms"] <= t < r["expires_ms"]:
                return self.decision(db, "REJECT", "EXPIRED_OR_FUTURE", digest(op_identity(r)))
            try:
                s, p = self.gate(db, r["source"])
                self.private_condition(db, data["payload"])
            except ProtocolError as e:
                return self.decision(db, e.verdict, e.reason, digest(op_identity(r)))
            permit = self.envelope({"kind": "permit", "version": 2, "node": self.node,
                "request_hash": digest(data["request"]), "op_hash": digest(op_identity(r)),
                "destination_revision": s["revision"], "peer_revision": p["revision"],
                "issued_ms": t, "expires_ms": r["expires_ms"], "eligibility": True,
                "evidence_ref": secrets.token_hex(16)})
            self.log(db, "APPROVE", {"request": data["request"], "permit": permit})
            return permit

    @staticmethod
    def existing(db, r: dict) -> dict | None:
        row = db.execute("SELECT * FROM inbound WHERE source=? AND intent=?", (r["source"], r["intent"])).fetchone()
        if row is None:
            return None
        if row["op_hash"] != digest(op_identity(r)):
            raise ProtocolError("IDEMPOTENCY_CONFLICT")
        return loads(row["receipt"])

    def make_receipt(self, db, req: dict, status: str, permit: dict | None = None, checked_ms: int | None = None, authorization: dict | None = None) -> dict:
        r = req["body"]
        body = {"kind": "receipt", "node": self.node, **op_identity(r), "op_hash": digest(op_identity(r)),
                "status": status, "effect_id": secrets.token_hex(16) if status == "COMMITTED" else None,
                "at_ms": self.timestamp(db) if checked_ms is None else checked_ms, "request_hash": digest(req), "permit_hash": digest(permit) if permit is not None else None, "authorization_hash": digest(authorization) if authorization is not None else None}
        rec = self.envelope(body)
        db.execute("INSERT INTO inbound VALUES(?,?,?,?)", (r["source"], r["intent"], body["op_hash"], canonical(rec).decode()))
        return rec

    def take_fault(self, db, key: str) -> bool:
        faults = self.meta(db, "faults")
        val = faults.pop(key, False)
        self.put_meta(db, "faults", faults)
        return bool(val)

    def check_permit(self, env: dict, request: dict) -> dict:
        r = request["body"]
        permit = verify(env, self.keys(), self.node)
        exact(permit, {"kind", "version", "node", "request_hash", "op_hash", "destination_revision", "peer_revision", "issued_ms", "expires_ms", "eligibility", "evidence_ref"})
        if permit["kind"] != "permit" or type(permit["version"]) is not int or permit["version"] != 2 or permit["node"] != self.node or permit["eligibility"] is not True:
            raise ProtocolError("PERMIT_KIND")
        if permit["request_hash"] != digest(request) or permit["op_hash"] != digest(op_identity(r)):
            raise ProtocolError("PERMIT_BINDING")
        for k in ("issued_ms", "expires_ms", "destination_revision", "peer_revision"):
            integer(permit[k])
        identifier(permit["evidence_ref"])
        return permit

    def admission_check(self, db, r: dict, permit: dict, payload: dict, t: int):
        if not (r["issued_ms"] <= permit["issued_ms"] <= t < permit["expires_ms"] <= r["expires_ms"]):
            raise ProtocolError("EXPIRED_OR_FUTURE")
        s, peer = self.gate(db, r["source"])
        self.private_condition(db, payload)
        if permit["destination_revision"] != s["revision"] or permit["peer_revision"] != peer["revision"]:
            raise ProtocolError("STALE_APPROVAL")
        return s, peer

    def authorize(self, data: dict) -> dict:
        """Issue a challenge-bound admission, not a promise of global instant revocation.

        Does NOT take out_lock: transmit holds that lock while waiting for the
        receiver, which calls back here. DB transactions serialize issuance with
        source control changes. No network request is made inside this method.
        """
        exact(data, {"request", "permit", "challenge"})
        keys = self.keys()
        req = data["request"]
        r = request_check(req, keys, req.get("body", {}).get("destination"))
        if r["source"] != self.node:
            raise ProtocolError("AUTHORIZATION_SOURCE")
        dest = r["destination"]
        ch = verify(data["challenge"], keys, dest)
        exact(ch, {"kind", "version", "node", "source", "request_hash", "permit_hash", "nonce", "issued_ms", "expires_ms"})
        if ch["kind"] != "execution-challenge" or type(ch["version"]) is not int or ch["version"] != 2 or ch["node"] != dest or ch["source"] != self.node:
            raise ProtocolError("CHALLENGE_KIND")
        if ch["request_hash"] != digest(req) or ch["permit_hash"] != digest(data["permit"]):
            raise ProtocolError("CHALLENGE_BINDING")
        for k in ("issued_ms", "expires_ms"):
            integer(ch[k])
        identifier(ch["nonce"])
        if not 0 < ch["expires_ms"] - ch["issued_ms"] <= GRANT_TTL:
            raise ProtocolError("CHALLENGE_LIFETIME")
        # A signed receiver challenge is still insufficient without an exact,
        # durably dispatched local operation and its recorded receiver permit.
        with self.tx() as db:
            t = self.timestamp(db)
            if self.fault_mode and self.meta(db, "faults").get("authorization_unavailable", False):
                raise TransportError("INJECTED_AUTHORIZATION_UNAVAILABLE")
            try:
                s, pe = self.gate(db, dest)
                if s["revision"] != r["source_revision"] or pe["revision"] != r["source_peer_revision"]:
                    raise ProtocolError("SOURCE_CONDITION_CHANGED")
                out = self.get_out(db, r["intent"])
                if out is None or out["request"] != req or out["permit"] != data["permit"]:
                    raise ProtocolError("SOURCE_OPERATION_BINDING")
                if out["phase"] not in ("SENDING", "UNKNOWN"):
                    raise ProtocolError("SOURCE_NOT_DISPATCHED")
                self.private_condition(db, out["payload"])
                if not (r["issued_ms"] <= t < r["expires_ms"] and ch["issued_ms"] <= t < ch["expires_ms"]):
                    raise ProtocolError("SOURCE_AUTHORIZATION_EXPIRED")
            except ProtocolError as e:
                return self.decision(db, e.verdict, e.reason, digest(op_identity(r)))
            grant = self.envelope({"kind": "source-authorization", "version": 2,
                "source": self.node, "destination": dest, "request_hash": digest(req),
                "permit_hash": digest(data["permit"]), "challenge_hash": digest(data["challenge"]),
                "op_hash": digest(op_identity(r)), "source_revision": s["revision"],
                "source_peer_revision": pe["revision"], "issued_ms": t,
                "expires_ms": min(t + GRANT_TTL, ch["expires_ms"], r["expires_ms"]),
                "authorization_id": secrets.token_hex(16), "eligibility": True})
            db.execute("INSERT INTO grants VALUES(?,?,?,?)", (grant["body"]["authorization_id"], r["intent"], digest(req), canonical(grant).decode()))
            self.log(db, "OUT_AUTHORIZE", {"request_hash": digest(req), "challenge": data["challenge"], "authorization": grant,
                "gate": {"enabled": s["enabled"], "eligible": s["eligible"], "revision": s["revision"], "peer_enabled": pe["enabled"], "peer_revision": pe["revision"]}})
            return grant

    def execute(self, data: dict) -> dict | object:
        exact(data, {"request", "permit", "payload"})
        keys = self.keys()
        r = request_check(data["request"], keys, self.node, data["payload"])
        permit = self.check_permit(data["permit"], data["request"])
        with self.tx() as db:
            existing = self.existing(db, r)
            if existing is not None:
                self.log(db, "REPLAY", {"receipt": existing})
                return existing
            if self.fault_mode and self.take_fault(db, "drop_before_execute"):
                self.log(db, "FAULT", {"fault": "drop_before_execute", "op_hash": digest(op_identity(r))})
                return DROP
            t = self.timestamp(db)
            try:
                self.admission_check(db, r, permit, data["payload"], t)
            except ProtocolError as e:
                return self.decision(db, e.verdict, e.reason, digest(op_identity(r)))
            challenge = self.envelope({"kind": "execution-challenge", "version": 2, "node": self.node,
                "source": r["source"], "request_hash": digest(data["request"]), "permit_hash": digest(data["permit"]),
                "nonce": secrets.token_hex(16), "issued_ms": t, "expires_ms": min(t + GRANT_TTL, permit["expires_ms"])})
            db.execute("INSERT INTO challenges(id,envelope) VALUES(?,?)", (challenge["body"]["nonce"], canonical(challenge).decode()))
            self.log(db, "CHALLENGE", {"challenge": challenge})
        # Never hold a SQLite write transaction across a remote callback.
        # This prevents reciprocal A->B / B->A calls from deadlocking on DB locks.
        try:
            authorization = self.remote(r["source"], "/v1/authorize", {"request": data["request"], "permit": data["permit"], "challenge": challenge})
            g = verify(authorization, keys, r["source"])
        except (TransportError, ProtocolError) as e:
            with self.tx() as db:
                return self.decision(db, "HOLD", "SOURCE_AUTHORIZATION_UNAVAILABLE", digest(op_identity(r)))
        if self.fault_mode and g.get("kind") == "source-authorization":
            self.pause_before_commit(r)
        with self.tx() as db:
            existing = self.existing(db, r)
            if existing is not None:
                self.log(db, "REPLAY", {"receipt": existing})
                return existing
            if g.get("kind") == "decision":
                if g.get("op_hash") != digest(op_identity(r)) or g.get("verdict") not in ("HOLD", "REJECT"):
                    raise ProtocolError("SOURCE_DECISION_BINDING")
                return self.decision(db, g["verdict"], g["reason"] if g["reason"].startswith("SOURCE_") else "SOURCE_" + g["reason"], digest(op_identity(r)))
            exact(g, {"kind", "version", "source", "destination", "request_hash", "permit_hash", "challenge_hash", "op_hash", "source_revision", "source_peer_revision", "issued_ms", "expires_ms", "authorization_id", "eligibility"})
            if (g["kind"] != "source-authorization" or type(g["version"]) is not int or g["version"] != 2
                or g["source"] != r["source"] or g["destination"] != self.node or g["eligibility"] is not True
                or g["request_hash"] != digest(data["request"]) or g["permit_hash"] != digest(data["permit"])
                or g["challenge_hash"] != digest(challenge) or g["op_hash"] != digest(op_identity(r))
                or g["source_revision"] != r["source_revision"] or g["source_peer_revision"] != r["source_peer_revision"]):
                raise ProtocolError("SOURCE_AUTHORIZATION_BINDING")
            for k in ("issued_ms", "expires_ms", "source_revision", "source_peer_revision"):
                integer(g[k])
            identifier(g["authorization_id"])
            t = self.timestamp(db)
            ch = challenge["body"]
            row = db.execute("SELECT envelope,consumed FROM challenges WHERE id=?", (ch["nonce"],)).fetchone()
            if row is None or row["consumed"] or loads(row["envelope"]) != challenge:
                raise ProtocolError("CHALLENGE_NOT_CURRENT")
            if not (ch["issued_ms"] <= g["issued_ms"] <= t < g["expires_ms"] <= ch["expires_ms"] and 0 < g["expires_ms"] - g["issued_ms"] <= GRANT_TTL):
                return self.decision(db, "HOLD", "SOURCE_AUTHORIZATION_EXPIRED", digest(op_identity(r)))
            try:
                s, pe = self.admission_check(db, r, permit, data["payload"], t)
            except ProtocolError as e:
                return self.decision(db, e.verdict, e.reason, digest(op_identity(r)))
            observation = GateInput(s["enabled"], s["eligible"], pe["enabled"], s["revision"], permit["destination_revision"], pe["revision"], permit["peer_revision"],
                r["issued_ms"], permit["issued_ms"], t, permit["expires_ms"], r["expires_ms"], True, g["issued_ms"], g["expires_ms"])
            if gate_decision(observation) != 2:
                raise ProtocolError("ADMISSION_KERNEL_MISMATCH")
            db.execute("UPDATE challenges SET consumed=1 WHERE id=?", (ch["nonce"],))
            receipt = self.make_receipt(db, data["request"], "COMMITTED", data["permit"], checked_ms=t, authorization=authorization)
            db.execute("INSERT INTO deliveries VALUES(?,?,?,?)", (r["source"], r["intent"], receipt["body"]["effect_id"], canonical(data["payload"]).decode()))
            self.log(db, "COMMIT", {**data, "challenge": challenge, "authorization": authorization, "receipt": receipt,
                "observation": observation.to_dict(), "gate": {"enabled": s["enabled"], "revision": s["revision"], "eligible": s["eligible"], "peer_enabled": pe["enabled"], "peer_revision": pe["revision"]}})
            if self.fault_mode and self.take_fault(db, "crash_before_commit"):
                os._exit(70)
            drop = self.fault_mode and self.take_fault(db, "drop_after_commit")
            crash = self.fault_mode and self.take_fault(db, "crash_after_commit")
            if drop or crash:
                self.log(db, "FAULT", {"fault": "crash_after_commit" if crash else "drop_after_commit", "op_hash": digest(op_identity(r))})
        if crash:
            os._exit(71)
        return DROP if drop else receipt

    def pause_before_commit(self, request: dict) -> None:
        """Deterministic test barrier. Never enabled outside explicit --fault-mode.

        Polls without retaining a DB transaction. Automatically releases after
        five seconds; the normal source-admission expiry still applies.
        """
        with self.tx() as db:
            if not self.meta(db, "faults").get("pause_before_commit", False):
                return
            self.log(db, "FAULT", {"fault": "pause_before_commit", "op_hash": digest(op_identity(request))})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with self.tx() as db:
                paused = self.meta(db, "faults").get("pause_before_commit", False)
            if not paused:
                break
            time.sleep(0.01)

    def terminal_message(self, req: dict, action: str) -> dict:
        if action not in ("cancel", "status") or req["body"]["source"] != self.node:
            raise ProtocolError("TERMINAL_ACTION")
        t = now_ms()
        auth = self.envelope({"kind": "terminal-control", "action": action, "source": self.node,
            "destination": req["body"]["destination"], "request_hash": digest(req),
            "issued_ms": t, "expires_ms": t + MAX_TTL, "nonce": secrets.token_hex(16)})
        return {"request": req, "authorization": auth}

    def local_terminal_message(self, data: dict) -> dict:
        exact(data, {"intent", "action"})
        identifier(data["intent"])
        with self.out_lock:
            with self.tx() as db:
                out = self.get_out(db, data["intent"])
                if out is None:
                    raise ProtocolError("UNKNOWN_INTENT")
            return self.terminal_message(out["request"], data["action"])

    def terminal(self, data: dict, cancel: bool) -> dict:
        # An execution signature is NOT authorization to cancel that execution.
        exact(data, {"request", "authorization"})
        keys = self.keys()
        r = request_check(data["request"], keys, self.node)
        auth = verify(data["authorization"], keys, r["source"])
        exact(auth, {"kind", "action", "source", "destination", "request_hash", "issued_ms", "expires_ms", "nonce"})
        if auth["kind"] != "terminal-control" or auth["action"] != ("cancel" if cancel else "status"):
            raise ProtocolError("TERMINAL_ACTION")
        if auth["source"] != r["source"] or auth["destination"] != self.node or auth["request_hash"] != digest(data["request"]):
            raise ProtocolError("TERMINAL_BINDING")
        integer(auth["issued_ms"])
        integer(auth["expires_ms"])
        identifier(auth["nonce"])
        if not 0 < auth["expires_ms"] - auth["issued_ms"] <= MAX_TTL:
            raise ProtocolError("TERMINAL_LIFETIME")
        with self.tx() as db:
            t = self.timestamp(db)
            if not auth["issued_ms"] <= t < auth["expires_ms"]:
                raise ProtocolError("TERMINAL_EXPIRED_OR_FUTURE")
            if self.fault_mode and self.meta(db, "faults").get("terminal_unavailable", False):
                raise TransportError("INJECTED_TERMINAL_UNAVAILABLE")
            proof = {**data, "authorization_checked_ms": t}
            existing = self.existing(db, r)
            if existing is not None:
                self.log(db, "RECONCILE", {**proof, "receipt": existing})
                return existing
            if not cancel:
                return self.envelope({"kind": "status", "node": self.node, "status": "NOT_FOUND", "op_hash": digest(op_identity(r)), "at_ms": t})
            # Tombstone and execute use the SAME local transaction boundary.
            receipt = self.make_receipt(db, data["request"], "CANCELLED", checked_ms=t)
            self.log(db, "CANCEL", {**proof, "receipt": receipt})
            return receipt

    def control(self, data: dict) -> dict:
        if set(data) not in ({"enabled"}, {"eligible"}, {"peer", "enabled"}):
            raise ProtocolError("CONTROL_SCHEMA")
        if any(type(v) is not bool for k, v in data.items() if k != "peer"):
            raise ProtocolError("CONTROL_BOOLEAN")
        if "peer" in data and (data["peer"] not in self.keys() or data["peer"] == self.node):
            raise ProtocolError("CONTROL_PEER")
        with self.tx() as db:
            s = self.meta(db, "state")
            if "peer" in data:
                p = dict(self.peer(s, data["peer"]))
                p.update(enabled=data["enabled"], revision=p["revision"] + 1)
                s["peers"][data["peer"]] = p
            else:
                s.update(data)
                s["revision"] += 1
            self.put_meta(db, "state", s)
            event = self.log(db, "CONTROL", {"change": data, "state": s})
            unresolved = []
            for row in db.execute("SELECT DISTINCT intent,request_hash FROM grants ORDER BY intent,request_hash"):
                out = self.get_out(db, row["intent"])
                if out and out.get("receipt") is None and out["request"] and digest(out["request"]) == row["request_hash"]:
                    unresolved.append(row["intent"])
            return {"verdict": "PASS", "reason": "LOCAL_GATE_UPDATE_ACKNOWLEDGED", "state": s, "ack": event,
                "ack_scope": "LOCAL_STATE_AND_NEW_SOURCE_AUTHORIZATIONS", "unresolved_admissions": sorted(set(unresolved)),
                "remote_cancellation_confirmed": False}

    def fault(self, data: dict) -> dict:
        if not self.fault_mode:
            raise ProtocolError("FAULT_MODE_DISABLED")
        allowed = {"drop_before_execute", "drop_after_commit", "crash_after_commit", "terminal_unavailable", "source_crash_after_receive", "crash_before_commit", "source_crash_after_switch_record", "authorization_unavailable", "pause_before_commit"}
        if not set(data) <= allowed or any(type(v) is not bool for v in data.values()):
            raise ProtocolError("FAULT_SCHEMA")
        with self.tx() as db:
            f = self.meta(db, "faults")
            f.update(data)
            self.put_meta(db, "faults", f)
            self.log(db, "FAULT_CONFIG", data)
        return {"verdict": "PASS", "faults": f}

    @staticmethod
    def get_out(db, intent: str) -> dict | None:
        row = db.execute("SELECT record FROM outbound WHERE intent=?", (intent,)).fetchone()
        return None if row is None else loads(row[0])

    @staticmethod
    def put_out(db, record: dict) -> None:
        db.execute("INSERT INTO outbound VALUES(?,?) ON CONFLICT(intent) DO UPDATE SET record=excluded.record", (record["intent"], canonical(record).decode()))

    def new_request(self, db, intent, destination, payload, previous, ttl_ms) -> dict:
        s, pe = self.gate(db, destination)
        self.private_condition(db, payload)
        t = self.timestamp(db)
        return self.envelope({"kind": "request", "version": 2, "source": self.node, "destination": destination,
            "intent": intent, "scope": SCOPE, "payload_hash": digest(payload), "issued_ms": t, "expires_ms": t + ttl_ms,
            "nonce": secrets.token_hex(16), "source_revision": s["revision"], "source_peer_revision": pe["revision"], "previous": previous})

    @staticmethod
    def result(verdict: str, reason: str, receipt: dict | None = None, **extra) -> dict:
        result = {"verdict": verdict, "reason": reason, **extra}
        if receipt is not None:
            result["receipt"] = receipt
        return result

    def prepare(self, data: dict, switched: bool = False) -> dict:
        if not {"intent", "destination", "payload"} <= set(data) or not set(data) <= {"intent", "destination", "payload", "ttl_ms"}:
            raise ProtocolError("SUBMIT_SCHEMA")
        intent, dest, payload = data["intent"], data["destination"], data["payload"]
        identifier(intent)
        if dest not in self.keys() or dest == self.node:
            raise ProtocolError("UNKNOWN_DESTINATION")
        payload_check(payload)
        ttl = data.get("ttl_ms", MAX_TTL)
        integer(ttl, 100, MAX_TTL)
        with self.out_lock:
            with self.tx() as db:
                old = self.get_out(db, intent)
                if old is not None and (old["payload_hash"] != digest(payload) or old["destination"] != dest):
                    raise ProtocolError("OUTBOUND_IDEMPOTENCY_CONFLICT")
                if old is not None and not switched:
                    if old["phase"] == "COMMITTED":
                        return self.result("PASS", "ALREADY_COMMITTED", old["receipt"])
                    if old["phase"] in ("SENDING", "UNKNOWN"):
                        return self.result("HOLD", "RECONCILE_FIRST")
                    if old["phase"] == "CANCELLED":
                        return self.result("REJECT", "CANCELLED")
                    if old.get("permit"):
                        return self.result("PASS", "PREPARED", package={k: old[k] for k in ("request", "permit", "payload")})
                previous = [] if old is None else old["previous"]
                req = self.new_request(db, intent, dest, payload, previous, ttl)
                rec = {"intent": intent, "destination": dest, "payload": payload, "payload_hash": digest(payload), "previous": previous,
                    "request": req, "permit": None, "receipt": None, "phase": "PREPARING"}
                self.put_out(db, rec)
                self.log(db, "OUT_PREPARE", {"request": req})
            try:
                permit = self.remote(dest, "/v1/approve", {"request": req, "payload": payload})
                pb = verify(permit, self.keys(), dest)
                if pb.get("kind") == "decision":
                    with self.tx() as db:
                        rec["phase"] = "REJECTED"
                        self.put_out(db, rec)
                        self.log(db, "OUT_DENIED", {"decision": permit, "intent": intent, "stage": "APPROVAL"})
                    return self.result(pb["verdict"], pb["reason"])
                if pb.get("kind") != "permit" or pb.get("request_hash") != digest(req) or pb.get("op_hash") != digest(op_identity(req["body"])):
                    raise ProtocolError("REMOTE_APPROVAL_BINDING")
            except (TransportError, ProtocolError) as e:
                return self.result("HOLD", "APPROVAL_UNAVAILABLE", detail=str(e))
            with self.tx() as db:
                rec.update(permit=permit, phase="PREPARED")
                self.put_out(db, rec)
                self.log(db, "OUT_APPROVED", {"intent": intent, "permit": permit})
            return self.result("PASS", "PREPARED", package={k: rec[k] for k in ("request", "permit", "payload")})

    def accept_remote(self, intent: str, env: dict) -> dict:
        with self.tx() as db:
            out = self.get_out(db, intent)
            p = receipt_check(env, self.keys(), out["request"]["body"])
            if out.get("receipt") is not None and out["receipt"] != env:
                raise ProtocolError("TERMINAL_RESULT_CONFLICT")
            out.update(receipt=env, phase=p["status"])
            self.put_out(db, out)
            self.log(db, "OUT_RESULT", {"intent": intent, "receipt": env})
        return self.result("PASS" if p["status"] == "COMMITTED" else "REJECT", p["status"], env)

    def hold_out(self, intent: str, reason: str) -> dict:
        with self.tx() as db:
            out = self.get_out(db, intent)
            if out.get("receipt") is not None:
                status = out["receipt"]["body"]["status"]
                return self.result("PASS" if status == "COMMITTED" else "REJECT", "KNOWN_" + status, out["receipt"])
            out["phase"] = "UNKNOWN"
            self.put_out(db, out)
            self.log(db, "OUT_HOLD", {"intent": intent, "reason": reason})
        return self.result("HOLD", reason)

    def transmit(self, data: dict) -> dict:
        exact(data, {"intent"})
        identifier(data["intent"])
        intent = data["intent"]
        with self.out_lock:
            with self.tx() as db:
                out = self.get_out(db, intent)
                if out is None:
                    raise ProtocolError("UNKNOWN_INTENT")
                if out["phase"] == "COMMITTED":
                    return self.result("PASS", "ALREADY_COMMITTED", out["receipt"])
                if out["phase"] in ("UNKNOWN", "SENDING"):
                    return self.result("HOLD", "RECONCILE_FIRST")
                if out["phase"] != "PREPARED" or out["permit"] is None:
                    return self.result("REJECT", "NOT_PREPARED")
                s, pe = self.gate(db, out["destination"])
                if s["revision"] != out["request"]["body"]["source_revision"] or pe["revision"] != out["request"]["body"]["source_peer_revision"]:
                    raise ProtocolError("SOURCE_CONDITION_CHANGED")
                out["phase"] = "SENDING"
                self.put_out(db, out)
                self.log(db, "OUT_SEND", {"intent": intent, "request_hash": digest(out["request"]), "destination": out["destination"], "permit_hash": digest(out["permit"])})
            try:
                env = self.remote(out["destination"], "/v1/execute", {k: out[k] for k in ("request", "permit", "payload")})
                body = verify(env, self.keys(), out["destination"])
                if self.fault_mode:
                    with self.tx() as db:
                        crash = self.take_fault(db, "source_crash_after_receive")
                    if crash:
                        os._exit(72)
                if body.get("kind") == "receipt":
                    return self.accept_remote(intent, env)
                if body.get("kind") == "decision" and body.get("op_hash") == digest(op_identity(out["request"]["body"])):
                    with self.tx() as db:
                        # A denial concerns this attempt, not all packets already
                        # in flight. Only a signed terminal receipt settles K.
                        out["phase"] = "UNKNOWN"
                        self.put_out(db, out)
                        self.log(db, "OUT_DENIED", {"intent": intent, "decision": env, "stage": "EXECUTION"})
                    return self.result(body["verdict"], body["reason"])
                raise ProtocolError("INVALID_REMOTE_RESULT")
            except (TransportError, ProtocolError) as e:
                return self.hold_out(intent, "RESULT_UNKNOWN:" + str(e))

    def submit(self, data: dict) -> dict:
        with self.out_lock:
            result = self.prepare(data)
            if result["reason"] == "PREPARED":
                return self.transmit({"intent": data["intent"]})
            return result

    def reconcile(self, data: dict) -> dict:
        exact(data, {"intent"})
        with self.out_lock:
            with self.tx() as db:
                out = self.get_out(db, data["intent"])
                if out is None:
                    raise ProtocolError("UNKNOWN_INTENT")
                if out.get("receipt") is not None:
                    status = out["receipt"]["body"]["status"]
                    return self.result("PASS" if status == "COMMITTED" else "REJECT", "KNOWN_" + status, out["receipt"])
            try:
                env = self.remote(out["destination"], "/v1/status", self.terminal_message(out["request"], "status"))
                b = verify(env, self.keys(), out["destination"])
                if b.get("kind") == "receipt":
                    return self.accept_remote(data["intent"], env)
                # NOT_FOUND is an observation, NEVER a no-late-execution certificate.
                return self.hold_out(data["intent"], "NOT_FOUND_IS_NOT_CANCELLATION")
            except (TransportError, ProtocolError) as e:
                return self.hold_out(data["intent"], "RECONCILIATION_UNAVAILABLE:" + str(e))

    def switch(self, data: dict) -> dict:
        exact(data, {"intent", "destination"})
        intent, dest = data["intent"], data["destination"]
        identifier(intent)
        if dest not in self.keys() or dest == self.node:
            raise ProtocolError("UNKNOWN_DESTINATION")
        with self.out_lock:
            with self.tx() as db:
                out = self.get_out(db, intent)
                if out is None:
                    raise ProtocolError("UNKNOWN_INTENT")
                if out["phase"] == "COMMITTED":
                    return self.result("PASS", "ALREADY_COMMITTED_NO_SWITCH", out["receipt"])
                visited = {p["body"]["destination"] for p in out["previous"]} | {out["destination"]}
                if dest in visited:
                    raise ProtocolError("DESTINATION_ALREADY_VISITED")
            try:
                env = self.remote(out["destination"], "/v1/cancel", self.terminal_message(out["request"], "cancel"))
                r = receipt_check(env, self.keys(), out["request"]["body"])
            except (TransportError, ProtocolError) as e:
                return self.hold_out(intent, "SWITCH_REQUIRES_TERMINAL_PROOF:" + str(e))
            if r["status"] == "COMMITTED":
                result = self.accept_remote(intent, env)
                result["reason"] = "ALREADY_COMMITTED_NO_SWITCH"
                return result
            with self.tx() as db:
                previous = out["previous"] + [env]
                # Persist the new destination AND its bound request in the same source transaction.
                req = self.new_request(db, intent, dest, out["payload"], previous, MAX_TTL)
                out.update(destination=dest, request=req, phase="SWITCH_PENDING", previous=previous, permit=None, receipt=None)
                self.put_out(db, out)
                self.log(db, "OUT_SWITCH", {"intent": intent, "destination": dest, "cancellation": env})
                self.log(db, "OUT_PREPARE", {"request": req})
                crash = self.fault_mode and self.take_fault(db, "source_crash_after_switch_record")
            if crash:
                os._exit(73)
            result = self.prepare({"intent": intent, "destination": dest, "payload": out["payload"]}, switched=True)
            if result["reason"] == "PREPARED":
                result = self.transmit({"intent": intent})
                if result["verdict"] == "PASS":
                    result["reason"] = "SWITCHED_AFTER_CANCELLATION"
            return result

    def snapshot(self) -> dict:
        with self.tx() as db:
            inbound = [loads(r[0]) for r in db.execute("SELECT receipt FROM inbound ORDER BY source,intent")]
            outbound = [{"intent": r["intent"], "destination": r["destination"], "phase": r["phase"]} for r in (loads(x[0]) for x in db.execute("SELECT record FROM outbound ORDER BY intent"))]
            return {"node": self.node, "state": self.meta(db, "state"), "effects": db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], "inbound": inbound, "outbound": outbound}

    def export(self) -> dict:
        with self.tx() as db:
            events = [loads(x[0]) for x in db.execute("SELECT entry FROM audit ORDER BY seq")]
            receipts = [loads(x[0]) for x in db.execute("SELECT receipt FROM inbound ORDER BY source,intent")]
            state = self.meta(db, "state")
            checkpoint = self.envelope({"kind": "checkpoint", "node": self.node, "seq": len(events), "tail": digest(events[-1]) if events else ZERO,
                "receipts_hash": digest(receipts), "state_hash": digest(state), "effects": db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], "at_ms": now_ms()})
            return {"events": events, "receipts": receipts, "state": state, "checkpoint": checkpoint}

    def dispatch(self, path: str, data: dict, admin: bool) -> dict | object:
        if path.startswith("/local/") and not admin:
            raise ProtocolError("ADMIN_AUTH_REQUIRED")
        routes = {
            "/v1/approve": self.approve, "/v1/execute": self.execute, "/v1/authorize": self.authorize,
            "/v1/status": lambda d: self.terminal(d, False), "/v1/cancel": lambda d: self.terminal(d, True),
            "/local/prepare": self.prepare, "/local/transmit": self.transmit,
            "/local/submit": self.submit, "/local/switch": self.switch,
            "/local/reconcile": self.reconcile, "/local/control": self.control, "/local/fault": self.fault,
            "/local/terminal-message": self.local_terminal_message,
            "/local/snapshot": lambda d: self.snapshot(), "/local/export": lambda d: self.export(),
        }
        if path not in routes:
            raise ProtocolError("UNKNOWN_ROUTE")
        return routes[path](data)


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "VPI-CA/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, fmt, *args):
        pass

    def output(self, obj: dict, code: int = 200):
        raw = canonical(obj)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self):
        if self.path == "/health":
            self.output({"node": self.server.agent.node, "version": VERSION, "transport": "loopback-http-demo"})
        else:
            self.output({"verdict": "REJECT", "reason": "UNKNOWN_ROUTE"}, 404)

    def do_POST(self):
        a: Agent = self.server.agent
        try:
            if self.headers.get("Origin") is not None or self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise ProtocolError("BROWSER_ORIGIN_REJECTED")
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise ProtocolError("HTTP_FRAMING")
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ProtocolError("CONTENT_TYPE")
            try:
                size = int(self.headers["Content-Length"])
            except (TypeError, ValueError) as e:
                raise ProtocolError("CONTENT_LENGTH") from e
            if not 0 < size <= MAX_BODY:
                raise ProtocolError("BODY_SIZE")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ProtocolError("TRUNCATED_BODY")
            data = loads(raw)
            if type(data) is not dict:
                raise ProtocolError("OBJECT_REQUIRED")
            admin = hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + a.admin)
            result = a.dispatch(self.path, data, admin)
            if result is DROP:
                self.close_connection = True
                with contextlib.suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.output(result)
        except ProtocolError as e:
            self.output({"verdict": e.verdict, "reason": e.reason}, 403 if e.reason == "ADMIN_AUTH_REQUIRED" else 400)
        except TransportError:
            self.output({"verdict": "HOLD", "reason": "SERVICE_UNAVAILABLE"}, 503)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True
        except Exception as e:
            # Unexpected failures cannot produce a success response.
            print(f"[{a.node}] INTERNAL_ERROR {type(e).__name__}: {e}", flush=True)
            with contextlib.suppress(OSError):
                self.output({"verdict": "HOLD", "reason": "INTERNAL_ERROR"}, 500)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node", required=True)
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--network", type=Path, required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--fault-mode", action="store_true")
    args = p.parse_args()
    a = Agent(args.node, args.directory, args.network, args.fault_mode)
    ThreadingHTTPServer.request_queue_size = 64
    server = ThreadingHTTPServer(("127.0.0.1", args.port), AgentHandler)
    server.daemon_threads = True
    server.agent = a
    atomic_json(args.directory / "ready.json", {"node": args.node, "pid": os.getpid(), "port": server.server_port, "url": f"http://127.0.0.1:{server.server_port}", "public_key": public_hex(a.key)})
    print(f"{args.node} ready on 127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
