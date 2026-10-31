#!/usr/bin/env python3
"""Independent, offline evidence replay. Does NOT import assurance.py.

Validates mathematical consistency of disclosed records, not the honesty of a
signer, real-world identities, undisclosed histories, or private policy truth.
Pin keys AND checkpoints out-of-band for stronger provenance/completeness.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = "VPI-CYBER-ASSURANCE/2"
ZERO = "0" * 64
MAX_TTL = 30000
GRANT_TTL = 2000


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def validate_json(x: Any, depth: int = 0) -> None:
    require(depth <= 24, "JSON depth")
    if x is None or type(x) is bool:
        return
    if type(x) is int:
        require(-(2**63) < x < 2**63, "integer range")
    elif type(x) is str:
        require(x.isascii() and len(x) <= 8192, "string format")
    elif type(x) is list:
        require(len(x) <= 10000, "array size")
        for item in x:
            validate_json(item, depth + 1)
    elif type(x) is dict:
        for k, v in x.items():
            require(type(k) is str and k.isascii() and len(k) <= 96, "key format")
            validate_json(v, depth + 1)
    else:
        raise VerificationError("unsupported JSON value")


def canon(x: Any) -> bytes:
    validate_json(x)
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(x: Any) -> str:
    return hashlib.sha256(canon(x)).hexdigest()


def read_json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    require(path.stat().st_size <= 32 * 1024 * 1024, "file too large")
    def no_constant(value):
        raise VerificationError("non-finite JSON constant: " + value)
    obj = json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=no_constant)
    require(type(obj) is dict, "JSON object required")
    return obj


def load(path: Path) -> dict:
    obj = read_json(path)
    validate_json(obj)
    return obj


def load_sample(path: Path) -> dict:
    obj = read_json(path)
    require(obj.get("schema") == "vpi-cyber-sample/2", "sample schema")
    require({"schema", "report", "evidence", "anchors"} <= set(obj), "sample fields")
    require(set(obj) <= {"schema", "report", "evidence", "anchors", "validation"}, "unknown sample field")
    require(type(obj["evidence"]) is dict and type(obj["anchors"]) is dict, "sample evidence/anchors")
    validate_json(obj["evidence"])
    validate_json(obj["anchors"])
    return obj


def verify_file(path: Path, anchors_path: Path | None = None) -> dict:
    obj = read_json(path)
    bundled = obj.get("schema") == "vpi-cyber-sample/2"
    if bundled:
        obj = load_sample(path)
        evidence = obj["evidence"]
        anchors = load(anchors_path) if anchors_path else obj["anchors"]
    else:
        validate_json(obj)
        evidence = obj
        anchors = load(anchors_path) if anchors_path else None
    report = verify_bundle(evidence, anchors)
    if bundled and anchors_path is None:
        report["trust"] = "BUNDLED_KEYS_AND_CHECKPOINTS"
        report["anchor_note"] = "Bundled anchors are comparison values, not independent provenance."
    return report


def signature(env: dict, keys: dict, signer: str | None = None) -> dict:
    require(type(env) is dict and set(env) == {"body", "signer", "sig"}, "envelope schema")
    require(type(env["signer"]) is str and env["signer"] in keys, "unknown signer")
    require(signer is None or env["signer"] == signer, "wrong signer")
    require(type(env["body"]) is dict and type(env["sig"]) is str and len(env["sig"]) == 128, "signature format")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[env["signer"]])).verify(
            bytes.fromhex(env["sig"]), canon({"domain": DOMAIN, "signer": env["signer"], "body": env["body"]}))
    except Exception as e:
        raise VerificationError("invalid Ed25519 signature") from e
    return env["body"]


def ident(x):
    require(type(x) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", x) is not None, "identifier")


def nat(x):
    require(type(x) is int and 0 <= x < 2**63, "nonnegative integer")


def identity(r):
    return {k: r[k] for k in ("source", "destination", "intent", "scope", "payload_hash")}


def check_receipt(env, keys, r=None):
    p = signature(env, keys)
    require(set(p) == {"kind", "node", "source", "destination", "intent", "scope", "payload_hash", "op_hash", "status", "effect_id", "at_ms", "request_hash", "permit_hash", "authorization_hash"}, "receipt schema")
    require(p["kind"] == "receipt" and p["node"] == p["destination"] == env["signer"], "receipt issuer")
    require(p["source"] in keys and p["source"] != p["destination"], "receipt source")
    require(p["status"] in ("COMMITTED", "CANCELLED"), "receipt status")
    require(p["op_hash"] == sha(identity(p)), "operation binding")
    require(p["scope"] == "handoff.notice", "scope")
    nat(p["at_ms"])
    if r is not None:
        require(identity(p) == identity(r), "receipt request mismatch")
    if p["status"] == "CANCELLED":
        require(p["effect_id"] is None and p["permit_hash"] is None and p["authorization_hash"] is None, "cancelled effect")
    else:
        ident(p["effect_id"])
        require(type(p["permit_hash"]) is str and re.fullmatch(r"[0-9a-f]{64}", p["permit_hash"]) is not None, "missing approval hash")
        require(type(p["authorization_hash"]) is str and re.fullmatch(r"[0-9a-f]{64}", p["authorization_hash"]) is not None, "missing source authorization hash")
    return p


def check_request(env, keys):
    r = signature(env, keys)
    require(set(r) == {"kind", "version", "source", "destination", "intent", "scope", "payload_hash", "issued_ms", "expires_ms", "nonce", "source_revision", "source_peer_revision", "previous"}, "request schema")
    require(r["kind"] == "request" and type(r["version"]) is int and r["version"] == 2, "request version")
    require(env["signer"] == r["source"] and r["destination"] in keys and r["destination"] != r["source"], "request endpoints")
    for k in ("source", "destination", "intent", "nonce"):
        ident(r[k])
    for k in ("issued_ms", "expires_ms", "source_revision", "source_peer_revision"):
        nat(r[k])
    require(0 < r["expires_ms"] - r["issued_ms"] <= MAX_TTL, "request lifetime")
    require(r["scope"] == "handoff.notice" and type(r["payload_hash"]) is str and re.fullmatch(r"[0-9a-f]{64}", r["payload_hash"]) is not None, "scope/hash")
    require(type(r["previous"]) is list and len(r["previous"]) <= len(keys) - 2, "lineage size")
    seen = {r["destination"], r["source"]}
    for prev in r["previous"]:
        c = check_receipt(prev, keys)
        require(c["status"] == "CANCELLED", "switch without cancellation")
        require(c["destination"] not in seen, "revisited destination")
        require(identity(c) == dict(identity(r), destination=c["destination"]), "lineage binding")
        require(c["at_ms"] <= r["issued_ms"], "lineage chronology")
        seen.add(c["destination"])
    return r


def check_permit(env, keys, req):
    r = req["body"]
    p = signature(env, keys, r["destination"])
    require(set(p) == {"kind", "version", "node", "request_hash", "op_hash", "destination_revision", "peer_revision", "issued_ms", "expires_ms", "eligibility", "evidence_ref"}, "permit schema")
    require(p["kind"] == "permit" and type(p["version"]) is int and p["version"] == 2 and p["node"] == r["destination"], "permit identity")
    require(p["request_hash"] == sha(req) and p["op_hash"] == sha(identity(r)), "permit request binding")
    require(p["eligibility"] is True, "eligibility declaration")
    for k in ("destination_revision", "peer_revision", "issued_ms", "expires_ms"):
        nat(p[k])
    require(r["issued_ms"] <= p["issued_ms"] < p["expires_ms"] <= r["expires_ms"], "permit lifetime")
    return p


def check_challenge(env, keys):
    ch = signature(env, keys)
    require(set(ch) == {"kind", "version", "node", "source", "request_hash", "permit_hash", "nonce", "issued_ms", "expires_ms"}, "challenge schema")
    require(ch["kind"] == "execution-challenge" and type(ch["version"]) is int and ch["version"] == 2, "challenge version")
    require(env["signer"] == ch["node"] and ch["source"] in keys and ch["source"] != ch["node"], "challenge endpoints")
    ident(ch["nonce"])
    nat(ch["issued_ms"])
    nat(ch["expires_ms"])
    require(0 < ch["expires_ms"] - ch["issued_ms"] <= GRANT_TTL, "challenge lifetime")
    for k in ("request_hash", "permit_hash"):
        require(type(ch[k]) is str and re.fullmatch(r"[0-9a-f]{64}", ch[k]) is not None, "challenge digest")
    return ch


def check_authorization(env, challenge, keys, req):
    r = req["body"]
    ch = check_challenge(challenge, keys)
    g = signature(env, keys, r["source"])
    require(set(g) == {"kind", "version", "source", "destination", "request_hash", "permit_hash", "challenge_hash", "op_hash", "source_revision", "source_peer_revision", "issued_ms", "expires_ms", "authorization_id", "eligibility"}, "source authorization schema")
    require(g["kind"] == "source-authorization" and type(g["version"]) is int and g["version"] == 2 and g["eligibility"] is True, "source authorization kind")
    require(g["source"] == r["source"] == ch["source"] and g["destination"] == r["destination"] == ch["node"], "source authorization endpoints")
    require(g["request_hash"] == sha(req) == ch["request_hash"] and g["permit_hash"] == ch["permit_hash"] and g["challenge_hash"] == sha(challenge) and g["op_hash"] == sha(identity(r)), "source authorization binding")
    require(g["source_revision"] == r["source_revision"] and g["source_peer_revision"] == r["source_peer_revision"], "source authorization version binding")
    for k in ("issued_ms", "expires_ms", "source_revision", "source_peer_revision"):
        nat(g[k])
    ident(g["authorization_id"])
    require(ch["issued_ms"] <= g["issued_ms"] < g["expires_ms"] <= ch["expires_ms"] <= r["expires_ms"], "source authorization lifetime")
    require(0 < g["expires_ms"] - g["issued_ms"] <= GRANT_TTL, "source authorization TTL")
    return g


def observation_for(state, pe, r, p, g, t):
    # Independent extraction and decision; does not import the execution module.
    return {"enabled": state["enabled"], "eligible": state["eligible"], "peer_enabled": pe["enabled"],
        "revision": state["revision"], "permit_revision": p["destination_revision"], "peer_revision": pe["revision"], "permit_peer_revision": p["peer_revision"],
        "request_issued": r["issued_ms"], "permit_issued": p["issued_ms"], "now": t, "permit_expires": p["expires_ms"], "request_expires": r["expires_ms"],
        "source_verified": True, "source_issued": g["issued_ms"], "source_expires": g["expires_ms"]}


def observation_decision(o):
    if not (o["enabled"] and o["peer_enabled"]): return 0
    if o["revision"] != o["permit_revision"] or o["peer_revision"] != o["permit_peer_revision"]: return 0
    if not (o["request_issued"] <= o["permit_issued"] <= o["now"] < o["permit_expires"] <= o["request_expires"]): return 0
    if not (o["eligible"] and o["source_verified"] and o["source_issued"] <= o["now"] < o["source_expires"]): return 1
    return 2


def check_terminal_control(data, keys, action=None):
    req = data["request"]
    r = check_request(req, keys)
    auth = signature(data["authorization"], keys, r["source"])
    require(set(auth) == {"kind", "action", "source", "destination", "request_hash", "issued_ms", "expires_ms", "nonce"}, "terminal control schema")
    require(auth["kind"] == "terminal-control" and auth["action"] in ("cancel", "status"), "terminal control kind")
    require(action is None or auth["action"] == action, "terminal action binding")
    require(auth["source"] == r["source"] and auth["destination"] == r["destination"] and auth["request_hash"] == sha(req), "terminal request binding")
    for k in ("issued_ms", "expires_ms"):
        nat(auth[k])
    nat(data["authorization_checked_ms"])
    ident(auth["nonce"])
    require(0 < auth["expires_ms"] - auth["issued_ms"] <= MAX_TTL, "terminal control lifetime")
    require(auth["issued_ms"] <= data["authorization_checked_ms"] < auth["expires_ms"], "terminal control expired/future")
    return r


def check_state(s):
    require(type(s) is dict and set(s) == {"enabled", "revision", "eligible", "peers"}, "state schema")
    require(type(s["enabled"]) is bool and type(s["eligible"]) is bool, "state booleans")
    nat(s["revision"])
    require(s["revision"] >= 1 and type(s["peers"]) is dict, "state revision")
    for p in s["peers"].values():
        require(set(p) == {"enabled", "revision"} and type(p["enabled"]) is bool, "peer state")
        nat(p["revision"])


def peer(s, n):
    return s["peers"].get(n, {"enabled": True, "revision": 1})


def verify_bundle(bundle: dict, anchors: dict | None = None) -> dict:
    validate_json(bundle)
    require(type(bundle) is dict and bundle.get("schema") == "vpi-cyber-evidence/2", "bundle schema")
    keys, nodes = bundle["public_keys"], bundle["nodes"]
    require(type(keys) is dict and set(keys) == {"A", "B", "C"} and set(keys) == set(nodes), "expected exactly three nodes")
    require(len(set(keys.values())) == len(keys), "independent node keys required")
    for n, k in keys.items():
        ident(n)
        require(type(k) is str and re.fullmatch(r"[0-9a-f]{64}", k) is not None, "public key format")
    if anchors is not None:
        require(anchors.get("schema") == "vpi-cyber-anchors/2", "anchor schema")
        require(anchors["public_keys"] == keys and set(anchors["checkpoints"]) == set(nodes), "pinned keys/nodes mismatch")
    all_receipts, expectations, committed_ops = {}, [], set()
    source_prepares, commits = {}, []
    source_authorizations, receiver_challenges, required_challenges = {}, {}, []
    permit_records = {}
    used_grants, used_challenges = set(), set()
    totals = {"events": 0, "committed": 0, "cancelled": 0, "switches": 0, "replays": 0, "source_authorizations": 0, "challenges": 0}
    for node in sorted(nodes):
        data = nodes[node]
        require(set(data) == {"events", "receipts", "state", "checkpoint"}, "node export schema")
        cp = signature(data["checkpoint"], keys, node)
        require(cp["kind"] == "checkpoint" and cp["node"] == node, "checkpoint identity")
        if anchors is not None:
            require(anchors["checkpoints"][node] == sha(data["checkpoint"]), "pinned checkpoint mismatch")
        require(cp["seq"] == len(data["events"]) > 0, "checkpoint length")
        require(cp["receipts_hash"] == sha(data["receipts"]) and cp["state_hash"] == sha(data["state"]), "checkpoint exports")
        prev, state, terminal, effects = ZERO, None, {}, 0
        outbound = {}
        for i, env in enumerate(data["events"], 1):
            e = signature(env, keys, node)
            require(set(e) == {"kind", "node", "seq", "prev", "at_ms", "event", "data"}, "audit schema")
            require(e["kind"] == "audit" and e["node"] == node and e["seq"] == i and e["prev"] == prev, "audit chain/order")
            nat(e["at_ms"])
            nat(e["seq"])
            prev = sha(env)
            event, d = e["event"], e["data"]
            if event == "INIT":
                require(i == 1 and state is None, "unique genesis")
                require(d["state"] == {"enabled": True, "revision": 1, "eligible": True, "peers": {}}, "genesis state")
                state = copy.deepcopy(d["state"])
            else:
                require(state is not None, "missing genesis")
            if event == "CONTROL":
                change = d["change"]
                require(set(change) in ({"enabled"}, {"eligible"}, {"peer", "enabled"}), "control fields")
                require(all(type(v) is bool for k, v in change.items() if k != "peer"), "control values")
                expected = copy.deepcopy(state)
                if "peer" in change:
                    require(change["peer"] in keys and change["peer"] != node, "control peer")
                    p = dict(peer(state, change["peer"]))
                    p.update(enabled=change["enabled"], revision=p["revision"] + 1)
                    expected["peers"][change["peer"]] = p
                else:
                    expected.update(change)
                    expected["revision"] += 1
                require(d["state"] == expected, "control revision transition")
                check_state(expected)
                state = expected
            elif event == "APPROVE":
                r = check_request(d["request"], keys)
                p = check_permit(d["permit"], keys, d["request"])
                require(r["destination"] == node, "approval target")
                pe = peer(state, r["source"])
                require(state["enabled"] and state["eligible"] and pe["enabled"], "approval while disabled")
                require(p["destination_revision"] == state["revision"] and p["peer_revision"] == pe["revision"], "approval versions")
                permit_records[sha(d["permit"])] = (d["request"], d["permit"])
            elif event == "CHALLENGE":
                ch = check_challenge(d["challenge"], keys)
                require(ch["node"] == node and (node, ch["nonce"]) not in receiver_challenges, "unique receiver challenge")
                require(ch["permit_hash"] in permit_records, "challenge missing receiver approval")
                req, per = permit_records[ch["permit_hash"]]
                require(ch["request_hash"] == sha(req), "challenge approval binding")
                require(ch["expires_ms"] <= per["body"]["expires_ms"], "challenge after approval expiry")
                receiver_challenges[(node, ch["nonce"])] = d["challenge"]
                totals["challenges"] += 1
            elif event in ("COMMIT", "CANCEL"):
                r = check_request(d["request"], keys)
                require(r["destination"] == node, "effect target")
                rec = check_receipt(d["receipt"], keys, r)
                require(rec["request_hash"] == sha(d["request"]), "receipt request hash")
                key = (r["source"], r["intent"])
                require(key not in terminal, "multiple terminal transitions")
                terminal[key] = d["receipt"]
                if event == "COMMIT":
                    require(rec["status"] == "COMMITTED", "commit status")
                    p = check_permit(d["permit"], keys, d["request"])
                    require(rec["permit_hash"] == sha(d["permit"]), "receipt permit hash")
                    require(p["issued_ms"] <= rec["at_ms"] < p["expires_ms"], "commit outside approval lifetime")
                    require(set(d["payload"]) == {"reference", "units"}, "payload schema")
                    ident(d["payload"]["reference"])
                    require(type(d["payload"]["units"]) is int and 1 <= d["payload"]["units"] <= 100000, "payload units")
                    require(sha(d["payload"]) == r["payload_hash"], "payload hash")
                    pe = peer(state, r["source"])
                    gate = {"enabled": state["enabled"], "revision": state["revision"], "eligible": state["eligible"], "peer_enabled": pe["enabled"], "peer_revision": pe["revision"]}
                    require(d["gate"] == gate, "gate witness mismatch")
                    require(state["enabled"] and state["eligible"] and pe["enabled"], "commit after local revocation")
                    require(p["destination_revision"] == state["revision"] and p["peer_revision"] == pe["revision"], "stale approval executed")
                    require(key not in committed_ops, "cross-destination duplicate business effect")
                    committed_ops.add(key)
                    effects += 1
                    totals["committed"] += 1
                    g = check_authorization(d["authorization"], d["challenge"], keys, d["request"])
                    require(g["permit_hash"] == sha(d["permit"]) and rec["authorization_hash"] == sha(d["authorization"]), "commit source authorization binding")
                    require(g["issued_ms"] <= rec["at_ms"] < g["expires_ms"], "commit after source admission expiry")
                    observed = observation_for(state, pe, r, p, g, rec["at_ms"])
                    require(d["observation"] == observed and observation_decision(observed) == 2, "admission observation mismatch")
                    ck = (node, d["challenge"]["body"]["nonce"])
                    require(receiver_challenges.get(ck) == d["challenge"] and ck not in used_challenges, "unissued/reused receiver challenge")
                    gk = (r["source"], g["authorization_id"])
                    require(gk not in used_grants, "reused source authorization")
                    used_challenges.add(ck)
                    used_grants.add(gk)
                    commits.append((r["source"], sha(d["request"]), d["authorization"]))
                    for old in r["previous"]:
                        expectations.append((old["body"]["destination"], old))
                else:
                    require(rec["status"] == "CANCELLED", "cancel status")
                    check_terminal_control(d, keys, "cancel")
                    require(rec["at_ms"] == d["authorization_checked_ms"], "cancel authorization point")
                    totals["cancelled"] += 1
                all_receipts[(node, rec["source"], rec["intent"])] = d["receipt"]
            elif event in ("REPLAY", "RECONCILE"):
                r = check_receipt(d["receipt"], keys)
                require(terminal.get((r["source"], r["intent"])) == d["receipt"], "replayed nonexistent result")
                if event == "REPLAY":
                    totals["replays"] += 1
                else:
                    control_req = check_terminal_control(d, keys)
                    require(identity(control_req) == identity(r), "reconciliation control binding")
            elif event == "OUT_PREPARE":
                r = check_request(d["request"], keys)
                require(r["source"] == node and state["enabled"] and state["eligible"] and peer(state, r["destination"])["enabled"], "source authorization")
                require(r["source_revision"] == state["revision"] and r["source_peer_revision"] == peer(state, r["destination"])["revision"], "source revision")
                old = outbound.get(r["intent"])
                if old is not None:
                    require(old["phase"] in ("PREPARING", "REJECTED", "SWITCH_PENDING"), "new preparation over unresolved operation")
                    require(old["payload_hash"] == r["payload_hash"] and old["destination"] == r["destination"] and old["previous"] == r["previous"], "outbound lineage changed")
                else:
                    require(not r["previous"], "first source preparation cannot invent lineage")
                outbound[r["intent"]] = {"phase": "PREPARING", "request": d["request"], "permit_hash": None, "destination": r["destination"], "payload_hash": r["payload_hash"], "previous": r["previous"]}
                source_prepares[(node, sha(d["request"]))] = r
            elif event == "OUT_RESULT":
                r = check_receipt(d["receipt"], keys)
                require(r["source"] == node and r["intent"] == d["intent"], "outbound receipt identity")
                expectations.append((r["destination"], d["receipt"]))
                out = outbound.get(r["intent"])
                require(out is not None and out["destination"] == r["destination"] and out["payload_hash"] == r["payload_hash"], "outbound result without current operation")
                out["phase"] = r["status"]
            elif event == "OUT_SWITCH":
                r = check_receipt(d["cancellation"], keys)
                require(r["status"] == "CANCELLED" and r["source"] == node and r["intent"] == d["intent"] and r["destination"] != d["destination"], "switch proof")
                expectations.append((r["destination"], d["cancellation"]))
                out = outbound.get(r["intent"])
                require(out is not None and out["phase"] != "COMMITTED" and out["destination"] == r["destination"] and out["payload_hash"] == r["payload_hash"], "switch source state")
                require(d["destination"] not in {node, out["destination"]} | {x["body"]["destination"] for x in out["previous"]}, "switch revisits destination")
                out.update(phase="SWITCH_PENDING", destination=d["destination"], previous=out["previous"] + [d["cancellation"]])
                totals["switches"] += 1
            elif event in ("DENY", "OUT_DENIED"):
                b = signature(d["decision"], keys)
                require(b["kind"] == "decision" and b["verdict"] in ("HOLD", "REJECT"), "negative decision")
                if event == "DENY":
                    require(d["decision"]["signer"] == node, "deny signer")
                else:
                    out = outbound.get(d["intent"])
                    require(out is not None and d["decision"]["signer"] == out["destination"], "outbound denial binding")
                    require(d.get("stage") in ("APPROVAL", "EXECUTION"), "denial stage")
                    require(out["phase"] in (("PREPARING",) if d["stage"] == "APPROVAL" else ("SENDING", "UNKNOWN")), "denial phase")
                    out["phase"] = "REJECTED" if d["stage"] == "APPROVAL" else "UNKNOWN"
            elif event == "OUT_APPROVED":
                b = signature(d["permit"], keys)
                req = source_prepares.get((node, b.get("request_hash")))
                require(req is not None and b.get("node") == req["destination"] and b.get("op_hash") == sha(identity(req)), "outbound approval origin")
                out = outbound.get(d["intent"])
                require(out is not None and sha(out["request"]) == b["request_hash"] and out["phase"] == "PREPARING", "outbound approval phase")
                check_permit(d["permit"], keys, out["request"])
                out.update(phase="PREPARED", permit_hash=sha(d["permit"]))
            elif event == "OUT_SEND":
                r = source_prepares.get((node, d["request_hash"]))
                require(r is not None and r["intent"] == d["intent"] and r["destination"] == d["destination"], "outbound dispatch binding")
                require(state["enabled"] and state["eligible"] and peer(state, r["destination"])["enabled"] and state["revision"] == r["source_revision"] and peer(state, r["destination"])["revision"] == r["source_peer_revision"], "disabled source dispatch")
                out = outbound.get(r["intent"])
                require(out is not None and out["phase"] == "PREPARED" and sha(out["request"]) == d["request_hash"] and out["permit_hash"] == d["permit_hash"], "dispatch not currently prepared")
                out["phase"] = "SENDING"
            elif event == "OUT_AUTHORIZE":
                r = source_prepares.get((node, d["request_hash"]))
                require(r is not None, "source admission without preparation")
                out = outbound.get(r["intent"])
                require(out is not None and out["phase"] in ("SENDING", "UNKNOWN") and sha(out["request"]) == d["request_hash"], "source admission without dispatch")
                g = check_authorization(d["authorization"], d["challenge"], keys, out["request"])
                require(g["source"] == node and g["permit_hash"] == out["permit_hash"], "source admission permit")
                pe = peer(state, r["destination"])
                expected_gate = {"enabled": state["enabled"], "eligible": state["eligible"], "revision": state["revision"], "peer_enabled": pe["enabled"], "peer_revision": pe["revision"]}
                require(d["gate"] == expected_gate and state["enabled"] and state["eligible"] and pe["enabled"], "source admission after revocation")
                require(g["source_revision"] == state["revision"] and g["source_peer_revision"] == pe["revision"], "stale source admission")
                key = (node, g["authorization_id"])
                require(key not in source_authorizations, "duplicate source admission id")
                source_authorizations[key] = d["authorization"]
                required_challenges.append(d["challenge"])
                totals["source_authorizations"] += 1
            elif event == "OUT_HOLD":
                out = outbound.get(d["intent"])
                require(out is not None and out["phase"] not in ("COMMITTED", "CANCELLED"), "hold over terminal operation")
                out["phase"] = "UNKNOWN"
            elif event in ("INIT", "FAULT", "FAULT_CONFIG"):
                pass
            else:
                raise VerificationError("unknown audit event: " + str(event))
            totals["events"] += 1
        require(cp["tail"] == prev, "checkpoint tail")
        require(cp["effects"] == effects, "effect count")
        require(state == data["state"], "final state")
        ordered = [terminal[k] for k in sorted(terminal)]
        require(ordered == data["receipts"], "terminal receipt completeness")
    for node, env in expectations:
        r = env["body"]
        require(all_receipts.get((node, r["source"], r["intent"])) == env, "cross-company receipt not found/mismatch")
    for source, req_hash, grant in commits:
        require((source, req_hash) in source_prepares, "destination commit missing source preparation")
        require(source_authorizations.get((source, grant["body"]["authorization_id"])) == grant, "destination commit missing source execution authorization log")
    for ch in required_challenges:
        require(receiver_challenges.get((ch["body"]["node"], ch["body"]["nonce"])) == ch, "source admission missing receiver challenge log")
    return {"status": "CONSISTENT", "nodes": len(nodes), **totals,
        "trust": "PINNED_KEYS_AND_CHECKPOINTS" if anchors is not None else "SELF_CONTAINED_KEYS_ONLY",
        "scope": "Disclosed signed histories; source admission and dispatch; receiver challenges; local gate transitions; bounded protocol rules. Not private-policy truth or deployment-wide security.",
        "run_metadata_verified": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("evidence", type=Path)
    p.add_argument("--anchors", type=Path)
    args = p.parse_args()
    try:
        report = verify_file(args.evidence, args.anchors)
        print(json.dumps(report, indent=2))
    except Exception as e:
        print(json.dumps({"status": "INVALID", "reason": str(e)}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
