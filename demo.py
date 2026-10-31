#!/usr/bin/env python3
"""Run the complete, local, three-process experiment; optionally open a dashboard."""
from __future__ import annotations
import argparse
import concurrent.futures
import contextlib
import copy
import hashlib
import hmac
import http.client
import json
import os
import platform
import secrets
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import cryptography
import assurance as a
import verifier

ROOT = Path(__file__).resolve().parent


class Cluster:
    """The harness knows admin tokens; peer processes never share private keys/DBs."""
    def __init__(self, directory: Path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.network_path = self.directory / "network.json"
        self.processes, self.streams, self.info = {}, {}, {}
        self.tokens = {}

    def start(self):
        try:
            for n in "ABC":
                self.start_node(n)
            self.save_network()
            return self
        except BaseException:
            self.stop()
            raise

    def save_network(self):
        a.atomic_json(self.network_path, {n: {k: self.info[n][k] for k in ("url", "public_key")} for n in self.info})

    def start_node(self, n):
        d = self.directory / n
        d.mkdir(exist_ok=True)
        ready = d / "ready.json"
        ready.unlink(missing_ok=True)
        port = self.info.get(n, {}).get("port", 0)
        stream = (d / "process.log").open("ab")
        command = [sys.executable, str(ROOT / "assurance.py"), "--node", n, "--directory", str(d), "--network", str(self.network_path), "--port", str(port), "--fault-mode"]
        self.processes[n] = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        self.streams[n] = stream
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.processes[n].poll() is not None:
                raise RuntimeError(f"{n} failed to start: {(d / 'process.log').read_text(errors='replace')}")
            if ready.exists():
                self.info[n] = a.loads(ready.read_bytes())
                self.tokens[n] = (d / "admin.token").read_text(encoding="ascii")
                return
            time.sleep(0.03)
        raise RuntimeError(f"{n} readiness timeout")

    def stop_node(self, n):
        p = self.processes.get(n)
        if p:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if n in self.streams:
            self.streams.pop(n).close()

    def restart(self, n):
        self.stop_node(n)
        self.start_node(n)
        self.save_network()

    def stop(self):
        for n in list(self.processes):
            self.stop_node(n)

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.stop()

    def local(self, n, action, data=None):
        return a.http_json(self.info[n]["url"] + "/local/" + action, data or {}, self.tokens[n], timeout=12)

    def remote(self, n, action, data):
        return a.http_json(self.info[n]["url"] + "/v1/" + action, data, timeout=8)

    def raw(self, n, path, data=None, raw=None, token=None, headers=None):
        url = urllib.parse.urlparse(self.info[n]["url"])
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=8)
        body = raw if raw is not None else a.canonical(data or {})
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        h.update(headers or {})
        try:
            conn.request("POST", path, body, h)
            response = conn.getresponse()
            return response.status, a.loads(response.read())
        finally:
            conn.close()

    def terminal_message(self, req, action):
        msg = self.local(req["body"]["source"], "terminal-message", {"intent": req["body"]["intent"], "action": action})
        if msg["request"] != req:
            raise AssertionError("terminal authorization does not match requested attempt")
        return msg

    def effects(self, n):
        return self.local(n, "snapshot")["effects"]

    def snapshots(self):
        return {n: self.local(n, "snapshot") for n in "ABC"}

    def bundle(self):
        return {"schema": "vpi-cyber-evidence/2", "public_keys": {n: self.info[n]["public_key"] for n in "ABC"},
                "nodes": {n: self.local(n, "export") for n in "ABC"}}


def anchors_for(bundle):
    return {"schema": "vpi-cyber-anchors/2", "public_keys": bundle["public_keys"],
            "checkpoints": {n: a.digest(v["checkpoint"]) for n, v in bundle["nodes"].items()}}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def command(intent, dest="B", units=1, ttl=None):
    d = {"intent": intent, "destination": dest, "payload": {"reference": "SYNTH-" + intent, "units": units}}
    if ttl is not None:
        d["ttl_ms"] = ttl
    return d


def wait_for_pause(c, node, request, timeout=3.0):
    wanted = a.digest(a.op_identity(request["body"]))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = c.local(node, "export")["events"]
        if any(e["body"]["event"] == "FAULT" and e["body"]["data"].get("fault") == "pause_before_commit"
               and e["body"]["data"].get("op_hash") == wanted for e in events):
            return
        time.sleep(.01)
    raise AssertionError("receiver did not reach explicit pre-commit barrier")


def console_line(message: str) -> None:
    """Print progress without failing on limited Windows console encodings.

    Full Unicode scenario names remain unchanged in the UTF-8 evidence/report.
    Only the console rendering falls back to readable ASCII escape sequences.
    """
    encoding = getattr(sys.stdout, "encoding", None)
    if encoding:
        try:
            message.encode(encoding)
        except UnicodeEncodeError:
            message = message.encode(encoding, errors="backslashreplace").decode(encoding)
    print(message, flush=True)


def scenario_suite(c: Cluster, progress=None):
    cases = []

    def run(code, label, function):
        start = time.perf_counter()
        try:
            details = function() or {}
            row = {"id": code, "name": label, "passed": True, "details": details}
        except Exception as e:
            row = {"id": code, "name": label, "passed": False, "error": f"{type(e).__name__}: {e}"}
        row["elapsed_ms"] = int((time.perf_counter() - start) * 1000)
        cases.append(row)
        console_line(f"{'OK  ' if row['passed'] else 'FAIL'} {code} {label}")
        if not row["passed"]:
            console_line(row["error"])
        if progress:
            progress(copy.deepcopy(cases))

    def normal():
        before = c.effects("B")
        r = c.local("A", "submit", command("normal"))
        check(r["verdict"] == "PASS" and c.effects("B") == before + 1, "normal effect not committed")
        return {"verdict": "PASS", "route": "A-B", "effects_added": 1}
    run("D01", "正常接続・最小情報の実HTTP転送", normal)

    def no_auth():
        before = c.effects("B")
        code, _ = c.raw("B", "/v1/execute", {"payload": {"reference": "BAD", "units": 1}})
        check(code == 400 and c.effects("B") == before, "unsigned request passed")
        return {"verdict": "REJECT", "effects_added": 0}
    run("D02", "許可情報なしのゲート通過を拒否", no_auth)

    def payload_tamper():
        pkg = c.local("A", "prepare", command("payload-tamper"))["package"]
        pkg["payload"]["units"] = 999
        code, r = c.raw("B", "/v1/execute", pkg)
        check(code == 400 and r["reason"] == "PAYLOAD_BINDING", "payload tampering passed")
        return {"verdict": "REJECT", "reason": r["reason"]}
    run("D03", "承認後の交換データ改変を拒否", payload_tamper)

    def target_tamper():
        pkg = c.local("A", "prepare", command("target-tamper"))["package"]
        code, r = c.raw("C", "/v1/execute", pkg)
        check(code == 400 and r["reason"] == "REQUEST_TARGET", "target substitution passed")
        return {"verdict": "REJECT", "reason": r["reason"]}
    run("D04", "B向け承認のCへの流用を拒否", target_tamper)

    def scope_tamper():
        pkg = c.local("A", "prepare", command("scope-tamper"))["package"]
        pkg["request"]["body"]["scope"] = "admin.delete"
        code, r = c.raw("B", "/v1/execute", pkg)
        check(code == 400 and r["reason"] == "BAD_SIGNATURE", "scope substitution passed")
        return {"verdict": "REJECT", "reason": r["reason"]}
    run("D05", "操作範囲の書換えを拒否", scope_tamper)

    def revoke_switch():
        pkg = c.local("A", "prepare", command("revoke-switch"))["package"]
        c.local("B", "control", {"enabled": False})
        c.local("A", "control", {"peer": "B", "enabled": False})
        try:
            r = c.remote("B", "execute", pkg)
            check(r["body"]["reason"] == "REVOKED", "old B authorization passed")
            result = c.local("A", "switch", {"intent": "revoke-switch", "destination": "C"})
            check(result["reason"] == "SWITCHED_AFTER_CANCELLATION", "safe switch did not execute")
            check(result["receipt"]["body"]["destination"] == "C", "wrong switch target")
        finally:
            c.local("B", "control", {"enabled": True})
            c.local("A", "control", {"peer": "B", "enabled": True})
        return {"verdict": "PASS", "route": "A-B -> A-C", "old_destination": "CANCELLED"}
    run("D06", "B失効・未実行確定・Cを再承認して切替え", revoke_switch)

    def unaffected():
        c.local("A", "prepare", command("unaffected", "C"))
        c.local("B", "control", {"enabled": False})
        c.local("A", "control", {"peer": "B", "enabled": False})
        try:
            r = c.local("A", "transmit", {"intent": "unaffected"})
            check(r["verdict"] == "PASS", "unrelated A-C link was stopped")
        finally:
            c.local("B", "control", {"enabled": True})
            c.local("A", "control", {"peer": "B", "enabled": True})
        return {"verdict": "PASS", "route": "A-C", "prior_approval_preserved": True}
    run("D07", "B失効でも無関係なA-C接続は維持", unaffected)

    def policy_hold():
        before = c.effects("B")
        c.local("B", "control", {"eligible": False})
        try:
            r = c.local("A", "submit", command("private-policy"))
            check(r["verdict"] == "HOLD" and c.effects("B") == before, "local eligibility was bypassed")
        finally:
            c.local("B", "control", {"eligible": True})
        return {"verdict": "HOLD", "private_details_shared": False}
    run("D08", "社内条件未成立は詳細を出さず保留", policy_hold)

    def expired():
        pkg = c.local("A", "prepare", command("expired", ttl=250))["package"]
        time.sleep(0.3)
        r = c.remote("B", "execute", pkg)
        check(r["body"]["reason"] == "EXPIRED_OR_FUTURE", "expired permit accepted")
        return {"verdict": "REJECT", "reason": "EXPIRED_OR_FUTURE"}
    run("D09", "期限切れ承認を拒否", expired)

    def version_change():
        pkg = c.local("A", "prepare", command("epoch-change"))["package"]
        c.local("B", "control", {"enabled": False})
        c.local("B", "control", {"enabled": True})
        r = c.remote("B", "execute", pkg)
        check(r["body"]["reason"] == "STALE_APPROVAL", "old permit revived after re-enable")
        return {"verdict": "REJECT", "reason": "STALE_APPROVAL"}
    run("D10", "失効後の再有効化でも古い承認は復活しない", version_change)

    def lost_response():
        before = c.effects("B")
        pkg = c.local("A", "prepare", command("lost-response"))["package"]
        c.local("B", "fault", {"drop_after_commit": True})
        r = c.local("A", "transmit", {"intent": "lost-response"})
        check(r["verdict"] == "HOLD" and c.effects("B") == before + 1, "response loss not reproduced")
        resolved = c.local("A", "reconcile", {"intent": "lost-response"})
        replay = c.remote("B", "execute", pkg)
        check(resolved["verdict"] == "PASS" and replay == resolved["receipt"] and c.effects("B") == before + 1, "reconcile/replay duplicated effect")
        return {"verdict": "HOLD -> PASS", "effects_added": 1, "identical_receipt": True}
    run("D11", "実行直後の応答消失・結果照合・再送", lost_response)

    def unknown_switch():
        pkg = c.local("A", "prepare", command("unknown-switch"))["package"]
        before_b, before_c = c.effects("B"), c.effects("C")
        c.local("B", "fault", {"drop_before_execute": True, "terminal_unavailable": True})
        check(c.local("A", "transmit", {"intent": "unknown-switch"})["verdict"] == "HOLD", "missing drop")
        try:
            r = c.local("A", "switch", {"intent": "unknown-switch", "destination": "C"})
            check(r["verdict"] == "HOLD" and c.effects("C") == before_c, "unsafe failover occurred")
        finally:
            c.local("B", "fault", {"terminal_unavailable": False})
        # An absence query is explicitly not used as a terminal cancellation.
        r = c.local("A", "reconcile", {"intent": "unknown-switch"})
        check(r["verdict"] == "HOLD", "NOT_FOUND incorrectly treated as terminal")
        r = c.local("A", "switch", {"intent": "unknown-switch", "destination": "C"})
        delayed = c.remote("B", "execute", pkg)
        check(r["verdict"] == "PASS" and delayed["body"]["status"] == "CANCELLED", "late packet escaped tombstone")
        check(c.effects("B") == before_b and c.effects("C") == before_c + 1, "duplicate after failover")
        return {"verdict": "HOLD -> PASS", "late_old_request": "CANCELLED", "effects_added": 1}
    run("D12", "結果不明時は切替え保留・取消確定後だけ再開", unknown_switch)

    def committed_no_switch():
        before_c = c.effects("C")
        c.local("B", "fault", {"drop_after_commit": True})
        check(c.local("A", "submit", command("committed-no-switch"))["verdict"] == "HOLD", "missing loss")
        r = c.local("A", "switch", {"intent": "committed-no-switch", "destination": "C"})
        check(r["reason"] == "ALREADY_COMMITTED_NO_SWITCH" and c.effects("C") == before_c, "committed work repeated at C")
        return {"verdict": "PASS", "switch": "SUPPRESSED_ALREADY_COMMITTED"}
    run("D13", "旧接続先で実行済みならCへの再実行を抑止", committed_no_switch)

    def concurrent_replay():
        pkg = c.local("A", "prepare", command("concurrent"))["package"]
        c.local("B", "fault", {"drop_before_execute": True})
        check(c.local("A", "transmit", {"intent": "concurrent"})["verdict"] == "HOLD", "dispatch was not durably recorded")
        before = c.effects("B")
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            rs = list(pool.map(lambda _: c.remote("B", "execute", pkg), range(12)))
        check(len({a.digest(x) for x in rs}) == 1 and c.effects("B") == before + 1, "concurrent duplicate effect")
        c.local("A", "reconcile", {"intent": "concurrent"})
        return {"verdict": "PASS", "concurrent_requests": 12, "effects_added": 1}
    run("D14", "12件の同時再送を1回のDB効果に閉じる", concurrent_replay)

    def receiver_restart():
        before = c.effects("B")
        c.local("B", "fault", {"crash_after_commit": True})
        r = c.local("A", "submit", command("receiver-restart"))
        check(r["verdict"] == "HOLD", "receiver did not crash after commit")
        c.processes["B"].wait(timeout=5)
        check(c.processes["B"].returncode == 71, "wrong receiver crash point")
        c.restart("B")
        r = c.local("A", "reconcile", {"intent": "receiver-restart"})
        check(r["verdict"] == "PASS" and c.effects("B") == before + 1, "receiver restart lost/duplicated result")
        return {"verdict": "HOLD -> PASS", "actual_process_exit": 71, "durable_effects_added": 1}
    run("D15", "受信側をコミット直後に強制終了・再起動", receiver_restart)

    def sender_restart():
        before = c.effects("B")
        c.local("A", "fault", {"source_crash_after_receive": True})
        try:
            c.local("A", "submit", command("sender-restart"))
            raise AssertionError("sender did not crash")
        except a.TransportError:
            pass
        c.processes["A"].wait(timeout=5)
        check(c.processes["A"].returncode == 72, "wrong sender crash point")
        c.restart("A")
        check(c.local("A", "submit", command("sender-restart"))["verdict"] == "HOLD", "restart reissued unknown work")
        r = c.local("A", "reconcile", {"intent": "sender-restart"})
        check(r["verdict"] == "PASS" and c.effects("B") == before + 1, "source restart failed reconciliation")
        return {"verdict": "HOLD -> PASS", "actual_process_exit": 72, "durable_effects_added": 1}
    run("D16", "送信側を応答受信直後に強制終了・再照合", sender_restart)

    def conflict():
        code, r = c.raw("A", "/local/submit", command("normal", units=2), token=c.tokens["A"])
        check(code == 400 and r["reason"] == "OUTBOUND_IDEMPOTENCY_CONFLICT", "idempotency key reused with different payload")
        return {"verdict": "REJECT", "reason": r["reason"]}
    run("D17", "同じ操作IDへの異なる内容の上書きを拒否", conflict)

    def cancellation_race():
        pkg = c.local("A", "prepare", command("cancel-race"))["package"]
        before = c.effects("B")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(c.remote, "B", "execute", pkg)
            f2 = pool.submit(c.remote, "B", "cancel", c.terminal_message(pkg["request"], "cancel"))
            r1, r2 = f1.result(), f2.result()
        check(r1 == r2, "execute/cancel did not converge")
        status = r1["body"]["status"]
        check(c.effects("B") - before == (1 if status == "COMMITTED" else 0), "terminal and effect inconsistent")
        c.local("A", "reconcile", {"intent": "cancel-race"})
        return {"verdict": "PASS", "terminal_outcome": status, "race_agreed": True}
    run("D18", "実行と取消しの競合を単一終端状態に確定", cancellation_race)

    def source_changed():
        c.local("A", "prepare", command("source-changed"))
        c.local("A", "control", {"eligible": False})
        c.local("A", "control", {"eligible": True})
        code, r = c.raw("A", "/local/transmit", {"intent": "source-changed"}, token=c.tokens["A"])
        check(code == 400 and r["reason"] == "SOURCE_CONDITION_CHANGED", "source approval drift bypassed")
        return {"verdict": "REJECT", "reason": r["reason"]}
    run("D19", "送信側の条件変更後も再承認を要求", source_changed)

    def peer_revoke():
        pkg = c.local("A", "prepare", command("peer-revoke"))["package"]
        c.local("B", "control", {"peer": "A", "enabled": False})
        try:
            r = c.remote("B", "execute", pkg)
            check(r["body"]["reason"] == "REVOKED", "revoked incoming peer passed")
            r2 = c.local("C", "submit", command("unrelated-C-A", "A"))
            check(r2["verdict"] == "PASS", "independent C-A stopped")
        finally:
            c.local("B", "control", {"peer": "A", "enabled": True})
        return {"verdict": "REJECT / PASS", "blocked": "A-B", "preserved": "C-A"}
    run("D20", "接続単位の失効・無関係なC-Aは継続", peer_revoke)

    def admin_guard():
        before = c.local("B", "snapshot")["state"]
        code, r = c.raw("B", "/local/control", {"enabled": False}, token="forged-token")
        check(code == 403 and c.local("B", "snapshot")["state"] == before, "unauthorized admin changed state")
        return {"verdict": "REJECT", "http_status": code}
    run("D21", "無権限の失効操作を拒否", admin_guard)

    def parser_guard():
        count = 0
        for raw in (b'{"request":{},"request":{}}', b'{"x":NaN}', b'{"x":1.1}', b'[]'):
            code, _ = c.raw("B", "/v1/execute", raw=raw)
            check(code == 400, "ambiguous JSON accepted")
            count += 1
        return {"verdict": "REJECT", "invalid_inputs": count}
    run("D22", "重複JSONキー・NaN・浮動小数・非オブジェクト拒否", parser_guard)

    def offline_link():
        c.stop_node("B")
        try:
            r = c.local("A", "submit", command("offline-B"))
            check(r["verdict"] == "HOLD", "offline peer treated as authorized")
            r2 = c.local("A", "submit", command("offline-B-independent", "C"))
            check(r2["verdict"] == "PASS", "offline B blocked independent C")
        finally:
            c.restart("B")
        return {"verdict": "HOLD / PASS", "offline": "B", "preserved": "A-C"}
    run("D23", "Bプロセス停止中もA-Cは継続", offline_link)

    def no_secrets():
        bundle = c.bundle()
        raw = a.canonical(bundle)
        for n in "ABC":
            check((c.directory / n / "admin.token").read_bytes() not in raw, "admin token leaked")
            check((c.directory / n / "signing.key").read_bytes().hex().encode() not in raw, "signing key leaked")
            with contextlib.closing(sqlite3.connect(c.directory / n / "state.sqlite3")) as db:
                private = a.loads(db.execute("SELECT v FROM meta WHERE k='private_policy'").fetchone()[0])
            check(private["internal_customer"].encode() not in raw, "internal customer leaked")
            check(b"margin_floor" not in raw and b"warehouse_layout" not in raw, "internal policy fields leaked")
        return {"verdict": "PASS", "checked": "private-key/admin-token/internal-policy-canaries"}
    run("D24", "公開証拠への鍵・管理トークン・社内情報漏えい検査", no_secrets)

    def private_rule():
        before_b, before_c = c.effects("B"), c.effects("C")
        r = c.local("A", "submit", command("private-rule", units=500))
        check(r["verdict"] == "HOLD" and c.effects("B") == before_b, "private B rule not evaluated")
        r2 = c.local("A", "switch", {"intent": "private-rule", "destination": "C"})
        check(r2["verdict"] == "PASS" and c.effects("C") == before_c + 1, "private C rule not independently evaluated")
        return {"verdict": "HOLD -> PASS", "rule_threshold_shared": False, "route": "A-B -> A-C"}
    run("D25", "企業ごとに異なる社内ルールをローカル計算", private_rule)

    def before_commit_restart():
        before_b, before_c = c.effects("B"), c.effects("C")
        c.local("B", "fault", {"crash_before_commit": True})
        r = c.local("A", "submit", command("before-commit-crash"))
        check(r["verdict"] == "HOLD", "precommit crash not reproduced")
        c.processes["B"].wait(timeout=5)
        check(c.processes["B"].returncode == 70, "wrong precommit crash point")
        c.restart("B")
        c.local("B", "fault", {"crash_before_commit": False})
        check(c.effects("B") == before_b, "uncommitted DB effect survived")
        check(c.local("A", "reconcile", {"intent": "before-commit-crash"})["verdict"] == "HOLD", "absence treated as cancellation")
        r = c.local("A", "switch", {"intent": "before-commit-crash", "destination": "C"})
        check(r["verdict"] == "PASS" and c.effects("C") == before_c + 1, "recovery switch failed")
        return {"verdict": "HOLD -> PASS", "actual_process_exit": 70, "uncommitted_effect_rolled_back": True}
    run("D26", "受信側をDBコミット前に強制終了・未確定効果の回復", before_commit_restart)

    def switching_crash():
        pkg = c.local("A", "prepare", command("switching-crash"))["package"]
        c.local("A", "fault", {"source_crash_after_switch_record": True})
        try:
            c.local("A", "switch", {"intent": "switching-crash", "destination": "C"})
            raise AssertionError("switching crash not reproduced")
        except a.TransportError:
            pass
        c.processes["A"].wait(timeout=5)
        check(c.processes["A"].returncode == 73, "wrong switching crash point")
        c.restart("A")
        r = c.local("A", "submit", command("switching-crash", "C"))
        delayed = c.remote("B", "execute", pkg)
        check(r["verdict"] == "PASS" and delayed["body"]["status"] == "CANCELLED", "switch recovery unsafe")
        return {"verdict": "PASS", "actual_process_exit": 73, "late_old_request": "CANCELLED"}
    run("D27", "切替え記録直後の送信側クラッシュから再開", switching_crash)

    def terminal_action_binding():
        pkg = c.local("A", "prepare", command("terminal-action-binding"))["package"]
        code1, _ = c.raw("B", "/v1/cancel", {"request": pkg["request"]})
        status_message = c.terminal_message(pkg["request"], "status")
        code2, r = c.raw("B", "/v1/cancel", status_message)
        check(code1 == 400 and code2 == 400 and r["reason"] == "TERMINAL_ACTION", "execution/status credential authorized cancellation")
        result = c.local("A", "transmit", {"intent": "terminal-action-binding"})
        check(result["verdict"] == "PASS", "forged cancellation left a tombstone")
        return {"verdict": "REJECT / PASS", "reason": "ACTION_BOUND_CANCELLATION", "effects_added": 1}
    run("D28", "実行署名・照合署名を取消しへ流用できない", terminal_action_binding)

    def no_dispatch():
        p = c.local("A", "prepare", command("no-dispatch"))["package"]
        before = c.effects("B")
        r = c.remote("B", "execute", p)["body"]
        check(r["reason"] == "SOURCE_NOT_DISPATCHED" and c.effects("B") == before, "prepared package bypassed source dispatch")
        return {"verdict": "REJECT", "reason": r["reason"], "effects_added": 0}
    run("D29", "準備済み要求だけでは送信元の実行許可を代用できない", no_dispatch)

    def source_policy_bypass():
        p = c.local("A", "prepare", command("source-policy-bypass"))["package"]
        before = c.effects("B")
        c.local("A", "control", {"eligible": False})
        try:
            r = c.remote("B", "execute", p)["body"]
            check(r["reason"] == "SOURCE_LOCAL_CONDITION_UNMET" and c.effects("B") == before, "old source-policy bypass remains")
        finally:
            c.local("A", "control", {"eligible": True})
        return {"verdict": "HOLD", "reason": r["reason"], "effects_added": 0, "v1_regression": True}
    run("D30", "送信元の条件変更後に古い要求を直接送っても実行しない", source_policy_bypass)

    def source_peer_aba():
        p = c.local("A", "prepare", command("source-peer-aba"))["package"]
        c.local("B", "fault", {"drop_before_execute": True})
        c.local("A", "transmit", {"intent": "source-peer-aba"})
        before = c.effects("B")
        c.local("A", "control", {"peer": "B", "enabled": False})
        c.local("A", "control", {"peer": "B", "enabled": True})
        r = c.remote("B", "execute", p)["body"]
        check(r["reason"] == "SOURCE_CONDITION_CHANGED" and c.effects("B") == before, "source peer ABA revived old packet")
        return {"verdict": "REJECT", "reason": r["reason"], "effects_added": 0}
    run("D31", "送信側の接続失効・再有効化でも古い版を復活させない", source_peer_aba)

    def unavailable_source():
        before = c.effects("B")
        c.local("A", "fault", {"authorization_unavailable": True})
        try:
            r = c.local("A", "submit", command("source-unavailable"))
            check(r["verdict"] == "HOLD" and c.effects("B") == before, "unavailable source authorization failed open")
            other = c.local("C", "submit", command("source-unavailable-unrelated", "B"))
            check(other["verdict"] == "PASS", "unrelated C-B operation blocked")
        finally:
            c.local("A", "fault", {"authorization_unavailable": False})
        return {"verdict": "HOLD / PASS", "affected_route": "A-B", "unaffected_route": "C-B", "unaffected_effects_added": 1}
    run("D32", "送信元の確認不能は保留し、別主体の接続は継続", unavailable_source)

    def reciprocal():
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            ab = pool.submit(c.local, "A", "submit", command("reciprocal-ab", "B"))
            ba = pool.submit(c.local, "B", "submit", command("reciprocal-ba", "A"))
            check(ab.result(timeout=10)["verdict"] == ba.result(timeout=10)["verdict"] == "PASS", "reciprocal callbacks deadlocked")
        return {"verdict": "PASS", "routes": ["A-B", "B-A"], "effects_added": 2}
    run("D33", "双方向の同時要求でも確認コールバックが行き詰まらない", reciprocal)

    def receiver_revocation_inflight():
        p = c.local("A", "prepare", command("receiver-revoke-inflight"))["package"]
        before = c.effects("B")
        c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(c.local, "A", "transmit", {"intent": "receiver-revoke-inflight"})
                wait_for_pause(c, "B", p["request"])
                c.local("B", "control", {"enabled": False})
                c.local("B", "fault", {"pause_before_commit": False})
                result = pending.result(timeout=8)
                check(result["reason"] == "REVOKED" and c.effects("B") == before, "receiver revoked admission committed")
        finally:
            c.local("B", "fault", {"pause_before_commit": False})
            c.local("B", "control", {"enabled": True})
        return {"verdict": "REJECT", "source_admission_preexisted": True, "effects_added": 0}
    run("D34", "送信元の許可後でも受信側が失効すれば確定しない", receiver_revocation_inflight)

    def source_inflight_boundary():
        intent = "source-inflight-boundary"
        p = c.local("A", "prepare", command(intent))["package"]
        before = c.effects("B")
        c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(c.local, "A", "transmit", {"intent": intent})
                wait_for_pause(c, "B", p["request"])
                ack = c.local("A", "control", {"enabled": False})
                check(intent in ack["unresolved_admissions"] and not ack["remote_cancellation_confirmed"], "inflight operation falsely declared cancelled")
                c.local("B", "fault", {"pause_before_commit": False})
                check(pending.result(timeout=8)["verdict"] == "PASS" and c.effects("B") == before + 1, "preexisting unexpired admission not represented")
        finally:
            c.local("B", "fault", {"pause_before_commit": False})
            c.local("A", "control", {"enabled": True})
        return {"verdict": "BOUNDARY_CONFIRMED", "effects_added": 1, "instant_global_revocation": False,
            "meaning": "Source admission predated revocation. The control ACK did not claim remote cancellation."}
    run("D35", "送信元失効を、許可済み処理の取消し完了と誤表示しない", source_inflight_boundary)

    def admission_expiry():
        p = c.local("A", "prepare", command("admission-expiry"))["package"]
        before = c.effects("B")
        c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(c.local, "A", "transmit", {"intent": "admission-expiry"})
                wait_for_pause(c, "B", p["request"])
                time.sleep(a.GRANT_TTL / 1000 + .1)
                c.local("B", "fault", {"pause_before_commit": False})
                r = pending.result(timeout=8)
                check(r["reason"] == "SOURCE_AUTHORIZATION_EXPIRED" and c.effects("B") == before, "expired source grant executed")
        finally:
            c.local("B", "fault", {"pause_before_commit": False})
        return {"verdict": "HOLD", "source_grant_ttl_ms": a.GRANT_TTL, "effects_added": 0}
    run("D36", "実行時許可の期限超過を、業務効果の直前で止める", admission_expiry)

    def cancel_inflight():
        intent = "cancel-inflight"
        p = c.local("A", "prepare", command(intent))["package"]
        message = c.terminal_message(p["request"], "cancel")
        before = c.effects("B")
        c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(c.local, "A", "transmit", {"intent": intent})
                wait_for_pause(c, "B", p["request"])
                rec = c.remote("B", "cancel", message)
                c.local("B", "fault", {"pause_before_commit": False})
                result = pending.result(timeout=8)
                check(rec == result["receipt"] and rec["body"]["status"] == "CANCELLED" and c.effects("B") == before, "cancellation lost atomic race")
        finally:
            c.local("B", "fault", {"pause_before_commit": False})
        return {"verdict": "REJECT", "terminal": "CANCELLED", "effects_added": 0}
    run("D37", "実行許可済みでも取消しが先に確定すれば遅延実行を封じる", cancel_inflight)

    def source_down_after_admission():
        intent = "source-down-after-admission"
        p = c.local("A", "prepare", command(intent))["package"]
        before = c.effects("B")
        c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(c.local, "A", "transmit", {"intent": intent})
                wait_for_pause(c, "B", p["request"])
                c.stop_node("A")
                c.local("B", "fault", {"pause_before_commit": False})
                try:
                    pending.result(timeout=8)
                    raise AssertionError("source stop did not interrupt caller")
                except a.TransportError:
                    pass
            c.restart("A")
            deadline = time.monotonic() + 3
            while c.effects("B") == before and time.monotonic() < deadline:
                time.sleep(.01)
            result = c.local("A", "reconcile", {"intent": intent})
            check(result["verdict"] == "PASS" and c.effects("B") == before + 1, "persisted admission/receipt not recovered")
        finally:
            c.local("B", "fault", {"pause_before_commit": False})
            if c.processes["A"].poll() is not None:
                c.restart("A")
        return {"verdict": "HOLD -> PASS", "actual_source_process_stopped": True, "effects_added": 1}
    run("D38", "送信元停止後も、既に許可した処理の結果を再起動後に照合", source_down_after_admission)

    def receiver_down_after_admission():
        intent = "receiver-down-after-admission"
        p = c.local("A", "prepare", command(intent))["package"]
        before_b, before_c = c.effects("B"), c.effects("C")
        c.local("B", "fault", {"pause_before_commit": True})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(c.local, "A", "transmit", {"intent": intent})
            wait_for_pause(c, "B", p["request"])
            c.stop_node("B")
            check(pending.result(timeout=8)["verdict"] == "HOLD", "receiver death not unknown")
        c.restart("B")
        c.local("B", "fault", {"pause_before_commit": False})
        check(c.local("A", "reconcile", {"intent": intent})["verdict"] == "HOLD", "absence became no-execution proof")
        result = c.local("A", "switch", {"intent": intent, "destination": "C"})
        late = c.remote("B", "execute", p)
        check(result["verdict"] == "PASS" and late["body"]["status"] == "CANCELLED" and c.effects("B") == before_b and c.effects("C") == before_c + 1, "post-admission receiver recovery unsafe")
        return {"verdict": "HOLD -> PASS", "actual_receiver_process_stopped": True, "old_terminal": "CANCELLED", "effects_added": 1}
    run("D39", "許可発行後の受信側停止でも、取消し確定後だけ別社へ切替え", receiver_down_after_admission)

    def known_result_preserved():
        intent = "known-result-preserved"
        result = c.local("A", "submit", command(intent))
        c.local("B", "fault", {"terminal_unavailable": True})
        try:
            reconciled = c.local("A", "reconcile", {"intent": intent})
            check(reconciled["receipt"] == result["receipt"] and reconciled["verdict"] == "PASS", "known result downgraded by status outage")
        finally:
            c.local("B", "fault", {"terminal_unavailable": False})
        return {"verdict": "PASS", "known_terminal_retained": True}
    run("D40", "確定済み結果は、後の照合障害で未確定へ戻さない", known_result_preserved)
    return cases


def evidence_mutations(bundle, anchors):
    tests = []
    def attempt(name, mutation, pinned=True):
        b = copy.deepcopy(bundle)
        mutation(b)
        rejected = False
        reason = ""
        try:
            verifier.verify_bundle(b, anchors if pinned else None)
        except Exception as e:
            rejected, reason = True, str(e)
        tests.append({"name": name, "rejected": rejected, "reason": reason})
    attempt("signed_record_modified", lambda b: b["nodes"]["A"]["events"][0]["body"].update(at_ms=1))
    attempt("audit_tail_deleted", lambda b: b["nodes"]["B"]["events"].pop())
    attempt("audit_order_swapped", lambda b: b["nodes"]["A"]["events"].reverse())
    attempt("receipt_deleted", lambda b: b["nodes"]["B"]["receipts"].pop())
    attempt("public_key_substituted", lambda b: b["public_keys"].update(A="00" * 32))
    attempt("final_state_modified", lambda b: b["nodes"]["B"]["state"].update(enabled=False))
    attempt("peer_history_removed", lambda b: b["nodes"].pop("C"))
    attempt("checkpoint_signature_modified", lambda b: b["nodes"]["C"]["checkpoint"].update(sig="00" * 64))
    return tests


def run_experiment(c, output: Path, progress=None):
    import validate as v
    start = time.perf_counter()
    cases = scenario_suite(c, progress)
    bundle = c.bundle()
    anchors = anchors_for(bundle)
    verification = verifier.verify_bundle(bundle, anchors)
    mutations = evidence_mutations(bundle, anchors)
    model = v.check_model()
    report = {"schema": "vpi-cyber-report/2", "created_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "platform": platform.platform(), "cryptography": cryptography.__version__, "sqlite": sqlite3.sqlite_version},
        "cases": cases, "scenario_passed": sum(x["passed"] for x in cases), "scenario_total": len(cases),
        "verification": verification, "tamper_checks": mutations, "model": model,
        "elapsed_ms": int((time.perf_counter() - start) * 1000),
        "passed": all(x["passed"] for x in cases) and all(x["rejected"] for x in mutations) and model["passed"],
        "snapshots": c.snapshots()}
    bundle["run_metadata"] = {"created_utc": report["created_utc"], "scenario_passed": report["scenario_passed"], "scenario_total": report["scenario_total"]}
    output.mkdir(parents=True, exist_ok=True)
    # Run metadata is deliberately not authenticated by peer signatures.
    artifact = {"schema": "vpi-cyber-sample/2", "report": report,
                "evidence": bundle, "anchors": anchors}
    (output / "sample.json").write_text(
        json.dumps(artifact, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return report


class Lab:
    def __init__(self, output):
        self.output = output
        self.lock = threading.Lock()
        self.report, self.cases, self.error = {}, [], None
        self.running, self.generation, self.cluster = False, 0, None
        self.admin = secrets.token_hex(24)
        self.workspace = tempfile.TemporaryDirectory(prefix="vpi-cyber-")

    def run(self):
        with self.lock:
            if self.running:
                return False
            self.running = True
            self.cases, self.error, self.report = [], None, None
        def task():
            try:
                if self.cluster:
                    self.cluster.stop()
                self.generation += 1
                self.cluster = Cluster(Path(self.workspace.name) / str(self.generation)).start()
                def progress(cases):
                    with self.lock:
                        self.cases = cases
                result = run_experiment(self.cluster, self.output, progress)
                with self.lock:
                    self.report = result
            except Exception as e:
                with self.lock:
                    self.error = f"{type(e).__name__}: {e}"
            finally:
                with self.lock:
                    self.running = False
        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()
        return True

    def state(self):
        with self.lock:
            return {"running": self.running, "cases": self.cases, "report": self.report, "error": self.error}

    def close(self):
        if hasattr(self, "worker"):
            self.worker.join(timeout=30)
        if self.cluster:
            self.cluster.stop()
        self.workspace.cleanup()


def serve(output, port, no_open):
    lab = Lab(output)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def respond(self, raw, code=200, content="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self):
            if self.path == "/":
                raw = (ROOT / "dashboard.html").read_text(encoding="utf-8")
                boot = json.dumps({"live": True, "token": lab.admin})
                raw = raw.replace("/*BOOT*/", "window.BOOT=" + boot + ";")
                self.respond(raw.encode("utf-8"), content="text/html; charset=utf-8")
            elif self.path == "/api/state":
                self.respond(json.dumps(lab.state(), ensure_ascii=False).encode("utf-8"))
            else:
                self.respond(b'{}', 404)
        def do_POST(self):
            expected_origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.path != "/api/run" or self.headers.get("Origin") != expected_origin or not hmac.compare_digest(self.headers.get("X-Demo-Token", ""), lab.admin):
                self.respond(b'{"error":"forbidden"}', 403)
                return
            ok = lab.run()
            self.respond(json.dumps({"started": ok}).encode())
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_port}"
    print(f"Dashboard: {url}\nOutput: {output.resolve()}\nCtrl+C stops all demo processes.", flush=True)
    lab.run()
    if not no_open:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        lab.close()


def main():
    # A background launcher may have inherited SIGINT=IGNORE. Install explicit
    # handlers so both Ctrl+C and service termination enter the cleanup paths.
    def request_shutdown(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("run"))
    p.add_argument("--serve", action="store_true", help="browser dashboard; starts fresh experiment")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--no-open", action="store_true")
    p.add_argument("--keep-runtime", action="store_true", help="retain private keys/DBs under output/private-runtime (DO NOT PUBLISH)")
    args = p.parse_args()
    if args.serve:
        serve(args.output, args.port, args.no_open)
        return
    if args.keep_runtime:
        runtime = args.output / "private-runtime"
        if runtime.exists():
            p.error("private-runtime already exists; choose a different --output to avoid mixing experiments")
        with Cluster(runtime) as cluster:
            report = run_experiment(cluster, args.output)
    else:
        with tempfile.TemporaryDirectory(prefix="vpi-cyber-") as temp:
            with Cluster(Path(temp)) as cluster:
                report = run_experiment(cluster, args.output)
    print(json.dumps({k: report[k] for k in ("passed", "scenario_passed", "scenario_total", "verification", "elapsed_ms")}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
