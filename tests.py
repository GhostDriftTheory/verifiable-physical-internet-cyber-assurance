#!/usr/bin/env python3
"""Runtime, failure, evidence, model and public-artifact regressions.
Run: python -m unittest -v tests
"""
from __future__ import annotations
import ast
import concurrent.futures
import contextlib
import copy
import io
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import assurance as a
from assurance import GateInput, gate_decision
import demo
import verifier
import validate as v

class CodecTests(unittest.TestCase):
    def test_canonical_object_order(self):
        self.assertEqual(a.canonical({"b": 2, "a": 1}), a.canonical({"a": 1, "b": 2}))

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.loads('{"a":1,"a":2}')

    def test_nested_duplicate_keys_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.loads('{"outer":{"a":1,"a":2}}')

    def test_nan_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.loads('{"a":NaN}')

    def test_float_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.canonical({"a": 1.5})

    def test_unicode_not_in_protocol_subset(self):
        with self.assertRaises(a.ProtocolError):
            a.canonical({"reference": "日本"})

    def test_oversized_integer_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.canonical({"n": 2**63})

    def test_boolean_not_integer(self):
        with self.assertRaises(a.ProtocolError):
            a.payload_check({"reference": "X", "units": True})

    def test_nested_depth_rejected(self):
        value = {}
        for _ in range(26):
            value = {"n": value}
        with self.assertRaises(a.ProtocolError):
            a.canonical(value)

    def test_payload_unknown_field_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.payload_check({"reference": "X", "units": 1, "customer_name": "hidden"})

    def test_zero_units_rejected(self):
        with self.assertRaises(a.ProtocolError):
            a.payload_check({"reference": "X", "units": 0})

    def test_signature_roundtrip(self):
        key = Ed25519PrivateKey.generate()
        env = a.signed(key, "A", {"kind": "test"})
        self.assertEqual(a.verify(env, {"A": a.public_hex(key)}, "A"), {"kind": "test"})

    def test_signature_change_rejected(self):
        key = Ed25519PrivateKey.generate()
        env = a.signed(key, "A", {"kind": "test"})
        env["body"]["kind"] = "altered"
        with self.assertRaises(a.ProtocolError):
            a.verify(env, {"A": a.public_hex(key)})

    def test_signature_domain_separation(self):
        key = Ed25519PrivateKey.generate()
        env = {"signer": "A", "body": {"kind": "test"}, "sig": key.sign(a.canonical({"kind": "test"})).hex()}
        with self.assertRaises(a.ProtocolError):
            a.verify(env, {"A": a.public_hex(key)})

    def test_wrong_signer_rejected(self):
        key = Ed25519PrivateKey.generate()
        env = a.signed(key, "A", {"kind": "test"})
        with self.assertRaises(a.ProtocolError):
            a.verify(env, {"A": a.public_hex(key)}, "B")

    def test_independent_canonical_implementations_agree(self):
        obj = {"list": [1, None, True, {"z": "ascii", "a": -10}], "empty": {}}
        self.assertEqual(a.canonical(obj), verifier.canon(obj))

class LiveProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vpi-tests-")
        cls.c = demo.Cluster(Path(cls.tmp.name)).start()

    @classmethod
    def tearDownClass(cls):
        cls.c.stop()
        cls.tmp.cleanup()

    def intent(self):
        return self._testMethodName

    def package(self, ttl=None):
        return self.c.local("A", "prepare", demo.command(self.intent(), ttl=ttl))["package"]

    def key(self, n):
        return Ed25519PrivateKey.from_private_bytes((self.c.directory / n / "signing.key").read_bytes())

    def test_separate_pid_keys_databases(self):
        self.assertEqual(len({x["pid"] for x in self.c.info.values()}), 3)
        self.assertEqual(len({x["public_key"] for x in self.c.info.values()}), 3)
        for n in "ABC":
            self.assertTrue((self.c.directory / n / "state.sqlite3").exists())

    def test_happy_path_real_effect(self):
        before = self.c.effects("B")
        r = self.c.local("A", "submit", demo.command(self.intent()))
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(self.c.effects("B"), before + 1)

    def test_source_duplicate_returns_same_receipt(self):
        before = self.c.effects("B")
        d = demo.command(self.intent())
        r1, r2 = self.c.local("A", "submit", d), self.c.local("A", "submit", d)
        self.assertEqual(r1["receipt"], r2["receipt"])
        self.assertEqual(self.c.effects("B"), before + 1)

    def test_concurrent_source_submissions(self):
        before = self.c.effects("B")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(lambda _: self.c.local("A", "submit", demo.command(self.intent())), range(8)))
        self.assertTrue(all(r["verdict"] == "PASS" for r in replies))
        self.assertEqual(len({a.digest(r["receipt"]) for r in replies}), 1)
        self.assertEqual(self.c.effects("B"), before + 1)

    def test_payload_binding(self):
        p = self.package()
        p["payload"]["units"] = 2
        status, r = self.c.raw("B", "/v1/execute", p)
        self.assertEqual((status, r["reason"]), (400, "PAYLOAD_BINDING"))

    def test_target_binding(self):
        status, r = self.c.raw("C", "/v1/execute", self.package())
        self.assertEqual((status, r["reason"]), (400, "REQUEST_TARGET"))

    def test_tampered_signature(self):
        p = self.package()
        p["request"]["sig"] = "00" * 64
        status, r = self.c.raw("B", "/v1/execute", p)
        self.assertEqual((status, r["reason"]), (400, "BAD_SIGNATURE"))

    def test_valid_signer_cannot_add_scope(self):
        p = self.package()
        p["request"]["body"]["scope"] = "network.admin"
        p["request"] = a.signed(self.key("A"), "A", p["request"]["body"])
        status, r = self.c.raw("B", "/v1/approve", {"request": p["request"], "payload": p["payload"]})
        self.assertEqual((status, r["reason"]), (400, "SCOPE_OR_DIGEST"))

    def test_permit_cannot_be_moved_to_another_request(self):
        p = self.package()
        altered = copy.deepcopy(p["request"]["body"])
        altered["nonce"] = "different-nonce"
        p["request"] = a.signed(self.key("A"), "A", altered)
        status, r = self.c.raw("B", "/v1/execute", p)
        self.assertEqual((status, r["reason"]), (400, "PERMIT_BINDING"))

    def test_expiry_blocks_new_effect(self):
        p = self.package(ttl=200)
        before = self.c.effects("B")
        time.sleep(.25)
        r = self.c.remote("B", "execute", p)
        self.assertEqual(r["body"]["reason"], "EXPIRED_OR_FUTURE")
        self.assertEqual(self.c.effects("B"), before)

    def test_expired_replay_only_returns_prior_result(self):
        p = self.package(ttl=1000)
        r1 = self.c.local("A", "transmit", {"intent": self.intent()})["receipt"]
        before = self.c.effects("B")
        time.sleep(1.05)
        r2 = self.c.remote("B", "execute", p)
        self.assertEqual(r1, r2)
        self.assertEqual(self.c.effects("B"), before)

    def test_revocation_fences_previous_approval(self):
        p = self.package()
        self.c.local("B", "control", {"enabled": False})
        try:
            r = self.c.remote("B", "execute", p)
            self.assertEqual(r["body"]["reason"], "REVOKED")
        finally:
            self.c.local("B", "control", {"enabled": True})

    def test_reenable_does_not_revive_old_permit(self):
        p = self.package()
        self.c.local("B", "control", {"enabled": False})
        self.c.local("B", "control", {"enabled": True})
        self.assertEqual(self.c.remote("B", "execute", p)["body"]["reason"], "STALE_APPROVAL")

    def test_policy_change_fences_previous_approval(self):
        p = self.package()
        self.c.local("B", "control", {"eligible": False})
        try:
            self.assertEqual(self.c.remote("B", "execute", p)["body"]["verdict"], "HOLD")
        finally:
            self.c.local("B", "control", {"eligible": True})

    def test_private_threshold_not_in_outcome(self):
        r = self.c.local("A", "submit", demo.command(self.intent(), units=500))
        self.assertEqual(r["verdict"], "HOLD")
        self.assertNotIn("max_units", json.dumps(r))

    def test_missing_result_is_not_cancellation(self):
        self.package()
        r = self.c.local("A", "reconcile", {"intent": self.intent()})
        self.assertEqual(r["verdict"], "HOLD")
        self.assertEqual(r["reason"], "NOT_FOUND_IS_NOT_CANCELLATION")

    def test_cancellation_blocks_late_execute(self):
        p = self.package()
        cancelled = self.c.remote("B", "cancel", self.c.terminal_message(p["request"], "cancel"))
        before = self.c.effects("B")
        late = self.c.remote("B", "execute", p)
        self.assertEqual(cancelled, late)
        self.assertEqual(late["body"]["status"], "CANCELLED")
        self.assertEqual(self.c.effects("B"), before)

    def test_cancellation_after_commit_returns_commit(self):
        p = self.package()
        committed = self.c.local("A", "transmit", {"intent": self.intent()})["receipt"]
        cancelled = self.c.remote("B", "cancel", self.c.terminal_message(p["request"], "cancel"))
        self.assertEqual(committed, cancelled)
        self.assertEqual(cancelled["body"]["status"], "COMMITTED")

    def test_stale_payload_with_same_id_rejected_at_receiver(self):
        p = self.package()
        self.c.local("A", "transmit", {"intent": self.intent()})
        p["payload"]["units"] = 2
        p["request"]["body"]["payload_hash"] = a.digest(p["payload"])
        p["request"] = a.signed(self.key("A"), "A", p["request"]["body"])
        p["permit"] = self.c.remote("B", "approve", {"request": p["request"], "payload": p["payload"]})
        status, r = self.c.raw("B", "/v1/execute", p)
        self.assertEqual((status, r["reason"]), (400, "IDEMPOTENCY_CONFLICT"))

    def test_unavailable_terminal_proof_holds_switch(self):
        self.package()
        before = self.c.effects("C")
        self.c.local("B", "fault", {"terminal_unavailable": True})
        try:
            r = self.c.local("A", "switch", {"intent": self.intent(), "destination": "C"})
            self.assertEqual(r["verdict"], "HOLD")
            self.assertEqual(self.c.effects("C"), before)
        finally:
            self.c.local("B", "fault", {"terminal_unavailable": False})

    def test_committed_source_cannot_switch(self):
        self.c.local("A", "submit", demo.command(self.intent()))
        before = self.c.effects("C")
        r = self.c.local("A", "switch", {"intent": self.intent(), "destination": "C"})
        self.assertEqual(r["reason"], "ALREADY_COMMITTED_NO_SWITCH")
        self.assertEqual(self.c.effects("C"), before)

    def test_safe_switch_carries_cancellation(self):
        self.package()
        r = self.c.local("A", "switch", {"intent": self.intent(), "destination": "C"})
        self.assertEqual(r["verdict"], "PASS")
        events = self.c.local("C", "export")["events"]
        matched = [e["body"]["data"] for e in events if e["body"]["event"] == "COMMIT" and e["body"]["data"]["request"]["body"]["intent"] == self.intent()]
        self.assertEqual(matched[0]["request"]["body"]["previous"][0]["body"]["status"], "CANCELLED")

    def test_revisited_destination_refused(self):
        self.package()
        self.c.local("C", "control", {"eligible": False})
        try:
            self.c.local("A", "switch", {"intent": self.intent(), "destination": "C"})
        finally:
            self.c.local("C", "control", {"eligible": True})
        code, r = self.c.raw("A", "/local/switch", {"intent": self.intent(), "destination": "B"}, token=self.c.tokens["A"])
        self.assertEqual((code, r["reason"]), (400, "DESTINATION_ALREADY_VISITED"))

    def test_execution_signature_cannot_cancel(self):
        p = self.package()
        code, _ = self.c.raw("B", "/v1/cancel", {"request": p["request"]})
        self.assertEqual(code, 400)
        self.assertEqual(self.c.local("A", "transmit", {"intent": self.intent()})["receipt"]["body"]["status"], "COMMITTED")

    def test_status_signature_cannot_cancel(self):
        p = self.package()
        query = self.c.terminal_message(p["request"], "status")
        code, r = self.c.raw("B", "/v1/cancel", query)
        self.assertEqual((code, r["reason"]), (400, "TERMINAL_ACTION"))
        self.assertEqual(self.c.local("A", "transmit", {"intent": self.intent()})["receipt"]["body"]["status"], "COMMITTED")

    def test_missing_admin_token(self):
        status, r = self.c.raw("B", "/local/control", {"enabled": False})
        self.assertEqual((status, r["reason"]), (403, "ADMIN_AUTH_REQUIRED"))

    def test_browser_cross_origin_rejected(self):
        status, r = self.c.raw("B", "/local/control", {"enabled": False}, token=self.c.tokens["B"], headers={"Origin": "https://untrusted.example"})
        self.assertEqual((status, r["reason"]), (400, "BROWSER_ORIGIN_REJECTED"))

    def test_unknown_destination_not_used_as_url(self):
        d = demo.command(self.intent(), "http://example.invalid")
        status, r = self.c.raw("A", "/local/submit", d, token=self.c.tokens["A"])
        self.assertEqual((status, r["reason"]), (400, "UNKNOWN_DESTINATION"))

    def test_duplicate_json_wire_rejected(self):
        status, r = self.c.raw("B", "/v1/execute", raw=b'{"request":{},"request":{}}')
        self.assertEqual((status, r["reason"]), (400, "DUPLICATE_JSON_KEY"))

    def test_content_type_rejected(self):
        status, r = self.c.raw("B", "/v1/execute", {}, headers={"Content-Type": "text/plain"})
        self.assertEqual((status, r["reason"]), (400, "CONTENT_TYPE"))

    def test_unknown_endpoint_rejected(self):
        status, r = self.c.raw("B", "/v1/internal-business-bypass", {})
        self.assertEqual((status, r["reason"]), (400, "UNKNOWN_ROUTE"))

    def test_boolean_ttl_rejected(self):
        d = demo.command(self.intent(), ttl=True)
        status, r = self.c.raw("A", "/local/submit", d, token=self.c.tokens["A"])
        self.assertEqual((status, r["reason"]), (400, "INTEGER"))

class LocalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpi-local-test-")
        p = Path(self.temp.name)
        self.agent = a.Agent("A", p / "A", p / "network.json", fault_mode=False)

    def tearDown(self):
        self.temp.cleanup()

    def test_fault_injection_disabled_by_default(self):
        with self.assertRaisesRegex(a.ProtocolError, "FAULT_MODE_DISABLED"):
            self.agent.fault({"crash_after_commit": True})

    def test_clock_rollback_fails_closed(self):
        with self.agent.tx() as db:
            self.agent.put_meta(db, "last_ms", 1000)
        with mock.patch("assurance.now_ms", return_value=999):
            with self.assertRaisesRegex(a.ProtocolError, "CLOCK_ROLLBACK"):
                with self.agent.tx() as db:
                    self.agent.timestamp(db)

    def test_sqlite_effect_and_receipt_rollback_together(self):
        with self.assertRaises(RuntimeError):
            with self.agent.tx() as db:
                db.execute("INSERT INTO deliveries VALUES('B','X','effect','{}')")
                db.execute("INSERT INTO inbound VALUES('B','X','hash','{}')")
                raise RuntimeError("abort")
        with contextlib.closing(self.agent.connect()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM inbound").fetchone()[0], 0)

    def test_private_metadata_not_in_export(self):
        raw = a.canonical(self.agent.export())
        self.assertNotIn(b"max_units", raw)
        self.assertNotIn(b"private_policy", raw)
        self.assertNotIn(b"PRIVATE-A", raw)

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vpi-evidence-test-")
        cls.c = demo.Cluster(Path(cls.tmp.name)).start()
        cls.c.local("A", "submit", demo.command("evidence-fixture"))
        cls.bundle = cls.c.bundle()
        cls.anchors = demo.anchors_for(cls.bundle)
        cls.keys = {n: Ed25519PrivateKey.from_private_bytes((cls.c.directory / n / "signing.key").read_bytes()) for n in "ABC"}

    @classmethod
    def tearDownClass(cls):
        cls.c.stop()
        cls.tmp.cleanup()

    def rechain(self, b, node):
        """Test adversary has fixture keys: re-sign, so tests exercise semantics, not only signatures."""
        data, prev = b["nodes"][node], a.ZERO
        for i, env in enumerate(data["events"], 1):
            env["body"].update(seq=i, prev=prev)
            data["events"][i-1] = a.signed(self.keys[node], node, env["body"])
            prev = a.digest(data["events"][i-1])
        cp = data["checkpoint"]["body"]
        cp.update(seq=len(data["events"]), tail=prev, receipts_hash=a.digest(data["receipts"]), state_hash=a.digest(data["state"]))
        data["checkpoint"] = a.signed(self.keys[node], node, cp)

    def test_valid_bundle_pinned(self):
        r = verifier.verify_bundle(self.bundle, self.anchors)
        self.assertEqual(r["status"], "CONSISTENT")
        self.assertEqual(r["trust"], "PINNED_KEYS_AND_CHECKPOINTS")

    def test_unpinned_bundle_qualified(self):
        r = verifier.verify_bundle(self.bundle)
        self.assertEqual(r["trust"], "SELF_CONTAINED_KEYS_ONLY")
        self.assertFalse(r["run_metadata_verified"])

    def test_eight_artifact_mutations_rejected(self):
        results = demo.evidence_mutations(self.bundle, self.anchors)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(x["rejected"] for x in results))

    def test_valid_signature_false_gate_witness_rejected(self):
        b = copy.deepcopy(self.bundle)
        event = next(e for e in b["nodes"]["B"]["events"] if e["body"]["event"] == "COMMIT")
        event["body"]["data"]["gate"]["enabled"] = False
        self.rechain(b, "B")
        with self.assertRaisesRegex(verifier.VerificationError, "gate witness"):
            verifier.verify_bundle(b)

    def test_valid_signature_incorrect_effect_count_rejected(self):
        b = copy.deepcopy(self.bundle)
        b["nodes"]["B"]["checkpoint"]["body"]["effects"] = 99
        self.rechain(b, "B")
        with self.assertRaisesRegex(verifier.VerificationError, "effect count"):
            verifier.verify_bundle(b)

    def test_valid_signature_false_final_state_rejected(self):
        b = copy.deepcopy(self.bundle)
        b["nodes"]["B"]["state"]["enabled"] = False
        self.rechain(b, "B")
        with self.assertRaisesRegex(verifier.VerificationError, "final state"):
            verifier.verify_bundle(b)

    def test_valid_signature_unknown_transition_rejected(self):
        b = copy.deepcopy(self.bundle)
        b["nodes"]["B"]["events"][1]["body"]["event"] = "UNSUPPORTED_TRANSITION"
        self.rechain(b, "B")
        with self.assertRaisesRegex(verifier.VerificationError, "unknown audit event"):
            verifier.verify_bundle(b)

    def test_pins_detect_consistently_resigned_shorter_history(self):
        b = copy.deepcopy(self.bundle)
        for n in "ABC":
            d = b["nodes"][n]
            d["events"] = d["events"][:1]
            d["receipts"] = []
            d["state"] = copy.deepcopy(d["events"][0]["body"]["data"]["state"])
            d["checkpoint"]["body"]["effects"] = 0
            self.rechain(b, n)
        # This is consistent as a standalone disclosed prefix. Do NOT claim otherwise.
        self.assertEqual(verifier.verify_bundle(b)["status"], "CONSISTENT")
        with self.assertRaisesRegex(verifier.VerificationError, "pinned checkpoint"):
            verifier.verify_bundle(b, self.anchors)

class ModelTests(unittest.TestCase):
    def test_safe_state_space_exhausted(self):
        r = v.explore()
        self.assertTrue(r["safe"])
        self.assertTrue(r["exhaustive_within_model"])

    def test_unsafe_failover_has_counterexample(self):
        r = v.explore("unsafe_failover")
        self.assertFalse(r["safe"])
        self.assertIn("at-most-one", r["violation"])

    def test_stale_approval_has_counterexample(self):
        r = v.explore("stale_approval")
        self.assertFalse(r["safe"])
        self.assertIn("authorization", r["violation"])

class EndToEndRegressionTests(unittest.TestCase):
    def test_all_40_scenarios_and_offline_verification(self):
        with tempfile.TemporaryDirectory(prefix="vpi-regression-") as d:
            with demo.Cluster(Path(d) / "private") as cluster:
                with contextlib.redirect_stdout(io.StringIO()):
                    report = demo.run_experiment(cluster, Path(d) / "public")
                self.assertEqual(report["scenario_total"], 40)
                failures = [x for x in report["cases"] if not x["passed"]]
                self.assertEqual(failures, [])
                self.assertTrue(report["passed"])
                self.assertEqual(verifier.verify_file(Path(d) / "public/sample.json")["status"], "CONSISTENT")


def wait_for_pause(c, node, request, timeout=3.0):
    wanted = a.digest(a.op_identity(request["body"]))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = c.local(node, "export")["events"]
        if any(e["body"]["event"] == "FAULT" and e["body"]["data"].get("fault") == "pause_before_commit"
               and e["body"]["data"].get("op_hash") == wanted for e in events):
            return
        time.sleep(.01)
    raise AssertionError("receiver did not reach the explicit pre-commit barrier")

class SourceAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vpi-v2-tests-")
        cls.c = demo.Cluster(Path(cls.tmp.name)).start()

    @classmethod
    def tearDownClass(cls):
        cls.c.stop()
        cls.tmp.cleanup()

    def intent(self):
        return self._testMethodName

    def package(self, dest="B"):
        return self.c.local("A", "prepare", demo.command(self.intent(), dest))["package"]

    def dispatched_unknown(self):
        package = self.package()
        self.c.local("B", "fault", {"drop_before_execute": True})
        self.assertEqual(self.c.local("A", "transmit", {"intent": self.intent()})["verdict"], "HOLD")
        return package

    def assert_no_effect(self, package, change, restore, reason):
        before = self.c.effects("B")
        self.c.local("A", "control", change)
        try:
            reply = self.c.remote("B", "execute", package)
            self.assertEqual(reply["body"]["reason"], reason)
            self.assertEqual(self.c.effects("B"), before)
        finally:
            self.c.local("A", "control", restore)

    def test_prepared_request_without_dispatch_cannot_execute(self):
        p = self.package()
        before = self.c.effects("B")
        r = self.c.remote("B", "execute", p)
        self.assertEqual(r["body"]["reason"], "SOURCE_NOT_DISPATCHED")
        self.assertEqual(self.c.effects("B"), before)

    def test_original_source_ineligible_bypass_is_blocked(self):
        self.assert_no_effect(self.package(), {"eligible": False}, {"eligible": True}, "SOURCE_LOCAL_CONDITION_UNMET")

    def test_source_revoked_bypass_is_blocked(self):
        self.assert_no_effect(self.package(), {"enabled": False}, {"enabled": True}, "SOURCE_REVOKED")

    def test_source_peer_revoked_bypass_is_blocked(self):
        self.assert_no_effect(self.package(), {"peer": "B", "enabled": False}, {"peer": "B", "enabled": True}, "SOURCE_REVOKED")

    def test_source_global_aba_is_fenced(self):
        p = self.dispatched_unknown()
        self.c.local("A", "control", {"enabled": False})
        self.c.local("A", "control", {"enabled": True})
        self.assertEqual(self.c.remote("B", "execute", p)["body"]["reason"], "SOURCE_CONDITION_CHANGED")

    def test_source_peer_aba_is_fenced(self):
        p = self.dispatched_unknown()
        self.c.local("A", "control", {"peer": "B", "enabled": False})
        self.c.local("A", "control", {"peer": "B", "enabled": True})
        self.assertEqual(self.c.remote("B", "execute", p)["body"]["reason"], "SOURCE_CONDITION_CHANGED")

    def test_unrelated_peer_revocation_preserves_prepared_route(self):
        self.package(dest="C")
        self.c.local("A", "control", {"peer": "B", "enabled": False})
        try:
            self.assertEqual(self.c.local("A", "transmit", {"intent": self.intent()})["verdict"], "PASS")
        finally:
            self.c.local("A", "control", {"peer": "B", "enabled": True})

    def test_source_callback_unavailable_holds_without_effect(self):
        p = self.dispatched_unknown()
        before = self.c.effects("B")
        self.c.local("A", "fault", {"authorization_unavailable": True})
        try:
            r = self.c.remote("B", "execute", p)
            self.assertEqual(r["body"]["reason"], "SOURCE_AUTHORIZATION_UNAVAILABLE")
            self.assertEqual(self.c.effects("B"), before)
        finally:
            self.c.local("A", "fault", {"authorization_unavailable": False})

    def test_source_process_down_holds_but_unrelated_source_works(self):
        p = self.dispatched_unknown()
        before = self.c.effects("B")
        self.c.stop_node("A")
        try:
            r = self.c.remote("B", "execute", p)
            self.assertEqual(r["body"]["reason"], "SOURCE_AUTHORIZATION_UNAVAILABLE")
            self.assertEqual(self.c.effects("B"), before)
            self.assertEqual(self.c.local("C", "submit", demo.command(self.intent() + "-other"))["verdict"], "PASS")
        finally:
            self.c.restart("A")
        self.assertEqual(self.c.remote("B", "execute", p)["body"]["status"], "COMMITTED")
        self.c.local("A", "reconcile", {"intent": self.intent()})

    def test_reciprocal_operations_do_not_deadlock(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a_to_b = pool.submit(self.c.local, "A", "submit", demo.command(self.intent() + "-ab", "B"))
            b_to_a = pool.submit(self.c.local, "B", "submit", demo.command(self.intent() + "-ba", "A"))
            self.assertEqual(a_to_b.result(timeout=10)["verdict"], "PASS")
            self.assertEqual(b_to_a.result(timeout=10)["verdict"], "PASS")

    def test_receiver_revoke_during_inflight_admission_blocks_commit(self):
        p = self.package()
        before = self.c.effects("B")
        self.c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.c.local, "A", "transmit", {"intent": self.intent()})
                wait_for_pause(self.c, "B", p["request"])
                self.c.local("B", "control", {"enabled": False})
                self.c.local("B", "fault", {"pause_before_commit": False})
                self.assertEqual(pending.result(timeout=8)["reason"], "REVOKED")
                self.assertEqual(self.c.effects("B"), before)
        finally:
            self.c.local("B", "fault", {"pause_before_commit": False})
            self.c.local("B", "control", {"enabled": True})

    def test_source_revoke_does_not_mislabel_inflight_grant_as_cancelled(self):
        p = self.package()
        before = self.c.effects("B")
        self.c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.c.local, "A", "transmit", {"intent": self.intent()})
                wait_for_pause(self.c, "B", p["request"])
                ack = self.c.local("A", "control", {"enabled": False})
                self.assertIn(self.intent(), ack["unresolved_admissions"])
                self.assertFalse(ack["remote_cancellation_confirmed"])
                self.c.local("B", "fault", {"pause_before_commit": False})
                self.assertEqual(pending.result(timeout=8)["verdict"], "PASS")
                self.assertEqual(self.c.effects("B"), before + 1)
        finally:
            self.c.local("B", "fault", {"pause_before_commit": False})
            self.c.local("A", "control", {"enabled": True})

    def test_expired_source_grant_is_not_committed(self):
        p = self.package()
        before = self.c.effects("B")
        self.c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.c.local, "A", "transmit", {"intent": self.intent()})
                wait_for_pause(self.c, "B", p["request"])
                time.sleep(a.GRANT_TTL / 1000 + .10)
                self.c.local("B", "fault", {"pause_before_commit": False})
                r = pending.result(timeout=8)
                self.assertEqual((r["verdict"], r["reason"]), ("HOLD", "SOURCE_AUTHORIZATION_EXPIRED"))
                self.assertEqual(self.c.effects("B"), before)
                phase = next(x["phase"] for x in self.c.local("A", "snapshot")["outbound"] if x["intent"] == self.intent())
                self.assertEqual(phase, "UNKNOWN", "attempt-level denial must not certify no execution")
        finally:
            self.c.local("B", "fault", {"pause_before_commit": False})

    def test_cancel_wins_after_source_admission_before_commit(self):
        p = self.package()
        cancellation = self.c.terminal_message(p["request"], "cancel")
        before = self.c.effects("B")
        self.c.local("B", "fault", {"pause_before_commit": True})
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(self.c.local, "A", "transmit", {"intent": self.intent()})
                wait_for_pause(self.c, "B", p["request"])
                receipt = self.c.remote("B", "cancel", cancellation)
                self.c.local("B", "fault", {"pause_before_commit": False})
                r = pending.result(timeout=8)
                self.assertEqual(r["receipt"], receipt)
                self.assertEqual(receipt["body"]["status"], "CANCELLED")
                self.assertEqual(self.c.effects("B"), before)
        finally:
            self.c.local("B", "fault", {"pause_before_commit": False})

    def test_known_commit_never_downgrades_to_unknown_on_status_outage(self):
        self.package()
        first = self.c.local("A", "transmit", {"intent": self.intent()})
        self.c.local("B", "fault", {"terminal_unavailable": True})
        try:
            r = self.c.local("A", "reconcile", {"intent": self.intent()})
            self.assertEqual(r["receipt"], first["receipt"])
            self.assertEqual(r["verdict"], "PASS")
        finally:
            self.c.local("B", "fault", {"terminal_unavailable": False})

    def test_z_all_new_histories_are_independently_consistent(self):
        b = self.c.bundle()
        result = verifier.verify_bundle(b, demo.anchors_for(b))
        self.assertGreater(result["source_authorizations"], 5)
        self.assertEqual(result["status"], "CONSISTENT")

class SemanticEvidenceV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="vpi-v2-semantic-")
        cls.c = demo.Cluster(Path(cls.tmp.name)).start()
        cls.c.local("A", "submit", demo.command("semantic-v2"))
        cls.bundle = cls.c.bundle()
        cls.keys = {n: Ed25519PrivateKey.from_private_bytes((cls.c.directory / n / "signing.key").read_bytes()) for n in "ABC"}

    @classmethod
    def tearDownClass(cls):
        cls.c.stop(); cls.tmp.cleanup()

    def rechain(self, b, n):
        d, prev = b["nodes"][n], a.ZERO
        for i, env in enumerate(d["events"], 1):
            env["body"].update(seq=i, prev=prev)
            d["events"][i-1] = a.signed(self.keys[n], n, env["body"])
            prev = a.digest(d["events"][i-1])
        cp = d["checkpoint"]["body"]
        cp.update(seq=len(d["events"]), tail=prev, receipts_hash=a.digest(d["receipts"]), state_hash=a.digest(d["state"]))
        d["checkpoint"] = a.signed(self.keys[n], n, cp)

    def remove_event(self, node, event, reason):
        b = copy.deepcopy(self.bundle)
        b["nodes"][node]["events"] = [e for e in b["nodes"][node]["events"] if e["body"]["event"] != event]
        self.rechain(b, node)
        with self.assertRaisesRegex(verifier.VerificationError, reason):
            verifier.verify_bundle(b)  # All remaining signatures are valid.

    def test_missing_execution_dispatch_rejected_even_resigned(self):
        self.remove_event("A", "OUT_SEND", "without dispatch")

    def test_missing_source_authorization_rejected_even_resigned(self):
        self.remove_event("A", "OUT_AUTHORIZE", "missing source execution authorization")

    def test_missing_receiver_challenge_rejected_even_resigned(self):
        self.remove_event("B", "CHALLENGE", "unissued/reused receiver challenge")

    def test_false_observation_rejected_even_resigned(self):
        b = copy.deepcopy(self.bundle)
        e = next(x for x in b["nodes"]["B"]["events"] if x["body"]["event"] == "COMMIT")
        e["body"]["data"]["observation"]["source_verified"] = False
        self.rechain(b, "B")
        with self.assertRaisesRegex(verifier.VerificationError, "admission observation"):
            verifier.verify_bundle(b)

    def test_source_authorization_after_revocation_rejected_even_resigned(self):
        b = copy.deepcopy(self.bundle)
        ev = b["nodes"]["A"]["events"]
        at = next(i for i,e in enumerate(ev) if e["body"]["event"] == "OUT_AUTHORIZE")
        state = {"enabled": False, "revision": 2, "eligible": True, "peers": {}}
        ev.insert(at, {"body": {"kind": "audit", "node": "A", "seq": 0, "prev": a.ZERO, "at_ms": ev[at]["body"]["at_ms"], "event": "CONTROL", "data": {"change": {"enabled": False}, "state": state}}})
        b["nodes"]["A"]["state"] = state
        self.rechain(b, "A")
        with self.assertRaisesRegex(verifier.VerificationError, "source admission after revocation"):
            verifier.verify_bundle(b)

    def test_wire_v1_is_not_accepted_as_v2(self):
        b = copy.deepcopy(self.bundle)
        b["schema"] = "vpi-cyber-evidence/1"
        with self.assertRaisesRegex(verifier.VerificationError, "bundle schema"):
            verifier.verify_bundle(b)

    def test_verifier_has_no_runtime_import(self):
        import ast
        tree = ast.parse(Path(verifier.__file__).read_text())
        imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        imports |= {x.name for n in ast.walk(tree) if isinstance(n, ast.Import) for x in n.names}
        self.assertTrue({"assurance", "validate", "demo"}.isdisjoint(imports))

class PolicyBoundaryTests(unittest.TestCase):
    def good(self):
        return dict(enabled=True, eligible=True, peer_enabled=True, revision=1, permit_revision=1, peer_revision=1, permit_peer_revision=1,
                    request_issued=1, permit_issued=2, now=3, permit_expires=4, request_expires=5, source_verified=True, source_issued=2, source_expires=4)

    def test_all_single_guard_failures_block(self):
        changes = [{"enabled":False}, {"eligible":False}, {"peer_enabled":False}, {"revision":2}, {"peer_revision":2},
                   {"request_issued":3}, {"permit_issued":4}, {"now":4}, {"permit_expires":6}, {"source_verified":False}, {"source_issued":4}, {"source_expires":3}]
        for patch in changes:
            with self.subTest(patch=patch):
                self.assertNotEqual(gate_decision(GateInput(**(self.good() | patch))), 2)

    def test_valid_boundary_is_live_not_all_hold(self):
        self.assertEqual(gate_decision(GateInput(**self.good())), 2)

    def test_booleans_are_not_admitted_as_revisions(self):
        with self.assertRaises(ValueError): GateInput(**(self.good() | {"revision":True}))

    def test_negative_and_overflow_times_are_rejected(self):
        for n in (-1, 2**63):
            with self.assertRaises(ValueError): GateInput(**(self.good() | {"now":n}))


class PublicQualityTests(unittest.TestCase):
    def test_raw_corpus_matches_independent_verifier(self):
        with tempfile.TemporaryDirectory() as d:
            r=v.generate(Path(d)/'Cases.lean')
        self.assertEqual(r['status'],'PYTHON_REFERENCE_PASS')
        self.assertEqual(r['cartesian_cases'],6144)
        self.assertTrue(all(n>0 for n in r['decision_counts'].values()))

    def test_generated_cases_contain_raw_versions_and_times(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'Cases.lean';v.generate(f)
            text=f.read_text()
        self.assertIn('permitRevision :=',text)
        self.assertIn('sourceExpires :=',text)
        self.assertNotIn('verdict :=',text)
        self.assertEqual(text.count('example :'),6182)

    def test_lean_comment_stripping_supports_nesting(self):
        self.assertEqual(v.strip_comments('a /- outer /- inner -/ x -/ b -- tail\nc'),'a  b \nc')

    def test_lean_source_contains_no_proof_shortcut(self):
        info=v.inspect_sources()
        self.assertGreater(info['VpiAssurance.lean']['named_theorems'],10)

    def test_release_rejects_private_runtime_file_names(self):
        for name in ('signing.key','foo/admin.token','runtime/x.sqlite','__pycache__/x.pyc','private-runtime/a.txt'):
            with self.subTest(name=name),self.assertRaises(ValueError):v.validate_relative(name)

    def test_release_rejects_path_traversal(self):
        for name in ('../secret','/tmp/secret','x/../../secret'):
            with self.subTest(name=name),self.assertRaises(ValueError):v.validate_relative(name)

    def test_release_rejects_cross_platform_absolute_paths(self):
        for name in ('/tmp/secret', r'C:\private\secret', r'\\server\share\secret',
                     r'\rooted\secret', 'x\\..\\secret', 'x//secret', 'x/./secret'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                v.validate_relative(name)

    def test_lean_chunks_preserve_every_concrete_proposition(self):
        with tempfile.TemporaryDirectory() as d:
            generated = Path(d) / 'Correspondence.lean'
            v.generate(generated)
            original = [line for line in generated.read_text(encoding='utf-8').splitlines()
                        if line.startswith('example : ')]
            parts = v.split_correspondence(generated, batch_size=97)
            actual = [line for part in parts
                      for line in part.read_text(encoding='utf-8').splitlines()
                      if line.startswith('example : ')]
            self.assertEqual(actual, original)
            self.assertTrue(all(part.name.startswith('Correspondence_') for part in parts))
            self.assertTrue(all(len([line for line in part.read_text(encoding='utf-8').splitlines()
                                     if line.startswith('example : ')]) <= 97 for part in parts))

    def test_release_rejects_private_key_material(self):
        marker=b'-----BEGIN '+b'PRIVATE KEY-----\nsecret\n'
        with self.assertRaises(ValueError):v.scan_bytes('safe.json',marker)

    def test_release_rejects_synthetic_private_canary(self):
        material=b'PRIVATE-' + b'A-' + b'ab'*12
        with self.assertRaises(ValueError):v.scan_bytes('sample/evidence.json',material)

    def test_release_accepts_public_evidence(self):
        v.scan_bytes('sample/evidence.json',b'{"public_keys":{"A":"synthetic"}}')

    def test_source_fingerprint_includes_execution_and_verifier(self):
        f=v.source_fingerprints()
        for key in ('assurance.py','verifier.py','validate.py','VpiAssurance.lean'):
            self.assertEqual(len(f[key]),64)

    def test_all_five_negative_model_controls_find_counterexamples(self):
        result=v.check_model()
        self.assertEqual(len(result['negative_controls']),5)
        self.assertTrue(all(not x['safe'] and x['counterexample'] for x in result['negative_controls'].values()))

    def test_state_cap_cannot_be_reported_as_exhaustive(self):
        with self.assertRaisesRegex(RuntimeError,'NOT exhaustive'):v.explore(limit=1)

class ConsoleEncodingTests(unittest.TestCase):
    def test_progress_output_under_windows_charmap(self):
        """The scenario runner must never abort on a non-UTF console."""
        sink = io.BytesIO()
        stream = io.TextIOWrapper(sink, encoding="cp1252", errors="strict")
        with contextlib.redirect_stdout(stream):
            demo.console_line("OK D01 正常接続・最小情報の実HTTP転送")
        stream.flush()
        rendered = sink.getvalue().decode("cp1252")
        self.assertIn("OK D01", rendered)
        self.assertIn(r"\u6b63", rendered)


class CompactArtifactTests(unittest.TestCase):
    """Protect the compact container, trust labels and release gate semantics."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='vpi-artifact-')
        with demo.Cluster(Path(cls.temp.name) / 'private') as cluster:
            cluster.local('A', 'submit', demo.command('artifact-fixture'))
            bundle = cluster.bundle()
        cls.artifact = {
            'schema': 'vpi-cyber-sample/2', 'report': {'description': '合成実験'},
            'evidence': bundle, 'anchors': demo.anchors_for(bundle),
        }

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def save(self, obj):
        path = Path(self.temp.name) / (self._testMethodName + '.json')
        path.write_text(json.dumps(obj, ensure_ascii=False), encoding='utf-8')
        return path

    def good_summary(self):
        return {'runtime_passed': True,
                'tests': {'passed': True, 'run': 1, 'failures': 0, 'errors': 0, 'skipped': 0},
                'formal': {'status': 'NOT_RUN_TOOLCHAIN_UNAVAILABLE'}}

    def test_compact_sample_verifies(self):
        result = verifier.verify_file(self.save(self.artifact))
        self.assertEqual(result['status'], 'CONSISTENT')
        self.assertEqual(result['trust'], 'BUNDLED_KEYS_AND_CHECKPOINTS')
        self.assertFalse(result['run_metadata_verified'])

    def test_explicit_anchor_path_is_distinguished(self):
        anchors = Path(self.temp.name) / 'external-anchors.json'
        anchors.write_text(json.dumps(self.artifact['anchors']), encoding='utf-8')
        result = verifier.verify_file(self.save(self.artifact), anchors)
        self.assertEqual(result['trust'], 'PINNED_KEYS_AND_CHECKPOINTS')

    def test_unsigned_display_claims_do_not_change_verifier(self):
        sample = copy.deepcopy(self.artifact)
        sample['report'] = {'scenario_passed': 999999, 'description': '未検証の説明'}
        sample['validation'] = {'formal': {'status': 'PASS'}}
        result = verifier.verify_file(self.save(sample))
        self.assertEqual(result['status'], 'CONSISTENT')
        self.assertFalse(result['run_metadata_verified'])
        self.assertNotIn('formal', result)

    def test_nested_evidence_modification_is_rejected(self):
        sample = copy.deepcopy(self.artifact)
        sample['evidence']['nodes']['A']['events'][0]['body']['at_ms'] = 1
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_file(self.save(sample))

    def test_missing_sample_field_is_rejected(self):
        sample = copy.deepcopy(self.artifact)
        del sample['evidence']
        with self.assertRaisesRegex(verifier.VerificationError, 'sample fields'):
            verifier.verify_file(self.save(sample))

    def test_unknown_sample_field_is_rejected(self):
        sample = copy.deepcopy(self.artifact)
        sample['extra'] = 'unexpected'
        with self.assertRaisesRegex(verifier.VerificationError, 'unknown sample field'):
            verifier.verify_file(self.save(sample))

    def test_duplicate_container_key_is_rejected(self):
        path = self.save({})
        path.write_text('{"schema":"a","schema":"b"}', encoding='utf-8')
        with self.assertRaisesRegex(verifier.VerificationError, 'duplicate JSON key'):
            verifier.verify_file(path)

    def test_nonfinite_display_metadata_is_rejected(self):
        sample = copy.deepcopy(self.artifact)
        sample['report']['number'] = float('nan')
        with self.assertRaisesRegex(verifier.VerificationError, 'non-finite JSON constant'):
            verifier.verify_file(self.save(sample))

    def test_wire_unicode_is_still_rejected_inside_container(self):
        sample = copy.deepcopy(self.artifact)
        sample['evidence']['run_metadata'] = {'text': '非ASCII'}
        with self.assertRaisesRegex(verifier.VerificationError, 'string format'):
            verifier.verify_file(self.save(sample))

    def test_top_level_array_is_rejected(self):
        with self.assertRaisesRegex(verifier.VerificationError, 'JSON object required'):
            verifier.verify_file(self.save([]))

    def test_pending_formal_release_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(ValueError, 'allow-pending-formal'):
            v.check_release_status(self.good_summary())
        v.check_release_status(self.good_summary(), True)

    def test_failed_formal_release_cannot_be_overridden(self):
        summary = self.good_summary()
        for status in ('BUILD_FAILED', 'TOOLCHAIN_ERROR', 'VALIDATION_ERROR', None):
            summary['formal']['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                v.check_release_status(summary, True)

    def test_skipped_tests_cannot_be_released_as_success(self):
        summary = self.good_summary()
        summary['tests']['skipped'] = 1
        with self.assertRaises(ValueError):
            v.check_release_status(summary, True)

    def test_source_distribution_is_fourteen_files(self):
        self.assertEqual(len(v.PUBLIC_FILES), 14)
        self.assertEqual(len(set(v.PUBLIC_FILES)), 14)
        self.assertNotIn('Correspondence.lean', v.PUBLIC_FILES)
        for name in v.PUBLIC_FILES:
            self.assertTrue((v.ROOT / name).is_file(), name)

    def test_payload_fingerprint_detects_report_change(self):
        original = v.payload_hash(self.artifact)
        changed = copy.deepcopy(self.artifact)
        changed['report']['scenario_passed'] = 999
        self.assertNotEqual(v.payload_hash(changed), original)

    def test_revalidation_metadata_does_not_make_hash_self_referential(self):
        original = v.payload_hash(self.artifact)
        changed = copy.deepcopy(self.artifact)
        changed['validation'] = {'payload_sha256': original}
        self.assertEqual(v.payload_hash(changed), original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
