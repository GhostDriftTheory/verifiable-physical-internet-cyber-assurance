#!/usr/bin/env python3
"""Validate and package the fixed-scope public PoC.

python validate.py                      # runtime checks; explicit Lean status
python validate.py --require-lean       # fail unless pinned Lean also succeeds
python validate.py --refresh-sample     # replace bundled results after validation
python validate.py --package out.zip --allow-pending-formal

Generated proof cases and logs stay in run-check/, not in the source distribution.
"""
from __future__ import annotations
import argparse
import contextlib
import functools
import hashlib
import io
import itertools
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from collections import deque
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
import cryptography
import assurance
from assurance import GateInput, gate_decision
import verifier
from verifier import observation_decision

ROOT = Path(__file__).resolve().parent
PIN = '4.19.0'
SOURCE_FILES = (
    'README.md', 'NOTICE.md', 'requirements.txt', '.gitignore',
    '.github/workflows/validate.yml', 'assurance.py', 'verifier.py',
    'demo.py', 'tests.py', 'validate.py', 'dashboard.html',
    'VpiAssurance.lean', 'lean-toolchain',
)
PUBLIC_FILES = SOURCE_FILES + ('sample.json',)
BLOCKED_NAMES = {'signing.key', 'admin.token', 'network.json', 'private.json'}
BLOCKED_SUFFIXES = {'.sqlite', '.sqlite3', '.db', '.pem', '.key', '.pyc'}
EMPTY, CANCELLED, COMMITTED = 0, 1, 2
NEW, READY, UNKNOWN, SEEN_COMMIT, SEEN_CANCEL = range(5)
FIELDS = {
    'enabled':'enabled', 'eligible':'eligible', 'peer_enabled':'peerEnabled',
    'revision':'revision','permit_revision':'permitRevision',
    'peer_revision':'peerRevision','permit_peer_revision':'permitPeerRevision',
    'request_issued':'requestIssued','permit_issued':'permitIssued','now':'now',
    'permit_expires':'permitExpires','request_expires':'requestExpires',
    'source_verified':'sourceVerified','source_issued':'sourceIssued','source_expires':'sourceExpires',
}

# Finite exploration: one sender/intent, B/C, bounded epochs and leases.
class State(NamedTuple):
    route: int = 0
    phase: int = NEW
    terminal: tuple[int, int] = (EMPTY, EMPTY)
    pending: int = 0
    epoch: tuple[int, int] = (0, 0)
    approval: tuple[int, int] = (-1, -1)
    source_epoch: int = 0
    request_epoch: tuple[int, int] = (-1, -1)
    grants: int = 0
    request_expired: bool = False
    grant_expired: bool = False
    bad_commit: bool = False
    bad_admission: bool = False

def at(pair, index, value):
    return tuple(value if i == index else pair[i] for i in range(2))

def successors(s: State, mutant="safe"):
    r = s.route
    if s.phase == NEW and s.source_epoch != 1 and s.epoch[r] != 1 and not s.request_expired:
        yield "prepare/approve " + "BC"[r], s._replace(phase=READY,
            approval=at(s.approval, r, s.epoch[r]), request_epoch=at(s.request_epoch, r, s.source_epoch))
    if s.phase == READY and s.source_epoch != 1 and s.request_epoch[r] == s.source_epoch:
        yield "durable dispatch " + "BC"[r], s._replace(phase=UNKNOWN, pending=s.pending | (1 << r))
    if s.phase == UNKNOWN and s.approval[r] >= 0 and not s.pending & (1 << r):
        yield "retry same packet " + "BC"[r], s._replace(pending=s.pending | (1 << r))
    for i in range(2):
        if s.pending & (1 << i):
            mask = 1 << i
            receiver_ok = s.epoch[i] != 1 and s.approval[i] == s.epoch[i] and not s.request_expired
            source_ok = (s.source_epoch != 1 and s.request_epoch[i] == s.source_epoch
                         and s.route == i and s.phase == UNKNOWN and not s.request_expired)
            if (s.terminal[i] == EMPTY and not s.grants & mask and not s.grant_expired
                and receiver_ok and (source_ok or mutant == "stale_source")):
                yield "issue challenge-bound source admission " + "BC"[i], s._replace(
                    grants=s.grants | mask, bad_admission=s.bad_admission or not source_ok)
            pending = s.pending & ~mask
            if s.terminal[i] != EMPTY:
                yield "return immutable terminal " + "BC"[i], s._replace(pending=pending)
            else:
                grant_ok = bool(s.grants & mask) and not s.grant_expired
                allowed_receiver = receiver_ok or (mutant == "stale_approval" and s.epoch[i] != 1 and not s.request_expired)
                allowed_grant = grant_ok or mutant == "source_bypass" or (mutant == "expired_admission" and bool(s.grants & mask))
                if allowed_receiver and allowed_grant:
                    yield "commit; acknowledgement may be lost " + "BC"[i], s._replace(pending=pending,
                        terminal=at(s.terminal, i, COMMITTED), bad_commit=s.bad_commit or not (receiver_ok and grant_ok))
                # A packet may be dropped at any point. Absence is never a tombstone.
                yield "drop/deny packet; outcome not inferred " + "BC"[i], s._replace(pending=pending)
        if s.epoch[i] < 2:
            yield ("revoke " if s.epoch[i] == 0 else "restore/new epoch ") + "BC"[i], s._replace(epoch=at(s.epoch, i, s.epoch[i] + 1))
    if s.source_epoch < 2:
        yield "source revoke" if s.source_epoch == 0 else "source restore/new epoch", s._replace(source_epoch=s.source_epoch + 1)
    if not s.request_expired:
        yield "request expires", s._replace(request_expired=True)
    if not s.grant_expired:
        yield "admission lease expires", s._replace(grant_expired=True)
    if s.phase != SEEN_COMMIT:
        if s.terminal[r] == EMPTY:
            yield "atomic cancellation tombstone " + "BC"[r], s._replace(terminal=at(s.terminal, r, CANCELLED))
        if s.terminal[r] == CANCELLED:
            yield "observe signed cancellation " + "BC"[r], s._replace(phase=SEEN_CANCEL)
        elif s.terminal[r] == COMMITTED:
            yield "observe committed receipt " + "BC"[r], s._replace(phase=SEEN_COMMIT)
    if r == 0 and (s.phase == SEEN_CANCEL or (mutant == "unsafe_failover" and s.phase == UNKNOWN)):
        yield "switch to C" + (" WITHOUT cancellation" if s.phase != SEEN_CANCEL else " after cancellation"), s._replace(route=1, phase=NEW)
    yield "process restart preserving durable state", s

def violation(s):
    if sum(x == COMMITTED for x in s.terminal) > 1:
        return "at-most-one business effect across B/C violated"
    if s.bad_commit:
        return "commit without current receiver authorization and unexpired source admission"
    if s.bad_admission:
        return "source admission issued without current source authorization"
    if s.phase == SEEN_COMMIT and s.terminal[s.route] != COMMITTED:
        return "reported commit without terminal receipt"
    if s.phase == SEEN_CANCEL and s.terminal[s.route] != CANCELLED:
        return "reported cancellation without tombstone"
    return None

@functools.lru_cache(maxsize=6)
def explore(mutant="safe", limit=600000):
    if mutant not in ("safe", "unsafe_failover", "stale_approval", "source_bypass", "expired_admission", "stale_source"):
        raise ValueError("unknown model variant")
    initial = State()
    queue, parents, edges = deque([initial]), {initial: None}, 0
    while queue:
        state = queue.popleft()
        bad = violation(state)
        if bad:
            path, cursor = [], state
            while parents[cursor] is not None:
                previous, action = parents[cursor]
                path.append(action); cursor = previous
            return {"safe":False, "states":len(parents), "transitions":edges, "violation":bad, "counterexample":path[::-1]}
        for action, nxt in successors(state, mutant):
            edges += 1
            if nxt != state and nxt not in parents:
                if len(parents) >= limit:
                    raise RuntimeError("state-space cap reached; result is NOT exhaustive")
                parents[nxt] = (state, action)
                queue.append(nxt)
    return {"safe":True, "states":len(parents), "transitions":edges, "exhaustive_within_model":True}

def check_model():
    safe = explore()
    names = ("unsafe_failover", "stale_approval", "source_bypass", "expired_admission", "stale_source")
    mutants = {name: explore(name) for name in names}
    return {"passed": safe["safe"] and all(not v["safe"] for v in mutants.values()), "safe_model":safe, "negative_controls":mutants,
        "bounds":"1 sender; 1 immutable intent; B/C; 1 revoke/restore at source and each receiver; 1 request expiry; 1 grant expiry; one abstract grant/destination; durable terminal records; replay/loss",
        "revocation_boundary":"Source admission is checked at issuance. Already-issued unexpired admissions are in flight, not retroactively cancelled. Receiver revocation is rechecked at local commit admission.",
        "claim":"Finite-state exhaustive exploration within the stated model, not an implementation refinement proof or a Lean build result."}

# Raw-input correspondence; Lean execution is a separate stage.
def corpus():
    base = GateInput(True,True,True,0,0,0,0,10,20,30,40,50,True,25,35)
    # Twenty-four chronological boundary profiles, including exact-expiry denial.
    changes = [
        {}, {'request_issued':20}, {'request_issued':21},
        {'permit_issued':30}, {'permit_issued':31}, {'permit_issued':9},
        {'now':39,'source_expires':40}, {'now':40,'source_expires':41},
        {'permit_expires':50}, {'permit_expires':51}, {'permit_expires':30},
        {'request_expires':39}, {'source_issued':30}, {'source_issued':31},
        {'source_expires':30}, {'source_expires':31}, {'source_expires':29},
        {'request_issued':0,'permit_issued':0,'now':0,'source_issued':0},
        {'now':50}, {'source_issued':0},
        {'request_issued':0,'permit_issued':1,'now':2,'source_issued':1,'source_expires':3},
        {'permit_issued':40,'now':40,'permit_expires':41,'source_issued':40,'source_expires':41},
        {'source_issued':35,'source_expires':25}, {'request_issued':50},
    ]
    cases=[]
    for flags in itertools.product((False,True),repeat=4):
        for revisions in itertools.product((0,1),repeat=4):
            for variant in changes:
                g=replace(base,enabled=flags[0],eligible=flags[1],peer_enabled=flags[2],source_verified=flags[3],
                    revision=revisions[0],permit_revision=revisions[1],peer_revision=revisions[2],permit_peer_revision=revisions[3])
                cases.append(("cartesian",replace(g,**variant)))
    # Boundaries near the largest integer admitted by the Python parser.
    m=2**63-1
    high=replace(base,revision=m,permit_revision=m,peer_revision=m,permit_peer_revision=m,
        request_issued=m-50,permit_issued=m-40,now=m-30,permit_expires=m-20,
        request_expires=m,source_issued=m-35,source_expires=m-25)
    for key in FIELDS:
        if isinstance(getattr(high,key),bool):
            cases.append(("integer-boundary",replace(high,**{key:not getattr(high,key)})))
        else:
            for value in (0,m-1,m):
                cases.append(("integer-boundary",replace(high,**{key:value})))
    cases.append(("integer-boundary",high))
    return cases

def runtime_inputs(evidence: Path | None):
    if evidence is None: return []
    artifact=verifier.read_json(evidence)
    bundle=artifact['evidence'] if artifact.get('schema')=='vpi-cyber-sample/2' else artifact
    out=[]
    for node in sorted(bundle['nodes']):
        for env in bundle['nodes'][node]['events']:
            e=env['body'] if 'body' in env else env['payload']
            if e['event']=='COMMIT':
                out.append(('runtime-commit', GateInput(**e['data']['observation'])))
    return out

def generate(output: Path, evidence: Path | None = None):
    cases=corpus()+runtime_inputs(evidence)
    raw=[]; counts={0:0,1:0,2:0}
    lines=['import VpiAssurance', '', '-- Generated by validate.py. Raw inputs, not Python verdicts, enter Lean.',
        '-- Successful Python-reference comparison does not mean this file has compiled.',
        'set_option autoImplicit false','set_option warningAsError true',
        'namespace VpiAssurance.Concrete', '']
    for i,(group,g) in enumerate(cases):
        o=asdict(g); expected=gate_decision(g)
        reference=observation_decision(o)
        if expected!=reference: raise AssertionError(f'policy/reference disagreement at case {i}')
        counts[expected]+=1
        raw.append({'group':group,'input':o,'expected':expected})
        entries=', '.join(f'{FIELDS[k]} := {str(v).lower() if type(v) is bool else v}' for k,v in o.items())
        lines.append(f'example : gateDecision {{{entries}}} = {expected} := by decide')
    lines+=['','end VpiAssurance.Concrete','']
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text('\n'.join(lines),encoding='utf-8')
    return {'status':'PYTHON_REFERENCE_PASS','total':len(raw),
        'cartesian_cases':sum(g=='cartesian' for g,_ in cases),
        'integer_boundary_cases':sum(g=='integer-boundary' for g,_ in cases),
        'runtime_commit_cases':sum(g=='runtime-commit' for g,_ in cases),
        'decision_counts':{'REJECT':counts[0],'HOLD':counts[1],'ADMIT':counts[2]},
        'input_sha256':hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'lean_file_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
        'lean_execution':'NOT_IMPLIED; see validation.formal in sample.json',
        'scope':'raw admission observations; not whole-program refinement'}

def strip_comments(s):
    # Lean nested block comments and line comments; source scanner, not a Lean parser.
    out=[]; i=0; depth=0
    while i<len(s):
        if s.startswith('/-',i): depth+=1;i+=2
        elif depth and s.startswith('-/',i): depth-=1;i+=2
        elif depth: i+=1
        elif s.startswith('--',i):
            j=s.find('\n',i);i=len(s) if j<0 else j
        else: out.append(s[i]);i+=1
    if depth: raise ValueError('unterminated Lean comment')
    return ''.join(out)
def validate_relative(name: str):
    p=Path(name)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError('unsafe release path')
    if p.name in BLOCKED_NAMES or p.suffix in BLOCKED_SUFFIXES or any(x in {'__pycache__','.venv','private-runtime'} for x in p.parts):
        raise ValueError('runtime/private file cannot be released: '+name)

def scan_bytes(name: str, raw: bytes):
    validate_relative(name)
    # The patterns detect common accidental leaks, not all possible secrets.
    patterns=(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
              rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b',rb'\bsk-proj-[A-Za-z0-9_-]{20,}\b')
    if any(re.search(p,raw) for p in patterns):
        raise ValueError('credential-like material in '+name)
    if re.search(rb'PRIVATE-[ABC]-[0-9a-f]{24}', raw):
        raise ValueError('private runtime canary in '+name)

def inspect_sources(generated: Path | None = None):
    paths = [ROOT / 'VpiAssurance.lean']
    if generated is not None:
        paths.append(generated)
    result = {}
    for path in paths:
        raw = path.read_bytes()
        clean = strip_comments(raw.decode('utf-8'))
        prohibited = re.search(r'\b(sorry|admit|axiom|native_decide|ofReduceBool|ofReduceNat|trustCompiler)\b|skipKernelTC', clean)
        if prohibited:
            raise ValueError(f'Untrusted proof shortcut in {path.name}: {prohibited.group()}')
        result[path.name] = {
            'sha256': hashlib.sha256(raw).hexdigest(),
            'named_theorems': len(re.findall(r'^theorem\s+', clean, re.M)),
            'concrete_examples': len(re.findall(r'^example\s*:', clean, re.M)),
        }
    return result


def write_json(path: Path, value, *, compact=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':') if compact else None,
                      indent=None if compact else 2) + '\n'
    # Replace only complete files; never leave a partially written public result.
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(text, encoding='utf-8')
    os.replace(temporary, path)


def run_formal(output: Path, generated: Path):
    output.mkdir(parents=True, exist_ok=True)
    result = {'status': 'NOT_RUN_TOOLCHAIN_UNAVAILABLE', 'pinned_lean': PIN,
              'checked_theorems': None, 'checked_concrete_equalities': None}
    try:
        result['sources'] = inspect_sources(generated)
        lean = shutil.which('lean')
        if lean is None:
            candidate = Path.home() / '.elan' / 'bin' / ('lean.exe' if os.name == 'nt' else 'lean')
            if candidate.is_file():
                lean = str(candidate)
        if lean is None:
            result['reason'] = 'Lean executable unavailable; source declarations are not checked proofs.'
            return result
        env = os.environ.copy()
        env['ELAN_TOOLCHAIN'] = 'leanprover/lean4:v' + PIN
        p = subprocess.run([lean, '--version'], cwd=ROOT, env=env,
                           capture_output=True, text=True, timeout=45)
        result['toolchain_output'] = (p.stdout + p.stderr).strip()
        (output / 'lean-version.log').write_text(p.stdout + p.stderr, encoding='utf-8')
        if p.returncode or re.search(r'\bversion 4\.19\.0(?:\b|\s)', p.stdout) is None:
            result.update(status='TOOLCHAIN_ERROR', reason='The pinned Lean version did not execute.')
            return result
        # Compile fresh files, never reuse an unchecked cached .olean.
        build_dir = generated.parent.resolve()
        model = build_dir / 'VpiAssurance.lean'
        model.write_bytes((ROOT / 'VpiAssurance.lean').read_bytes())
        for path in build_dir.glob('*.olean'):
            path.unlink()
        env['LEAN_PATH'] = str(build_dir)
        log = []
        for path in (model, generated.resolve()):
            p = subprocess.run([lean, '-o', str(path.with_suffix('.olean')), str(path)],
                               cwd=build_dir, env=env, capture_output=True, text=True, timeout=600)
            log.append(f'=== {path.name} ===\n' + p.stdout + p.stderr)
            if p.returncode:
                result.update(status='BUILD_FAILED', reason='Lean rejected a source; no proof count is reported.')
                break
        else:
            result.update(status='PASS',
                checked_theorems=result['sources']['VpiAssurance.lean']['named_theorems'],
                checked_concrete_equalities=result['sources'][generated.name]['concrete_examples'])
        result['build_log'] = '\n'.join(log)
        (output / 'lean-build.log').write_text(result['build_log'], encoding='utf-8')
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result.update(status='VALIDATION_ERROR', reason=f'{type(exc).__name__}: {exc}')
    return result


def source_fingerprints():
    """Bind every distributed source/document/config, not the self-referential sample."""
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def payload_hash(artifact):
    payload = {key: artifact[key] for key in ('schema', 'report', 'evidence', 'anchors')}
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(raw).hexdigest()


def check_release_status(summary, allow_pending_formal=False):
    tests = summary.get('tests', {})
    if (summary.get('runtime_passed') is not True or tests.get('passed') is not True
        or tests.get('run', 0) <= 0 or any(tests.get(k, 1) != 0 for k in ('failures', 'errors', 'skipped'))):
        raise ValueError('Runtime checks are incomplete or failed; rerun validate.py --refresh-sample')
    status = summary.get('formal', {}).get('status')
    if status == 'PASS':
        return
    if status != 'NOT_RUN_TOOLCHAIN_UNAVAILABLE':
        raise ValueError('Formal validation failed or has no valid status; packaging is blocked')
    if not allow_pending_formal:
        raise ValueError('Lean is not checked. RC packaging requires --allow-pending-formal')


def build(output: Path, allow_pending_formal=False):
    output = output.resolve()
    if output.suffix.lower() != '.zip':
        raise ValueError('Release output must end in .zip')
    artifact = verifier.load_sample(ROOT / 'sample.json')
    summary = artifact.get('validation', {})
    check_release_status(summary, allow_pending_formal)
    if summary.get('source_fingerprints') != source_fingerprints():
        raise ValueError('Source/document changed after validation; rerun validate.py --refresh-sample')
    if summary.get('payload_sha256') != payload_hash(artifact):
        raise ValueError('Sample payload changed after validation')
    if verifier.verify_file(ROOT / 'sample.json')['status'] != 'CONSISTENT':
        raise ValueError('Independent evidence verification failed')
    report = artifact['report']
    if not (report.get('passed') and report.get('scenario_total') == len(report.get('cases', []))
            and report.get('scenario_total') == report.get('scenario_passed')
            and all(c.get('passed') for c in report['cases'])
            and report.get('model', {}).get('passed')
            and all(c.get('rejected') for c in report.get('tamper_checks', []))):
        raise ValueError('Public experiment results are incomplete')
    entries = {}
    for name in PUBLIC_FILES:
        raw = (ROOT / name).read_bytes()
        scan_bytes(name, raw)
        if name in summary['source_fingerprints'] and hashlib.sha256(raw).hexdigest() != summary['source_fingerprints'][name]:
            raise ValueError('Source changed while packaging: ' + name)
        if name == 'sample.json' and json.loads(raw) != artifact:
            raise ValueError('Sample changed while packaging')
        entries[name] = raw
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = 'verifiable-physical-internet-cyber-assurance/'
    temporary = output.with_name(output.name + '.tmp')
    with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(entries.items()):
            info = zipfile.ZipInfo(prefix + name, date_time=(2026, 10, 31, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    with zipfile.ZipFile(temporary) as archive:
        if set(archive.namelist()) != {prefix + n for n in entries}:
            raise ValueError('Unexpected archive contents')
        for name, raw in entries.items():
            if archive.read(prefix + name) != raw:
                raise ValueError('Archive verification failed: ' + name)
    os.replace(temporary, output)
    return {'zip': output.name, 'files': len(entries), 'bytes': output.stat().st_size,
            'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
            'formal_status': summary['formal']['status']}


def embed_dashboard(report, summary):
    path = ROOT / 'dashboard.html'
    dashboard = path.read_text(encoding='utf-8')
    # Keep only UI-relevant status; raw evidence and full logs live in sample.json.
    stored = {'report': report, 'validation': {'tests': summary['tests'], 'formal': summary['formal']}}
    text = json.dumps(stored, ensure_ascii=True, separators=(',', ':'), allow_nan=False).replace('<', '\\u003c')
    pattern = r'(<script type="application/json" id="stored">).*?(</script>)'
    updated, count = re.subn(pattern, lambda m: m.group(1) + text + m.group(2), dashboard, flags=re.S)
    if count != 1:
        raise ValueError('Dashboard must contain exactly one stored-results element')
    path.write_text(updated, encoding='utf-8')


def run_checks(output: Path, refresh_sample=False, require_lean=False):
    import demo
    output = output.resolve()
    if output == ROOT:
        raise ValueError('Use a separate output directory, not the source root')
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    before = source_fingerprints()
    summary = {
        'schema': 'vpi-public-validation/2', 'version': assurance.VERSION,
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'environment': {'python': platform.python_version(), 'platform': platform.platform(),
                        'cryptography': cryptography.__version__},
        'runtime_passed': False, 'all_layers_passed': False,
        'ci_execution': 'GitHub Actions is configured; this field does not attest a CI run.',
        'hash_purpose': 'Source/payload integrity, not a publisher signature or trusted timestamp.',
    }
    artifact = None
    try:
        buffer = io.StringIO()
        suite = unittest.defaultTestLoader.loadTestsFromName('tests')
        with contextlib.redirect_stdout(io.StringIO()):
            result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
        summary['tests'] = {
            'run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped), 'passed': result.wasSuccessful() and not result.skipped,
            'counting_note': 'Includes a test of all 40 HTTP scenarios; do not add both totals.',
        }
        summary['test_log'] = buffer.getvalue()
        (output / 'tests.log').write_text(buffer.getvalue(), encoding='utf-8')
        print('Tests: ' + json.dumps(summary['tests']), flush=True)
        if not summary['tests']['passed']:
            raise RuntimeError('Test failure or skip; see tests.log')
        with tempfile.TemporaryDirectory(prefix='vpi-validation-') as temp:
            with demo.Cluster(Path(temp)) as cluster:
                report = demo.run_experiment(cluster, output)
        artifact = verifier.load_sample(output / 'sample.json')
        summary['verification'] = verifier.verify_file(output / 'sample.json')
        generated = output / 'formal' / 'Correspondence.lean'
        summary['correspondence'] = generate(generated, output / 'sample.json')
        summary['formal'] = run_formal(output, generated)
        summary['runtime_passed'] = bool(report['passed'] and report['model']['passed']
            and summary['verification']['status'] == 'CONSISTENT'
            and summary['correspondence']['status'] == 'PYTHON_REFERENCE_PASS')
        summary['all_layers_passed'] = summary['runtime_passed'] and summary['formal']['status'] == 'PASS'
        if source_fingerprints() != before:
            summary['runtime_passed'] = summary['all_layers_passed'] = False
            raise RuntimeError('Sources changed during validation; results will not replace the public sample')
        if refresh_sample and summary['runtime_passed'] and (not require_lean or summary['all_layers_passed']):
            embed_dashboard(report, summary)
        summary['source_fingerprints'] = source_fingerprints()
        summary['payload_sha256'] = payload_hash(artifact)
    except Exception as exc:
        summary['runtime_passed'] = summary['all_layers_passed'] = False
        summary['error'] = f'{type(exc).__name__}: {exc}'
    summary['elapsed_ms'] = round((time.perf_counter() - started) * 1000)
    write_json(output / 'result.json', summary)
    if artifact is not None:
        artifact['validation'] = summary
        write_json(output / 'sample.json', artifact, compact=True)
        if refresh_sample and summary['runtime_passed'] and (not require_lean or summary['all_layers_passed']):
            write_json(ROOT / 'sample.json', artifact, compact=True)
    print(json.dumps({'runtime_passed': summary['runtime_passed'],
        'all_layers_passed': summary['all_layers_passed'],
        'formal': summary.get('formal', {}).get('status'),
        'result': str(output / 'result.json'), 'error': summary.get('error')}, ensure_ascii=False, indent=2))
    return 0 if summary['runtime_passed'] and (not require_lean or summary['all_layers_passed']) else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, default=Path('run-check'))
    parser.add_argument('--require-lean', action='store_true')
    parser.add_argument('--refresh-sample', action='store_true')
    parser.add_argument('--package', type=Path, metavar='OUTPUT.zip')
    parser.add_argument('--allow-pending-formal', action='store_true')
    args = parser.parse_args()
    try:
        if args.package:
            if args.refresh_sample or args.require_lean:
                parser.error('Run validation first, then use --package separately')
            print(json.dumps(build(args.package, args.allow_pending_formal), ensure_ascii=False, indent=2))
            return 0
        if args.allow_pending_formal:
            parser.error('--allow-pending-formal is only valid with --package')
        return run_checks(args.output, args.refresh_sample, args.require_lean)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(2, f'Validation/packaging blocked: {exc}\n')


if __name__ == '__main__':
    # Tests and demo import the same validation module and share its model cache.
    sys.modules['validate'] = sys.modules[__name__]
    raise SystemExit(main())
