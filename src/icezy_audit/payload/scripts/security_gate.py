"""Offline evidence bookkeeping only; not a scanner or security certification."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

CONTROL_IDS = ('AUTH', 'AUTHZ', 'INPUT', 'SESSION', 'CSRF', 'FETCH', 'FILES',
               'CRYPTO', 'HEADERS', 'CONFIG', 'ABUSE', 'BUSINESS', 'INTEGRATIONS',
               'SUPPLY', 'LOGS', 'RECOVERY', 'PRIVACY', 'PLATFORM', 'AI')
NONWAIVABLE = {'AUTHZ', 'CRYPTO', 'CONFIG', 'BUSINESS'}
STATUSES = {'pending', 'pass', 'fail', 'na', 'accepted-risk'}
SEVERITIES = {'none', 'low', 'medium', 'high', 'critical'}
METHODS = {'test', 'runtime', 'source-review', 'manual-review'}
DEFAULT_METHODS = {i: {'test'} for i in CONTROL_IDS}
DEFAULT_METHODS.update(AUTH={'test', 'runtime'}, SESSION={'test', 'runtime'},
                       CRYPTO={'source-review', 'runtime'}, HEADERS={'runtime'},
                       CONFIG={'runtime'}, LOGS={'runtime'}, RECOVERY={'runtime'},
                       PRIVACY={'manual-review'})
ARTIFACTS = ('docs/security/PROFILE.md', 'docs/security/THREAT-MODEL.md',
             'docs/security/security-controls.json')
PENDING_MARKER = '[SECURITY-DESIGN-PENDING]'
MAX_JSON_BYTES = 1_000_000
MAX_EVIDENCE_BYTES = 10_000_000
SAFE_ERRORS = (ValueError, TypeError, OSError, KeyError, OverflowError, RecursionError)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def fields(record, allowed, required):
    if not isinstance(record, dict) or set(record) - set(allowed) or set(required) - set(record):
        raise ValueError('invalid record fields; unknown or missing field')
    if 'extensions' in record and not isinstance(record['extensions'], dict):
        raise ValueError('extensions must be a non-authoritative object')


def immutable_ref(value):
    return bool(isinstance(value, str) and re.fullmatch(r'(?:git:[a-f0-9]{40}|git:[a-f0-9]{64}|sha256:[a-f0-9]{64})', value)
                and set(value.split(':', 1)[1]) != {'0'})


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO timezone-aware string')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('timestamp needs timezone')
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError('invalid/out-of-range timezone-aware timestamp') from None


def contained_path(root, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative:
        raise ValueError('invalid relative artifact path')
    path = PurePosixPath(relative)
    if path.is_absolute() or any(p in ('', '.', '..') for p in relative.split('/')):
        raise ValueError('artifact path must stay inside project')
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('symlink artifact component forbidden')
    current.resolve().relative_to(root)
    return current


def read_bounded(path, limit):
    # Quiescent trusted checkout only, not a race-safe hostile filesystem API.
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('artifact missing, not regular, or oversized')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError('artifact empty or oversized')
    return data


def evidence_ok(root, evidence, ref, now, max_age_days, providers):
    if not isinstance(evidence, list) or not evidence:
        raise ValueError('evidence list required')
    for item in evidence:
        fields(item, {'path', 'sha256', 'source_ref', 'observed_at', 'method',
                      'description', 'command', 'exit_code', 'provider_id',
                      'target', 'environment', 'extensions'},
               {'path', 'sha256', 'source_ref', 'observed_at', 'method', 'description'})
        if item['source_ref'] != ref:
            raise ValueError('stale/mismatched evidence source_ref')
        observed = timestamp(item['observed_at'])
        if observed > now + timedelta(minutes=5) or now - observed > timedelta(days=max_age_days):
            raise ValueError('evidence outside freshness window')
        method = item['method']
        if method not in METHODS or not text(item['description']):
            raise ValueError('evidence method/description required')
        if 'exit_code' in item and (type(item['exit_code']) is not int or item['exit_code'] != 0):
            raise ValueError('recorded execution requires integer exit_code=0')
        if method == 'test' and ('exit_code' not in item or not text(item.get('command'))):
            raise ValueError('test requires command and integer exit_code=0')
        if method == 'runtime' and (not text(item.get('target')) or item.get('environment') not in {'local', 'emulator', 'staging', 'production'}):
            raise ValueError('runtime evidence requires target and environment')
        provider_id = item.get('provider_id')
        if provider_id is not None:
            if not isinstance(provider_id, str) or provider_id not in providers:
                raise ValueError('unknown evidence provider')
            provider = providers[provider_id]
            if item.get('target') != provider['target'] or item.get('environment') != provider['environment']:
                raise ValueError('provider evidence target/environment mismatch')
        if method == 'runtime' and not provider_id:
            raise ValueError('runtime evidence must identify inventoried service')
        data = read_bounded(contained_path(root, item['path']), MAX_EVIDENCE_BYTES)
        if item['sha256'] != hashlib.sha256(data).hexdigest():
            raise ValueError('evidence hash mismatch')


def load_manifest(root):
    data = read_bounded(contained_path(root, ARTIFACTS[2]), MAX_JSON_BYTES)
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_pairs)


def provider_index(records):
    if not isinstance(records, list) or not records:
        raise ValueError('inventory every in-scope service, including self-hosted hosting')
    result = {}
    for item in records:
        fields(item, {'id', 'kind', 'target', 'environment', 'owner', 'controls', 'extensions'},
               {'id', 'kind', 'target', 'environment', 'owner', 'controls'})
        if not all(text(item[k]) for k in ('id', 'kind', 'target', 'owner')):
            raise ValueError('provider identity/purpose/target/owner required')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', item['id']) or item['id'] in result:
            raise ValueError('invalid/duplicate provider ID')
        if item['environment'] not in {'local', 'emulator', 'staging', 'production'}:
            raise ValueError('invalid provider environment')
        controls = item['controls']
        if not isinstance(controls, list) or not controls or not all(text(i) for i in controls) or len(set(controls)) != len(controls):
            raise ValueError('provider controls must be a nonempty unique list')
        result[item['id']] = item
    if not any(p['environment'] == 'production' for p in result.values()):
        raise ValueError('production release requires inventoried production target')
    return result


def design_ok(root, reviews, ref, now, age, providers):
    if not isinstance(reviews, list) or len(reviews) != 2:
        raise ValueError('profile and threat-model review records required')
    seen = set()
    for review in reviews:
        fields(review, {'path', 'reviewer', 'evidence', 'extensions'}, {'path', 'reviewer', 'evidence'})
        if review['path'] not in ARTIFACTS[:2] or review['path'] in seen or not text(review['reviewer']):
            raise ValueError('invalid/duplicate design review')
        seen.add(review['path'])
        data = read_bounded(contained_path(root, review['path']), MAX_JSON_BYTES)
        if PENDING_MARKER.encode() in data:
            raise ValueError('unfinished design initializer still present')
        evidence_ok(root, review['evidence'], ref, now, age, providers)
        if not any(e['path'] == review['path'] and e['method'] in {'source-review', 'manual-review'} for e in review['evidence']):
            raise ValueError('design review must bind the reviewed document hash')


def validate(root, ref, now=None, max_age_days=30):
    errors = []
    try:
        root = Path(root).resolve(strict=True)
        now = now or datetime.now(timezone.utc)
        if not immutable_ref(ref) or type(max_age_days) is not int or not 1 <= max_age_days <= 365:
            raise ValueError('immutable git:/sha256: identity and freshness 1..365 days required')
        m = load_manifest(root)
        fields(m, {'schema_version', 'environment', 'source_ref', 'controls', 'findings', 'providers', 'design_reviews', 'extensions'},
               {'schema_version', 'environment', 'source_ref', 'controls', 'findings', 'providers', 'design_reviews'})
        if type(m['schema_version']) is not int or m['schema_version'] != 1:
            raise ValueError('unsupported manifest schema')
        if m['source_ref'] != ref or m['environment'] != 'production':
            raise ValueError('matching source_ref and production scope required')
        providers = provider_index(m['providers'])
        design_ok(root, m['design_reviews'], ref, now, max_age_days, providers)
        records = m['controls']
        if not isinstance(records, list):
            raise ValueError('controls list required')
        ids = [r.get('id') if isinstance(r, dict) else None for r in records]
        if any(not text(i) for i in ids) or len(set(ids)) != len(ids) or not set(CONTROL_IDS).issubset(ids):
            raise ValueError('invalid/duplicate/missing baseline control ID')
        for provider in providers.values():
            if not set(provider['controls']).issubset(ids):
                raise ValueError('provider references missing control')
        for r in records:
            ident = r['id']
            try:
                fields(r, {'id', 'applicable', 'status', 'risk', 'rationale', 'boundary', 'required_methods', 'evidence', 'exception', 'extensions'},
                       {'id', 'applicable', 'status', 'risk', 'rationale', 'boundary', 'required_methods', 'evidence'})
                status, risk = r['status'], r['risk']
                if status not in STATUSES or risk not in SEVERITIES:
                    raise ValueError('invalid status/residual risk')
                if status in {'pass', 'na'} and risk != 'none':
                    raise ValueError('PASS/N-A cannot hide unresolved residual risk')
                if status != 'accepted-risk' and 'exception' in r:
                    raise ValueError('exception allowed only on accepted-risk record')
                required = r['required_methods']
                if not isinstance(required, list) or not all(isinstance(x, str) and x in METHODS for x in required) or len(set(required)) != len(required):
                    raise ValueError('invalid required_methods')
                if status == 'na':
                    if r['applicable'] is not False or not text(r['rationale']):
                        raise ValueError('N/A needs applicable=false and rationale')
                    if any(ident in p['controls'] for p in providers.values()):
                        raise ValueError('provider declares an inapplicable control')
                elif status == 'pass':
                    if r['applicable'] is not True or not text(r['boundary']) or not required:
                        raise ValueError('PASS needs applicability, trusted boundary and required methods')
                    minimum = DEFAULT_METHODS.get(ident, {'test'})
                    if not minimum.issubset(required):
                        raise ValueError('required verification classes omitted')
                    evidence_ok(root, r['evidence'], ref, now, max_age_days, providers)
                    if not set(required).issubset({e['method'] for e in r['evidence']}):
                        raise ValueError('required evidence class missing')
                    for p in providers.values():
                        if ident not in p['controls']:
                            continue
                        linked = [e for e in r['evidence'] if e.get('provider_id') == p['id']]
                        if not linked:
                            raise ValueError('missing evidence for provider ' + p['id'])
                        if 'runtime' in minimum and not any(e['method'] == 'runtime' for e in linked):
                            raise ValueError('missing runtime evidence for provider ' + p['id'])
                elif status == 'accepted-risk':
                    if r['applicable'] is not True or not text(r['boundary']) or ident in NONWAIVABLE or risk not in {'low', 'medium'}:
                        raise ValueError('risk cannot be waived')
                    ex = r.get('exception')
                    fields(ex, {'owner', 'issue', 'rationale', 'expires_at', 'approval_evidence', 'extensions'},
                           {'owner', 'issue', 'rationale', 'expires_at', 'approval_evidence'})
                    if not all(text(ex[k]) for k in ('owner', 'issue', 'rationale')) or timestamp(ex['expires_at']) <= now:
                        raise ValueError('risk needs owner, issue, reason and unexpired approval')
                    evidence_ok(root, ex['approval_evidence'], ref, now, max_age_days, providers)
                else:
                    raise ValueError('pending/failed control blocks production')
            except SAFE_ERRORS as error:
                errors.append(ident + ': ' + str(error))
        findings = m['findings']
        if not isinstance(findings, list):
            raise ValueError('findings list required, even when empty')
        finding_ids = []
        for f in findings:
            fields(f, {'id', 'severity', 'status', 'control_id', 'verification_evidence', 'extensions'}, {'id', 'severity', 'status'})
            if not text(f['id']):
                raise ValueError('finding ID required')
            finding_ids.append(f['id'])
            severity, status = f['severity'], f['status']
            if severity not in SEVERITIES - {'none'} or status not in {'open', 'fixed', 'accepted-risk'}:
                raise ValueError('invalid finding severity/status')
            if status == 'fixed':
                evidence_ok(root, f.get('verification_evidence'), ref, now, max_age_days, providers)
            elif status == 'open' or severity in {'high', 'critical'}:
                errors.append(f['id'] + ': unresolved finding blocks production')
            else:
                control = next((r for r in records if r['id'] == f.get('control_id')), None)
                if not control or control['status'] != 'accepted-risk' or control['risk'] != severity:
                    errors.append(f['id'] + ': no matching risk acceptance')
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError('duplicate finding IDs')
    except SAFE_ERRORS as error:
        errors.append(str(error))
    return {'status': 'BOOKKEEPING_PASS' if not errors else 'BLOCKED',
            'security_certification': False, 'application_behavior_tested_by_gate': False,
            'source_identity_authenticated_by_gate': False, 'source_ref': ref, 'errors': errors}


def initialize(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('project root must exist')
    paths = [contained_path(root, rel) for rel in ARTIFACTS]
    if any(p.exists() for p in paths):
        raise ValueError('security artifacts already exist; merge, do not overwrite')
    profile = '# Security profile\n\n' + PENDING_MARKER + '\nComplete scope, ALL providers/targets/owners, data, roles, auth assurance, standards, legal questions and verification strategy.\n'
    threat = '# Threat model\n\n' + PENDING_MARKER + '\nComplete assets, actors, boundaries, principal/resource/action matrix, misuse cases and negative tests.\n'
    m = {'schema_version': 1, 'environment': 'undecided', 'source_ref': 'UNSET',
         'providers': [], 'design_reviews': [],
         'controls': [{'id': i, 'applicable': None, 'status': 'pending', 'risk': 'none',
                       'rationale': '', 'boundary': '', 'required_methods': sorted(DEFAULT_METHODS[i]),
                       'evidence': []} for i in CONTROL_IDS], 'findings': []}
    contents = [profile, threat, json.dumps(m, ensure_ascii=False, indent=2) + '\n']
    for path, content in zip(paths, contents):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            stream.write(content)
    return {'status': 'INITIALIZED_PENDING', 'files': list(ARTIFACTS), 'security_certification': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init'); init.add_argument('--root', required=True)
    check = sub.add_parser('check'); check.add_argument('--root', required=True)
    check.add_argument('--source-ref', required=True)
    check.add_argument('--max-age-days', type=int, default=30)
    args = parser.parse_args()
    try:
        result = initialize(args.root) if args.action == 'init' else validate(args.root, args.source_ref, max_age_days=args.max_age_days)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] in {'INITIALIZED_PENDING', 'BOOKKEEPING_PASS'} else 1
    except SAFE_ERRORS as error:
        print(json.dumps({'status': 'BLOCKED', 'error': str(error)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
