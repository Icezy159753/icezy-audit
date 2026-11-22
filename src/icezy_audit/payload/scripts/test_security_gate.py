"""Synthetic workflow tests; never inspect or change a real application."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import security_gate as gate


class SecurityGateTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get('TMPDIR', tempfile.gettempdir()))
        self.temp = tempfile.TemporaryDirectory(prefix='security-gate-', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        gate.initialize(self.root)
        self.ref = 'sha256:' + 'a' * 64
        self.now = datetime.now(timezone.utc)
        proof = self.root / 'docs/security/synthetic-proof.txt'
        proof.write_text('SYNTHETIC UNIT FIXTURE ONLY: not production evidence.\n')
        self.evidence = {'path': 'docs/security/synthetic-proof.txt',
                         'sha256': hashlib.sha256(proof.read_bytes()).hexdigest(),
                         'source_ref': self.ref, 'observed_at': self.now.isoformat(),
                         'method': 'test', 'description': 'Synthetic fixture for helper validation',
                         'command': 'synthetic fixture only', 'exit_code': 0}
        self.evidence.update(provider_id='fixture-host', target='synthetic.invalid', environment='production')
        self.manifest = gate.load_manifest(self.root)
        self.manifest.update(environment='production', source_ref=self.ref)
        self.manifest['providers'] = [{'id': 'fixture-host', 'kind': 'SYNTHETIC ONLY',
            'target': 'synthetic.invalid', 'environment': 'production',
            'owner': 'Synthetic Tester', 'controls': list(gate.CONTROL_IDS)}]
        self.manifest['design_reviews'] = []
        for path in gate.ARTIFACTS[:2]:
            p = self.root / path
            p.write_text('# Synthetic completed design fixture\nNot a real application security assessment.\n')
            e = copy.deepcopy(self.evidence)
            e.update(path=path, sha256=hashlib.sha256(p.read_bytes()).hexdigest(), method='manual-review')
            self.manifest['design_reviews'].append({'path': path, 'reviewer': 'Synthetic Tester', 'evidence': [e]})
        for c in self.manifest['controls']:
            evidence = []
            for method in sorted(gate.DEFAULT_METHODS[c['id']]):
                e = copy.deepcopy(self.evidence); e['method'] = method; evidence.append(e)
            c.update(applicable=True, status='pass', boundary='Synthetic test boundary only', evidence=evidence)

    def save(self):
        (self.root / gate.ARTIFACTS[2]).write_text(json.dumps(self.manifest))

    def result(self):
        self.save()
        return gate.validate(self.root, self.ref, now=self.now)

    def assert_blocked(self):
        self.assertEqual(self.result()['status'], 'BLOCKED')

    def test_init_is_pending(self):
        self.assertEqual(gate.validate(self.root, self.ref)['status'], 'BLOCKED')

    def test_complete_synthetic_evidence_passes(self):
        self.assertEqual(self.result()['status'], 'BOOKKEEPING_PASS')

    def test_init_does_not_overwrite(self):
        with self.assertRaises(ValueError): gate.initialize(self.root)

    def test_missing_control_blocks(self):
        self.manifest['controls'].pop(); self.assert_blocked()

    def test_duplicate_control_blocks(self):
        self.manifest['controls'].append(copy.deepcopy(self.manifest['controls'][0])); self.assert_blocked()

    def test_pending_and_failure_block(self):
        for state in ['pending', 'fail']:
            self.manifest['controls'][0]['status'] = state; self.assert_blocked()

    def test_na_requires_reason(self):
        self.manifest['controls'][0].update(status='na', applicable=False, rationale=''); self.assert_blocked()
        self.manifest['controls'][0]['rationale'] = 'Public static project with no owned login flow'
        self.manifest['providers'][0]['controls'].remove('AUTH')
        self.assertEqual(self.result()['status'], 'BOOKKEEPING_PASS')

    def test_hash_tampering_blocks(self):
        (self.root / self.evidence['path']).write_text('changed'); self.assert_blocked()

    def test_missing_evidence_blocks(self):
        self.manifest['controls'][0]['evidence'] = []; self.assert_blocked()

    def test_stale_source_blocks(self):
        self.manifest['controls'][0]['evidence'][0]['source_ref'] = 'old'; self.assert_blocked()

    def test_stale_time_blocks(self):
        self.manifest['controls'][0]['evidence'][0]['observed_at'] = (self.now - timedelta(days=31)).isoformat(); self.assert_blocked()

    def test_path_traversal_blocks(self):
        self.manifest['controls'][0]['evidence'][0]['path'] = '../outside.txt'; self.assert_blocked()

    @unittest.skipIf(os.name == 'nt', 'Symlink privileges vary on Windows')
    def test_symlink_blocks(self):
        (self.root / 'linked').symlink_to(self.root / 'docs', target_is_directory=True)
        self.manifest['controls'][0]['evidence'][0]['path'] = 'linked/security/synthetic-proof.txt'; self.assert_blocked()

    def test_nonzero_or_boolean_exit_blocks(self):
        for code in [1, False]:
            self.manifest['controls'][0]['evidence'][0]['exit_code'] = code; self.assert_blocked()

    def exception(self, control):
        control.update(status='accepted-risk', applicable=True, risk='medium', exception={
            'owner': 'Synthetic Approver', 'issue': 'FIXTURE-ONLY', 'rationale': 'Test fixture',
            'expires_at': (self.now + timedelta(days=1)).isoformat(),
            'approval_evidence': [copy.deepcopy(self.evidence)]})

    def test_allowed_exception_and_expiry(self):
        c = next(c for c in self.manifest['controls'] if c['id'] == 'HEADERS'); self.exception(c)
        self.assertEqual(self.result()['status'], 'BOOKKEEPING_PASS')
        c['exception']['expires_at'] = (self.now - timedelta(seconds=1)).isoformat(); self.assert_blocked()

    def test_nonwaivable_and_high_exceptions_block(self):
        c = next(c for c in self.manifest['controls'] if c['id'] == 'AUTHZ'); self.exception(c); self.assert_blocked()
        c['status'] = 'pass'
        c = next(c for c in self.manifest['controls'] if c['id'] == 'HEADERS'); self.exception(c); c['risk'] = 'high'; self.assert_blocked()

    def test_high_finding_blocks(self):
        self.manifest['findings'] = [{'id': 'F1', 'severity': 'high', 'status': 'accepted-risk'}]; self.assert_blocked()

    def test_fixed_finding_needs_verification(self):
        self.manifest['findings'] = [{'id': 'F1', 'severity': 'high', 'status': 'fixed'}]; self.assert_blocked()
        self.manifest['findings'][0]['verification_evidence'] = [copy.deepcopy(self.evidence)]
        self.assertEqual(self.result()['status'], 'BOOKKEEPING_PASS')

    def test_nonproduction_is_not_production_pass(self):
        self.manifest['environment'] = 'demo'; self.assert_blocked()

    def test_duplicate_json_key_blocks(self):
        self.save()
        p = self.root / gate.ARTIFACTS[2]
        p.write_text(p.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        self.assertEqual(gate.validate(self.root, self.ref)['status'], 'BLOCKED')

    def test_pass_or_na_cannot_hide_residual_risk(self):
        self.manifest['controls'][0]['risk'] = 'critical'; self.assert_blocked()
        self.manifest['controls'][0].update(status='na', applicable=False, risk='high', rationale='No login')
        self.assert_blocked()

    def test_source_review_only_is_insufficient(self):
        for c in self.manifest['controls']:
            for e in c['evidence']: e['method'] = 'source-review'
        self.assert_blocked()

    def test_boundary_required(self):
        self.manifest['controls'][0]['boundary'] = ''; self.assert_blocked()

    def test_placeholder_source_ref_blocks(self):
        self.ref = 'UNSET'; self.manifest['source_ref'] = self.ref
        for c in self.manifest['controls']:
            for e in c['evidence']: e['source_ref'] = self.ref
        self.assert_blocked()

    def test_schema_version_must_be_integer(self):
        for version in [True, 1.0]:
            self.manifest['schema_version'] = version; self.assert_blocked()

    def test_unknown_fields_block(self):
        self.manifest['controls'][0]['statuz'] = 'fail'; self.assert_blocked()

    def test_unreviewed_design_blocks(self):
        self.manifest['design_reviews'] = []; self.assert_blocked()

    def test_runtime_target_required(self):
        self.manifest['controls'][0]['evidence'][0].update(method='runtime', target='', environment='production')
        self.assert_blocked()

    def test_extreme_timestamp_is_structured_block(self):
        self.manifest['controls'][0]['evidence'][0]['observed_at'] = '0001-01-01T00:00:00+23:59'
        self.assert_blocked()

    def test_every_provider_needs_its_own_evidence(self):
        self.manifest['providers'].append({'id': 'second-host', 'kind': 'Different provider',
            'target': 'second.invalid', 'environment': 'production', 'owner': 'Tester', 'controls': ['HEADERS']})
        self.assert_blocked()
        c = next(c for c in self.manifest['controls'] if c['id'] == 'HEADERS')
        e = copy.deepcopy(self.evidence)
        e.update(method='runtime', provider_id='second-host', target='second.invalid')
        c['evidence'].append(e)
        self.assertEqual(self.result()['status'], 'BOOKKEEPING_PASS')

    def test_provider_target_mismatch_blocks(self):
        self.manifest['controls'][0]['evidence'][0]['target'] = 'wrong.invalid'; self.assert_blocked()

    def test_missing_provider_inventory_blocks(self):
        self.manifest['providers'] = []; self.assert_blocked()

    def test_design_placeholder_blocks_even_with_matching_hash(self):
        p = self.root / gate.ARTIFACTS[0]; p.write_text(gate.PENDING_MARKER)
        self.manifest['design_reviews'][0]['evidence'][0]['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
        self.assert_blocked()

    def test_design_hash_mismatch_blocks(self):
        (self.root / gate.ARTIFACTS[0]).write_text('changed design'); self.assert_blocked()

    def test_deep_json_is_structured_block(self):
        p = self.root / gate.ARTIFACTS[2]; p.write_text('[' * 2000 + '0' + ']' * 2000)
        self.assertEqual(gate.validate(self.root, self.ref)['status'], 'BLOCKED')

    def test_reducing_required_methods_blocks(self):
        for c in self.manifest['controls']: c['required_methods'] = ['source-review']
        self.assert_blocked()

    def test_runtime_without_provider_blocks(self):
        c = next(c for c in self.manifest['controls'] if c['id'] == 'HEADERS')
        del c['evidence'][0]['provider_id']; self.assert_blocked()


if __name__ == '__main__':
    unittest.main(verbosity=2)
