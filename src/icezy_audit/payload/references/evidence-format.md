# Evidence manifest and CI integration

`security-controls.json` is initialized with every internal control pending, applicability null, environment undecided and source_ref UNSET. Complete the project profile/threat model and real implementation/tests before changing status. Record a named review of each design document with its source-bound content hash and remove the exact [SECURITY-DESIGN-PENDING] initializer marker. `providers` must list every in-scope service (including self-hosted targets), owner, target, environment and nonempty applicable control IDs; every declared service/control pair needs separately linked evidence. See templates/PROVIDER-MATRIX.md. The gate has a default 30-day evidence age window; choose a stricter policy when needed. Evidence must also match the exact supplied build/source reference, so old tests do not silently apply to a new release.

## Per-control record

```json
{
  "id": "AUTHZ",
  "applicable": true,
  "status": "pass",
  "risk": "none",
  "boundary": "Trusted backend API and object-storage policy",
  "required_methods": ["test"],
  "rationale": "Tenant and resource enforcement at the trusted API and storage rules",
  "evidence": [{
    "path": "docs/security/evidence/authz-test.txt",
    "sha256": "REPLACE_WITH_ACTUAL_FILE_SHA256",
    "source_ref": "REPLACE_WITH_REVIEWED_BUILD_ID",
    "observed_at": "REPLACE_WITH_ACTUAL_ISO_TIMESTAMP_WITH_TIMEZONE",
    "method": "test",
    "description": "Actual tenant A/B, anonymous, expired and role-downgrade regression results",
    "command": "REPLACE_WITH_ACTUAL_EXECUTED_TEST_COMMAND",
    "exit_code": 0
  }]
}
```

The placeholders are intentionally unusable; never copy them as proof. Use only immutable `git:<40-or-64-hex>` or `sha256:<64-hex>` identities and bind them to the actual checked-out/tested artifact with trusted CI; source-ref equality is not authenticated provenance. Risk means unresolved residual risk: PASS and N/A require none. Unknown fields are rejected at each interpreted record; place non-authoritative metadata under extensions. SHA256 binds the file, not the truth of its contents. The validator does not run the command or authenticate who produced it. Reviewers must inspect evidence and the actual target. Runtime evidence requires provider_id, target and environment matching an inventoried service. All provider-linked evidence, including tests or reviews, must match its provider target/environment. Each service's declared control needs its own evidence; an AWS test cannot cover a Vercel deployment merely because the control ID is the same. For controls with minimum runtime verification, EACH linked provider needs runtime evidence. The default minimum classes are defined in DEFAULT_METHODS in scripts/security_gate.py: authentication/session need test + runtime, crypto needs source-review + runtime, hosting headers/config/logs/restore need runtime, privacy needs manual-review, and other baseline controls need test. required_methods may add classes but cannot remove these minima. Static apps can justify whole controls as N/A where genuinely absent; when a minimum seems inappropriate, review and explicitly revise the shared policy rather than silently relabeling source review as a runtime test. This conservative policy is a local choice, not an OWASP mandate.

Manual/runtime/source-review evidence needs a nonempty description and real observed timestamp; source inspection alone cannot establish live IdP/MFA/hosting/TLS behavior. Named design reviews must hash each actual PROFILE.md and THREAT-MODEL.md, not just a generic test log. Findings marked fixed need current verification evidence.

For N/A: status na, applicable false, and a specific rationale tied to project features/trust boundaries. 'Not implemented yet' is pending, not N/A. Missing identity/upload/etc functionality can make a control inapplicable, but do not exempt a trusted API merely because the UI hides the feature.

For accepted-risk: applicable true, risk low/medium, exception with owner, issue, rationale, future expires_at, and approval_evidence in the same evidence format. AUTHZ/CRYPTO/CONFIG/BUSINESS and high/critical findings cannot be waived by the helper. Policy must additionally require genuine owner approval outside agent-authored assertions. A matching accepted finding references control_id; fixed findings need verification_evidence. Open findings block this conservative production gate even when low risk; decide explicitly whether to fix or approve an allowed low/medium exception.

## Commands

Invoke through Hermes terminal, using the real discovered skill path:

```text
python <skill-dir>/scripts/security_gate.py init --root <existing-project-root>
python <skill-dir>/scripts/security_gate.py check --root <project-root> --source-ref <reviewed-build-id>
python <skill-dir>/scripts/test_security_gate.py
```

Init refuses to overwrite any existing profile/threat/manifest. Check prints BOOKKEEPING_PASS or BLOCKED and returns 0 or 1. This is not a vulnerability scan and never means 'safe to deploy' by itself. It reads local evidence only and makes no network calls or application-code execution.

## Protected CI plan, not installed by this skill

1. Commit reviewed policy/instructions/helper or pin a reviewed skill version within the project; do not depend on the developer's home directory in CI.
2. Run actual unit/integration/rules/secret/dependency and relevant security checks against a concrete immutable build identity. Save only non-secret evidence under a controlled CI artifact policy; keep private test output out of a public repository.
3. Run the bookkeeping gate on the same identity. Require independent review of applicability, findings, policy changes and exceptions. Do not let a PR both remove a required check and approve itself.
4. Configure required checks/branch protection and restrict production credentials in the hosting control plane. Verify configuration by readback. An agent that can freely rewrite policy, evidence and CI is not subject to a strong independent gate.
5. Treat failed/unavailable scans, expired evidence, unverified deployment facts and dirty-build mismatch as blocked, not a fabricated pass. Do not make a network restriction disappear by disabling a scanner.

Filesystem scope: the helper rejects absolute/traversal/symlink evidence paths and caps sizes, but is designed for a quiescent trusted checkout. It is not a race-safe hostile multi-user filesystem sandbox, a CI attestation verifier or a defense against a malicious agent forging its entire manifest. Enforce those boundaries outside the model.
