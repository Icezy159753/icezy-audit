---
name: secure-project-baseline
description: Use when starting or changing any app project.
version: 0.1.2
author: DP Data, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security-by-design, web, api, mobile, owasp, release-gate]
---

# Secure Project Baseline

Apply security before architecture and scaffolding, during implementation, and before release. This is a development baseline, not certification, legal advice, a penetration-test authorization, or a guarantee of safety. Do not run a full security audit merely because this skill loaded.

## Modes

The installed `icezy` command passes one mode:

- **audit**: read-only. Follow `references/audit-method.md` phase by phase for the requested scope, using `references/controls.md` as the checklist, and report in its Phase 7 format. Do not run `security_gate.py init`, create `docs/security/` artifacts, edit project code or configuration, call paid APIs, or probe live systems. Isolated reproductions may use only the OS temporary directory. Name the artifacts a later `start` run would create instead.
- **start**: apply Gates 0 to 3 before and during implementation, including `security_gate.py init`, within the scope the user authorized. Build with `references/secure-build.md`: its structure, day-one defaults, never-do list and per-feature tests. Before calling a feature done, run `references/audit-method.md` Phases 2 to 4 on your own diff.

In both modes, run the bundled read-only scanner early: `python <baseline-dir>/scripts/security_scan.py <project-root> --out <os-temp-dir>/icezy-scan`. It covers secrets, Supabase and Firebase policies, web and container config, and runs npm audit, pip-audit, semgrep, bandit, gitleaks, trivy and osv-scanner when available. Its findings are leads to verify, and a tool it reports as NOT_RUN gives no assurance.

In both modes, when the project uses React, Next.js, another SPA framework, server-side TypeScript, or a browser-called backend-as-a-service such as Supabase or Firebase, also read `references/web-react-typescript.md` and apply it.

If no mode was given, ask which mode the user wants.

## When to Use

- Start, scaffold, design, extend or release a web app, PWA, API, mobile/desktop app or background service. Apply proportionally to changed trust boundaries in existing projects.
- A UI-only mock still needs safe assets, secrets handling and an explicit prohibition on production/private data; do not add unnecessary login or a backend to a public static site.
- Supplement existing project-specific release skills; never weaken their auth, data-preservation or deployment requirements.

## Prerequisites

Use project-local instructions, existing architecture and official framework documentation. Read `references/controls.md`, `references/sources.md` and `references/evidence-format.md`. Recheck current standards and supported framework/runtime releases at project kickoff; retain versioned source references. Never invent ASVS requirement numbers.

`<baseline-dir>` below means the directory that holds this SKILL.md. The installed `icezy` adapter gives its absolute path. Run the helper scripts with whatever shell tool your client provides.

## Procedure

### Gate 0 — Discover before code

1. Inspect the requested project root, repository status and existing instructions without exposing secrets. Identify public surfaces, trusted server/BaaS rules, identities/roles/tenants, sensitive data, uploads, URL fetching, paid calls, payments, webhooks, AI and hosting.
2. Inventory EVERY provider actually used by this project, not just Firebase: hosting/serverless/VPS/containers, DNS/CDN/WAF/tunnels, databases/BaaS, identity/OAuth, object storage, secrets/KMS, CI/CD/registries, AI/API gateways and their downstream data processors when known, payments, email/SMS, analytics/logging and backups. Discover from dependency/config/deployment/IaC files and owner-approved control planes without printing secrets; distinguish configured, live, legacy and unknown integrations. Add a provider matrix with service ID, purpose, environment/target, owner, data handled, access boundaries, applicable controls and evidence/limitations. Missing backend/control-plane access is UNVERIFIED, never PASS. Record scope in `docs/security/PROFILE.md`: data classification, deployment targets, jurisdictions needing legal review, auth ownership, threat model/trust boundaries, control applicability, service owners and explicit unknowns. Choose conservative defaults and proceed with reversible work; ask only for decisions materially changing data exposure, spending, identity or legal scope.
3. Select verification target: applicable OWASP ASVS 5.0.0 controls for web/backend (L2 target for typical authenticated/private-data production apps; L1 can suit lower-risk scope; L3 requires explicit elevated rigor), API Security Top 10 for APIs, MASVS/MASTG for mobile. These are targets, not achieved compliance. A desktop client still needs server authorization, secure OS storage, safe IPC and signed updates where applicable.
4. Read `templates/PROVIDER-MATRIX.md` to structure cross-provider coverage. In start mode, initialize with `python <baseline-dir>/scripts/security_gate.py init --root <project-root>`. The helper creates a pending internal-control matrix and profile outline, never marks controls passed or changes app code. Existing artifacts must not be overwritten. Every baseline control must be assessed; conditional controls need a justified N/A, not silent removal.
5. Finish a principal/resource/action matrix and concrete abuse cases before implementing affected privileged/data-bearing paths. Produce `docs/security/THREAT-MODEL.md`. Link design decisions and tests to stable internal control IDs, not guessed external IDs.

### Gate 1 — Build secure defaults

Use maintained framework/managed-identity mechanisms instead of custom crypto/auth. Prefer the owner's approved Google/OIDC flow when appropriate; no password database means password-storage controls may be N/A but token verification, authorization, sessions, recovery and MFA policy still apply. Browser restrictions are never authorization. Use the actual provider's trusted boundary: BaaS rules/RLS, database grants, backend middleware, cloud IAM/resource policies, signed URLs, edge/access gateways or managed IdP controls. Test all applicable paths including storage/query/list/SDK and cross-service delegation. Firebase is only one example, not a default assumption. Supabase/Postgres RLS, AWS/GCP/Azure IAM, Vercel/Cloudflare functions, self-hosted APIs and other providers each need their own official current configuration guidance and relevant negative tests. Admin/service credentials may bypass client policies and require their own server checks.

Read `references/controls.md` for all controls and scope qualifications. Encode relevant safeguards in shared modules, database constraints, rules and tests instead of copying reminders across routes. Before each sensitive feature, state the invariant and test the deny path. Never create default admin credentials, put secrets in VITE_/NEXT_PUBLIC_ bundles, silently broaden CORS/rules, disable TLS verification, or use production identities/data to make tests pass.

### Gate 2 — Evidence while implementing

- Test anonymous, expired, revoked, wrong-role, other-user and other-tenant access against the actual trusted enforcement layer. Include list/search/export/download, batch endpoints, workers and secondary SDK paths; random IDs do not replace authorization.
- Exercise relevant input/output injection, CSRF, OAuth state/PKCE, uploads, SSRF, business race/idempotency and webhook replay checks in isolated local/emulator/staging fixtures authorized for this task. Never scan production, spend API/SMS quota, or perform destructive/security testing without scope approval.
- Run build/typecheck/unit/integration plus appropriate SAST, dependency and secret checks using actual supported tools. Capture tool versions, command, exit status, source revision/build identity and non-secret evidence. Missing scanner/network/feed access is NOT a clean scan. Review severity, reachability and dependency context; no blind `audit fix --force`.
- Keep runtime/hosting facts separate from source assertions: real headers, identity-provider policy, TLS, storage ACLs, backup restore and alerts require evidence at their owning layer. If unavailable, mark unverified; do not report PASS from a config file alone.
- Update `docs/security/security-controls.json`. Status values: pending, pass, fail, na, accepted-risk. Pass requires current-revision hashed nonempty evidence, a trusted implementation boundary and the required test/runtime/review classes; runtime evidence must identify the inventoried service and exact target/environment. Each provider's declared controls need their own linked proof. Reviewed profile/threat-model hashes must be recorded and initializer placeholders removed. `risk` means unresolved residual risk, so PASS/N-A require risk=none; N/A requires applicability reasoning. An accepted risk requires named owner approval, issue and future expiry; it cannot waive critical/high findings or the nonwaivable controls enforced by the helper.

### Gate 3 — Release decision

1. Review every applicable baseline control plus project-specific controls and external-standard mappings. Verify every in-scope provider separately against its declared controls; one Firebase rules test or one site's HTTP header response must not certify other services. Include live management-plane IAM/MFA, secret scope, backups/retention, public access, logs and data-processing policy where relevant. Discovery is not permission to run scans, spend quota or modify every account the owner has; inspect only the authorized project's dependencies and request missing scope/access when necessary. The internal checklist is not the complete ASVS or MASVS. If claiming a level, map every requirement in that exact version/level and independently verify the entire applicable set.
2. Run `python <baseline-dir>/scripts/security_gate.py check --root <project-root> --source-ref <reviewed-ref>`. Use a supported immutable identity (`git:` plus full 40/64-hex commit or `sha256:` plus 64-hex reviewed artifact/tree digest); reject placeholders/branches. A dirty tree needs a recorded manifest digest. Trusted CI must derive and bind that identity to actual checkout/artifacts; the helper only validates its format and equality, not provenance. This helper validates evidence bookkeeping only, not app behavior, code safety or legal compliance.
3. Production release remains BLOCKED on pending/failed applicable controls, unverified hosting/identity policy, missing required evidence, expired exceptions or unresolved high/critical findings. A private isolated demo may proceed only under an explicitly narrower nonproduction scope with synthetic data; never relabel it production-ready.
4. Obtain appropriate review for auth/data/finance boundaries. Verify deployment through approved project release workflows, exact target readback, backup/rollback and minimal authorized smoke checks. Preserve live owner work and prior results.
5. Write `docs/security/RELEASE.md`: target/environment/ref, standards targeted, executed checks, actual results, limitations, accepted risks and owners/expiry, deployment/rollback evidence and release decision. No generic 'OWASP compliant' or '100% secure'.

## Portable activation

For documented startup discovery across coding clients, read `references/agent-entrypoints.md` and, in start mode with the user's permission, merge `templates/project-start/` entrypoints into the PROJECT ROOT: AGENTS.md (Codex/compatible clients), CLAUDE.md (Claude Code), GEMINI.md (Gemini CLI), .github/copilot-instructions.md and .cursor/rules/security-baseline.mdc. Do not copy START-HERE.md or the baseline itself into the project. The entrypoints point every later session at the installed `icezy` skill, so one shared baseline stays in the user's home. These files request the full baseline read; they do not prove agent compliance. Existing project instruction files must be merged without overwriting, and native client loaded-context behavior must be checked separately. Web chat/model brands alone do not auto-read a local folder.

Each collaborator installs the baseline once with the `icezy-audit` installer. `templates/AGENTS.security.md` is an excerpt for a project whose instruction file cannot take the full entrypoint; merge it into the file that agent actually reads (such as AGENTS.md or CLAUDE.md), and do not overwrite owner instructions or assume all agents auto-discover the same filename. A skill is guidance, not an OS security boundary and not a guaranteed automatic hook. For stronger enforcement, wire the validator and real security tests into protected CI required checks, with reviewed policies/CODEOWNERS and deploy permissions outside the AI's control. Do not claim CI/branch protection is installed unless actually configured and read back.

## Pitfalls

- OWASP Top 10 is an awareness/risk list, not a complete acceptance specification.
- Do not apply password rules to OAuth-only projects, force JWT into a session app, or add consent dialogs everywhere. Document the actual architecture and lawful basis with appropriate review.
- SameSite, CORS, CSP and hidden buttons do not substitute for CSRF defense or authorization. Cookie and mobile redirect behavior must be tested in a real browser where applicable.
- HTTPS/encryption do not prevent an authorized server or AI vendor from processing submitted data. Minimize data and assess processors, retention, deletion and cross-border handling before integration.

## Verification

Inspect this skill's linked files, run `python <baseline-dir>/scripts/test_security_gate.py` and `python <baseline-dir>/scripts/test_entrypoints.py`, then exercise init/check on synthetic projects. Require unfinished, tampered-evidence, stale-ref, unsafe-path and forbidden-exception fixtures to fail closed, and the fully evidenced synthetic fixture to pass. Report that this proves the workflow helper, not any production application's security.
