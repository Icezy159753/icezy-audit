# Security-by-design instruction excerpt

Merge this section into the project's existing agent instructions; do not replace unrelated owner rules. Provide the complete secure-project-baseline skill directory to every participating AI agent. In Hermes, load `secure-project-baseline` before app architecture/scaffolding and before changes to security boundaries.

Before feature code: inventory EVERY provider actually used by the project (cloud or self-hosted, not just Firebase), with service owner, data handled, actual enforcement, target/environment, applicable controls and separate evidence. Document scope, data, principals/tenants, trust boundaries and misuse cases in docs/security/PROFILE.md and THREAT-MODEL.md. Assess every internal baseline control in docs/security/security-controls.json; adapt to web/API/mobile/desktop/BaaS rather than copying irrelevant controls. Do not invent an authentication system for a public static app.

Implement server/BaaS-rule authorization, secure identity/session flows, data minimization and safe defaults. Never weaken protection to make a demo pass, expose credentials, use production/private data in tests, or send data to a new external AI provider without authorization.

For each applicable control: retain actual, source-ref-bound test/deployment evidence. Distinguish PASS, FAIL, PENDING, justified N/A and explicitly approved time-limited risk. Config text/scanner installation is not runtime verification. A structural manifest check is not proof of security.

Before production release: run the skill's security_gate.py check with the reviewed source/build ref plus the real project tests/scanners. Required controls with pending/failed/stale/missing evidence block release. No unresolved high/critical findings or forbidden exceptions. Report remaining unknowns honestly in docs/security/RELEASE.md; never claim blanket OWASP/legal compliance or 100% safety.

Skill loading is not guaranteed enforcement. For protected delivery, make real tests and the manifest validator required CI checks, protect policy/workflow changes through independent review, and restrict deployment credentials outside the AI's control. Configure those external controls only when authorized and verify them by readback.
