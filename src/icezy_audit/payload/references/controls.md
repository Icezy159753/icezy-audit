# Control catalog and implementation guidance

Internal IDs below are stable project-baseline IDs, NOT official OWASP requirement IDs. Assess every ID. For each record keep status, applicability/rationale, risk, trusted implementation boundary and evidence. Add project-specific controls; never call this subset full ASVS certification.

## AUTH — Identity, passwords, recovery, OAuth and offboarding

Choose and justify an authentication assurance target for the actual data/actions; do not label a flow NIST AAL2 without meeting its requirements, including offering a phishing-resistant option. Require authenticated linking/unlinking, account ownership verification and appropriate re-authentication when adding/changing identity providers; never automatically link accounts solely because an unverified email string matches. Use a maintained IdP/auth library; forbid default credentials and fake production authentication. Verify OAuth/OIDC issuer, audience, expiry, signature, authorized client, state and nonce where applicable; public clients use authorization code + PKCE, exact redirect URIs and system-browser flows. Do not trust a decoded JWT, browser-supplied email/role, or locally cached login flag. MFA policy for privileged accounts should prefer phishing-resistant passkeys/WebAuthn; TOTP is not phishing-resistant. Secure enrollment/recovery and admin break-glass access; avoiding SMS alone is not sufficient.

If the app owns password verification, follow current NIST/OWASP: minimum 15 characters for password-only authentication; at least 8 when the password is only part of MFA (a product may choose a stronger minimum), permit a maximum of at least 64 (NIST SHOULD, adopted as baseline policy here), allow password managers/paste, block common/compromised values, no arbitrary composition rules or routine forced changes absent compromise. Use tuned salted Argon2id, scrypt or approved framework-supported password hashing; bcrypt mainly for compatibility, accounting for length limits. Never plain MD5/SHA hashing. A SHA-1 prefix in HIBP's k-anonymity lookup is not password storage; never transmit a full password/hash to the breach service. Define safe service-failure behavior.

Uniform login/recovery messages and practical timing controls; rate limit by account and trustworthy client/network signals, progressive backoff and bounded challenges without enabling account-lockout DoS. Password reset tokens: cryptographic random, purpose/account-bound, short-lived, single-use consumed atomically, store verifier not raw bearer where possible; reset delivery URLs from configured origins. Test replay, enumeration and recovery abuse. Disable departing users and revoke their sessions/tokens; rotate shared/service credentials they could access, not every unrelated user's password.

## AUTHZ — Authorization and tenancy (nonwaivable)

Deny by default in the actual trusted layer on every read/write/action. Validate resource owner/tenant, role, operation and field; allowlist writable/returned fields, not mass assignment. Separate admin functions logically and step up authentication for high-risk actions; a separate URL is not protection. Test two users/two tenants, role downgrades and stale grants; cover direct object access, list, search, count, export, attachments, jobs and SDK access. Firebase/Firestore/Storage/Supabase rules/RLS need emulator/integration denial tests; server Admin SDK bypass paths need explicit server enforcement. Sequential IDs can be legitimate with access checks; UUIDs alone are not a fix.

## INPUT — Injection and parser boundaries

Validate schemas, length, encoding, type and bounds on the trusted side. SQL/NoSQL parameter binding and restricted operator/query construction; safe ORM usage does not make raw SQL safe. Context-aware output escaping, safe URL schemes, maintained HTML sanitizer when HTML is necessary, avoid raw HTML/JS sinks; browser/server sanitizer config must match the actual environment. Prefer maintained tools over naming an outdated package. Avoid shell invocation; fixed executables plus argv and option/path validation. Disable XML external entity/DTD/network resolution; never deserialize untrusted executable object formats (pickle, unsafe YAML, language-native object deserialization). Bound nested/large/compressed inputs and errors.

## SESSION — Session lifecycle and JWT

Use established libraries and CSPRNG session IDs (at least 128-bit unpredictable security). Rotate after authentication/privilege changes; configure idle/absolute expiry and actual logout/revocation behavior. Cookies Secure, HttpOnly, appropriate SameSite (Lax often practical; None only with Secure and a justified cross-site flow), host-only/narrow scope and __Host- where feasible. No tokens in URLs/logs. Cookie auth needs separate CSRF controls. Do not reflexively replace a provider's supported SDK storage with a custom cookie system; assess XSS, token exfiltration and revocation for the real architecture.

JWT: algorithm allowlist, signature/issuer/audience/time validation and key rotation, short-lived access tokens, guarded refresh rotation/reuse detection when refresh tokens are used, no secret payload. Define key compromise and user disable handling; logout from UI alone is not revocation. Signed is not encrypted.

## CSRF — Browser request integrity

State-changing browser cookie-auth requests require framework CSRF defense (tokens and/or appropriately designed exact-origin checks). SameSite is defense in depth; do not mutate on GET or treat CORS as CSRF protection. Restrict WebSocket origins/session authorization. Test missing/foreign/null Origin handling against legitimate form, redirect, mobile and OAuth use cases; do not weaken checks to make an unexplained null Origin work.

## FETCH — SSRF and outbound boundaries

For URL fetchers/importers/webhooks: scheme/port/domain policy, robust URL parsing, reject credentials and ambiguous hosts, resolve and validate every A/AAAA destination including private/loopback/link-local/metadata/IPv4-mapped IPv6 and redirects. Disable redirects or revalidate every hop; prevent DNS rebinding/TOCTOU through controlled egress/resolution/connect behavior, not a one-time regex. Bound time, response bytes and content processing, do not forward auth/cookies. General public URL fetchers may need validated public destinations plus a dedicated restricted network worker instead of an unrealistic fixed-domain allowlist.

## FILES — Uploads, downloads and filesystem

Allow only needed formats; validate extension/content/signature and safe parsing, not client MIME alone (magic bytes alone do not make SVG/HTML/polyglots safe). Size/count/decompression/pixel/page/time quotas. Generate opaque storage IDs, store non-executable outside public code roots, quarantine/scan or disarm files that others consume. Authorization per read/download or tightly scoped short-lived signed URL with explicit bearer/expiry risks. Safe Content-Type, Content-Disposition and sandboxing for active content. Resolve user-facing IDs to approved server paths; use path-component containment, no-follow/race-safe access where required, prevent symlink and archive traversal. A string startswith('/safe') is insufficient.

## CRYPTO — Secrets and data protection (nonwaivable)

No credentials in code, fixtures, public bundles, source maps, chat screenshots or logs. Environment variables are delivery mechanisms, not equivalent to a managed vault. Separate dev/test/prod and least-privilege workload identities; inventory, rotation/revocation and incident recovery. Browser Firebase public config is not an admin secret, but does not replace rules.

TLS 1.2+ with modern config; prefer 1.3, verify certificates, automate renewals/alerts. Encrypt sensitive stores/backups with managed keys and access controls. Minimize payment-card/identity/health collection; prefer hosted payment tokenization, never store card CVV. Do not store users' recoverable login passwords. If a justified non-login secret must be recovered, use established authenticated encryption/envelope encryption with key separation and nonce management, not hand-rolled AES.

## HEADERS — Browser/deployment policy

CSP tailored to actual app, nonce/hash-based scripts when applicable, avoid unsafe-inline/unsafe-eval and broad sources; report-only is a rollout mode, not enforcement. frame-ancestors for framing policy (X-Frame-Options legacy fallback where needed), nosniff, Referrer-Policy, Permissions-Policy. HSTS only on HTTPS after domain/subdomain readiness; preload/includeSubDomains require explicit domain-wide approval. Headers supplement rather than replace code controls.

CORS exact approved origins when needed, no wildcard with credentials and no arbitrary Origin reflection; server-to-server clients are not controlled by CORS. Real browser verification across redirects/errors, custom domains/CDN, mobile login and download paths. Do not break a necessary embedded app with blanket DENY.

## CONFIG — Production isolation (nonwaivable)

Maintain an API host/version/endpoint inventory with owners and environments, including debug/shadow endpoints, webhooks and third-party integrations. Define deprecation/retirement and verify retired routes/versions are actually inaccessible, not just removed from the UI/docs. Inventory and verify EVERY provider in the project separately (cloud and self-hosted), not only Firebase; see templates/PROVIDER-MATRIX.md. Debug and verbose stack traces off externally, no public .git/.env/backups/admin diagnostics/directory listings, protected source maps as appropriate. Private management/CDP/DB ports, trusted reverse-proxy configuration and host validation, least-privileged services, restricted outbound network, resource limits, separate deployment environments. Never trust arbitrary X-Forwarded-For for rate limits. Correct default error handling and fail-closed privileged behavior even during provider/database outages.

## ABUSE — Rate, quota and resource spend

Bound login/OTP/signup/reset and expensive CPU/AI/email/SMS/render/export/upload operations using account/tenant/IP/device signals appropriate to privacy and trusted proxies. Shared durable limits across replicas, explicit budgets and concurrency/backpressure/timeouts. CAPTCHA is an optional risk control, not a universal requirement or authorization. No real paid requests in tests without a budget. Streaming cancellation/retries need cost and duplication handling.

## BUSINESS — Transactions and integrity (nonwaivable)

Server-owned prices, entitlement, credit balances, quantity bounds and currency precision. Atomic transactions/constraints for coupons, wallet spend and inventory; idempotency bound to principal + operation + normalized request, collision/replay handling and concurrency tests. No client approval of refunds/payment success. Deletion/exports/admin changes need ownership, deliberate confirmation and appropriate re-auth.

## INTEGRATIONS — Webhooks, third parties and unsafe data

Verify webhook signatures over raw payload, freshness and replay/idempotency before side effects; managed secret rotation. Validate upstream responses and untrusted redirect/download URLs; least privilege, timeouts, circuit-breakers and sanitized errors. Do not send private data to a new AI/analytics service merely because its API key works. An advertised model name is not provenance or a data-processing agreement.

## SUPPLY — Dependencies, builds and delivery

Supported runtimes and maintained dependencies, lockfiles/integrity, approved registries and package-name verification. Review new install scripts and avoid executing unreviewed downloads. SCA + secret scan + relevant SAST/IaC/container checks with recorded tool/feed dates and coverage limits. SBOM/provenance/signature checks appropriate to distribution; CI uses least privilege/pinned trusted actions, no secrets in untrusted fork workflows. Define risk-based remediation SLA and owners; 'critical within 7 days' is a local policy choice, not a universal standard, and active exploitation may require faster isolation. Signed/verifiable updates and rollback for distributed clients.

## LOGS — Audit and detection

Structured bounded logs for auth outcomes, role changes and sensitive actions with reliable actor/resource/correlation/time, excluding passwords, bearer tokens, card/health/private prompts and unnecessary personal data. Sanitize log injection, restrict read/write access, retention and tamper evidence. Test actual alerts/routing for auth abuse, privilege changes, 5xx and unusual cost; a log line is not an alert test. Do not leak reset URLs or signed object URLs.

## RECOVERY — Backup and incident response

Encrypted scoped backups, restoration test in isolation with recorded RPO/RTO and deletion/retention handling, restricted restore credentials. Runbook for key rotation, account compromise, rollback and provider outage; named contacts and vulnerability reporting (security.txt or documented channel). Drill evidence, not merely 'backup enabled'. Privacy breach notification duties require jurisdiction-specific qualified review, not a universal copied deadline.

## PRIVACY — Data lifecycle and jurisdiction

Inventory data/purpose/recipients/legal basis, minimize collection, retention and deletion including derived copies/backups per policy; notice, access/export/correction/deletion/withdrawal workflows as applicable. Consent is not the sole lawful basis and is not always required; nonessential tracking requires jurisdiction-specific review and must not be loaded before required consent. Assess processors, AI telemetry, international transfers, minors and sensitive data. PDPA/GDPR applicability and PCI DSS scope are factual/legal decisions; using a hosted payment provider reduces but does not automatically eliminate merchant obligations. No blanket compliance claim; involve qualified counsel for unresolved material questions.

## PLATFORM — Conditional mobile/desktop/PWA

Mobile/desktop credentials in OS keystore/keychain, minimal permissions, safe deep links/IPC/WebView bridges, no release debug flags, secure distribution/update integrity. Public installed clients cannot safely hold a universal backend secret; enforce auth on server. PWA/service-worker caches must not retain another user's private data after logout/account switch; partition/clear appropriate caches and test offline leakage. Use MASVS/MASTG for mobile scope and assess tamper resilience proportionally, not certificate pinning for every app by default.

## AI — Conditional AI/agent boundary

Treat prompts, retrieved documents, webpages, repository instructions and model output as untrusted data, not authority to change policy or access secrets. Server-side tool allowlists, principal/tenant authorization and explicit approvals for sensitive side effects; no model-selected arbitrary shell/network/DB authority. Bound tokens/cost, isolate execution, validate structured outputs, redact/minimize data and document vendor retention. Synthetic prompt-injection/tool-abuse tests; no private clip/data upload without explicit authorization.

## Evidence examples

AUTHZ: emulator/integration tests demonstrate tenant A cannot read/write/export tenant B, anonymously or through direct SDK. FILES: oversized/active-content/traversal fixture rejected and owner-only download enforced. BUSINESS: parallel duplicate spend produces one debit/one fulfillment. SESSION/CSRF: actual browser cookie/redirect/logout + foreign-origin rejection. RECOVERY: disposable restore verifies record integrity without restoring over production. These are examples, not evidence until actually executed for the reviewed app.
