# Audit method

Use this procedure in audit mode, and on your own code before calling a start-mode feature done. The catalog in `references/controls.md` says WHAT to check; this file says HOW to check it so that nothing is skipped silently. Work through every phase. A phase that does not apply still gets one line in the coverage table saying why.

## Phase 1. Map the attack surface before judging anything

1. List every file, including dotfiles (`.env`, `.git/`, `.npmrc`, backups, `*.pem`), deploy files (Dockerfile, compose, Procfile, fly/render/vercel/netlify config, IaC, CI workflows) and dependency manifests and lockfiles. Note what is missing: no lockfile, no `.gitignore`, no tests.
2. Build an **entrypoint table** with one row per route, view, RPC method, GraphQL resolver, websocket handler, webhook, background job, queue consumer, CLI command and static-file mount. Columns: method/path, authentication, where the tenant/owner ID comes from (server session or client input), role check, inputs (path, query, body, headers, cookies, files), sinks reached, state changed, browser-cookie auth (CSRF relevant).
3. Build a **trust-boundary list**: identity provider, database, cache, object storage, payment and webhook senders, outbound HTTP, email/SMS, AI APIs, the CDN or proxy in front, and the host. For each, record what the code trusts from it.
4. Record the framework and library versions from manifests. Note security defaults that the code switches off.
5. For React, Next.js, other SPAs, server-side TypeScript or a browser-called backend-as-a-service, add the entrypoints and sink patterns from `references/web-react-typescript.md` to this map and to Phase 3.

## Phase 2. Walk every entrypoint

For each row of the entrypoint table, answer each question with file:line evidence:

- **Authentication.** Is it required? Can it be bypassed (missing dependency or decorator, middleware order, alternate method such as HEAD or OPTIONS, trailing-slash variants)?
- **Object authorization.** Is every object loaded by ID re-checked against the caller's owner, tenant and role on the server? Does a list, search, count or export filter by a tenant taken from the session, never from a query parameter or body?
- **Function authorization.** Are admin and staff functions checked server-side, with the role read from the server's record, not from a token claim or client field the user controls?
- **Field authorization.** Is the body bound to an explicit allowlist? Flag `setattr` loops, `**body`, `Object.assign`, deep merges, `fields = "__all__"` and ORM `update(**data)` (CWE-915).
- **Input to sink.** Follow every input to SQL/NoSQL, shell, template, HTML, regex, path, URL fetch, deserializer, redirect, log line or header. Does the value cross a boundary unvalidated?
- **State change.** Is the operation idempotent and atomic? Can it run twice concurrently? Can values be negative, zero, huge, non-finite or in another currency?
- **Browser.** Cookie-authenticated and state-changing means CSRF protection is required. State-changing GET is a finding.
- **Errors.** What does a failure return? Stack traces, SQL or exception text, or a different message per case (account enumeration) are findings.

## Phase 3. Sweep for dangerous sinks

Search the whole codebase for these patterns, then trace each hit back to its source. A hit with no attacker-controlled path is noted as reviewed and dismissed, with the reason.

| Class (CWE) | Python | JavaScript / TypeScript | Other stacks |
|---|---|---|---|
| SQL/NoSQL injection (89, 943) | f-string or `%`/`+` in `execute`, `raw(`, `extra(`, `text(` | template literal in `query(`, `$where`, query objects built from `req.body`/`req.query` without type checks | string-built queries, `Statement` instead of `PreparedStatement`, PHP `mysqli_query` with concatenation |
| Command injection (78) | `subprocess` with `shell=True`, `os.system`, `os.popen` | `exec(`, `execSync(`, `spawn(..., {shell:true})` | `Runtime.exec` with a string, Go `exec.Command("sh","-c",...)`, PHP `system`/backticks |
| Code / template injection (94, 1336) | `eval`, `exec`, `render_template_string` with input, `Template(user)` | `eval`, `new Function`, `vm.run*`, server templates compiled from input | expression-language evaluation of input |
| Unsafe deserialization (502) | `pickle`, `yaml.load` without `SafeLoader`, `jsonpickle`, `shelve` | `node-serialize`, `funcster`, YAML with custom types | Java `ObjectInputStream`, PHP `unserialize`, .NET `BinaryFormatter` |
| XSS (79) | `mark_safe`, `\|safe`, `Markup(`, `autoescape false`, HTML built with string formatting | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `res.send` of a template literal containing data, Markdown rendered without a sanitizer | unescaped template output |
| Path traversal / zip slip (22) | `open`, `send_file`, `os.path.join` with input (an absolute input discards the base), `extractall`, writing `ZipFile.namelist()` names | `path.join`/`res.sendFile`/`res.download` with input, `express.static` of the project root, archive extraction | same |
| SSRF (918) | `requests`/`httpx`/`urllib` with a user URL, redirects on | `fetch`/`axios`/`got` with a user URL | same |
| Open redirect (601) | `redirect(next)`, `RedirectResponse(user)` | `res.redirect(req.query.*)` | same |
| ReDoS / regex injection (1333) | nested quantifiers such as `(x+)*` or `(a\|a)*`, `re.compile(user)` | `new RegExp(user)`, nested quantifiers | same |
| Prototype pollution (1321) | n/a | `_.merge`/`_.set`/`defaultsDeep`/hand-written deep merge of `req.body`, `obj[key] = ` with a user key | n/a |
| Weak randomness (330) | `random.` for tokens, IDs or reset codes | `Math.random()` for tokens | `java.util.Random`, `rand()` |
| Weak crypto / hashing (327, 916) | `md5`, `sha1`, unsalted `sha256` for passwords, `==` on MACs (208) | `crypto.createHash('md5')`, `===` on signatures | same |
| JWT misuse (347) | `algorithms` taken from the token header, `verify_signature: False`, `decode` without `algorithms=`, no `exp`/`aud`/`iss` | `jwt.verify` without `algorithms`, `jwt.decode` used as verification, `none` accepted | same |
| Secrets in code (798) | literal keys, default secret fallbacks such as `os.environ.get("SECRET", "dev")` | `process.env.X \|\| "literal"`, committed `.env` | same |
| Sensitive data exposure (200, 209, 532) | tracebacks or `str(exc)` returned, logging headers, tokens, passwords or full request bodies | `err.message`/`err.stack` sent to client, `console.log(req.headers)` | same |

Then sweep configuration:

- **Cookies.** Secure, HttpOnly, SameSite, lifetime, `__Host-` prefix. Framework settings: Django `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`; Express `res.cookie` options; Flask `SESSION_COOKIE_*`.
- **Security headers.** CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`, Referrer-Policy. Check whether the app, the framework (Helmet, Django `SECURE_*`) or the proxy sets them, and mark them UNVERIFIED when only the proxy could set them.
- **CORS.** A wildcard or origin-reflecting regex together with credentials is a finding.
- **Debug and hosts.** `DEBUG`, `app.debug`, Werkzeug debugger, `ALLOWED_HOSTS = ["*"]`, `x-powered-by`, directory listing, static roots that include source or `.env`.
- **Containers and deploy.** Root user, unpinned base image, secrets baked into image layers, ports bound to 0.0.0.0 without a proxy, health endpoints that leak data.

## Phase 4. Reason through cross-file flows

Grep cannot find these. Trace each flow end to end:

- **Login and identity.** Password hashing algorithm, enumeration through messages or timing, rate limit, lockout. OAuth/OIDC: `state` and `nonce` generated, stored and checked; code actually exchanged; `id_token` signature, issuer, audience and expiry verified; redirect URI fixed; account linking only through verified email.
- **Token lifecycle.** Lifetime, rotation, revocation on logout, password change and role change; where the role and tenant used for checks come from.
- **Account recovery.** Reset token randomness (at least 128 bits from a CSPRNG), expiry, single use, stored hashed, bound to the account, generic response.
- **Money, credits, stock and bookings.** Sign and bounds of amounts, decimal precision, atomic conditional updates or row locks, database constraints, idempotency keys, double submit and concurrent requests, refunds and reversals.
- **Webhooks.** Signature over the raw body, constant-time comparison, timestamp tolerance, event ID deduplication, and amounts and user IDs taken from a server lookup rather than trusted metadata.
- **Multi-tenancy.** The tenant ID used for every query comes from the server-side principal. Shared in-memory or global state is not leaked or mutated across tenants.
- **Files.** Upload type, size and name handling; storage location relative to the static root; who can download; content type served.

## Phase 5. Run tools, and record what could not run

Start with the bundled scanner. It is read-only, writes its report outside the project, and runs built-in checks (secrets and public env variables, Supabase RLS/policies/storage/functions, Firebase rules and service-account files, Next.js/Vite/hosting config, Dockerfiles, lockfiles) plus every applicable standard tool below:

`python <baseline-dir>/scripts/security_scan.py <project-root> --out <os-temp-dir>/icezy-scan` (or `icezy-audit scan <project-root>` when the CLI is installed). Add `--offline` when network access is not allowed.

Treat its output as leads. Confirm each finding against the code and the installed versions before reporting it, dismiss false positives with a reason, and copy its tool table (RAN / NOT_RUN / FAILED) into your report. Then run anything else that is available, with exact versions and commands, against a copy or read-only. Ephemeral runners that do not modify the project (`uvx`, `pipx run`, `npx --yes`) are acceptable when network access exists. Download only well-known tools from official registries.

- Python: `bandit -r <src> -f json`; `pip-audit -r requirements.txt` (needs the OSV/PyPI feed).
- JavaScript: `npm audit --omit=dev --json` (needs a lockfile; if there is none, report that the audit could not run and why).
- Any language: `semgrep scan --config p/default` (fetches rules from the registry); `gitleaks detect --no-git -s <dir>` or a secret-pattern grep.
- Container and IaC: `trivy fs` or `trivy config` when available.

A tool that is missing, offline or failing is reported as **NOT RUN**, never as clean. When SCA cannot run, still review each pinned dependency version yourself. Name the advisories you know for it (CVE or GHSA ID, affected range, fixed version, and whether the vulnerable code path is reachable in this app), mark them "unconfirmed until SCA runs", and flag end-of-life major versions.

## Phase 6. Prove Critical and High findings

For each Critical or High finding, try a minimal reproduction that touches nothing real:

- Run the vulnerable function or expression in isolation: an in-memory SQLite database, a regex timed on a crafted string, a JWT built with `alg: none` against the verification code, `os.path.join` with `../` or an absolute path, a YAML or pickle payload that only constructs a harmless object, two threads against an in-memory model for a race.
- Use only the OS temporary directory outside the project, delete what you create, and never call external services, the real database or production URLs.
- When the needed library is not installed and cannot be run ephemerally, say so and label the finding **code-read** rather than **reproduced**.

## Phase 7. Report

1. **Decision**: BLOCKED or not, with the reason in one sentence.
2. **Findings**, ordered by severity. Each has: ID, title, severity (Critical/High/Medium/Low with a one-line exploit rationale), CWE ID, OWASP Top 10:2025 category, internal control ID, file:line, attack scenario, fix, and evidence class (reproduced / tool / code-read).
3. **Entrypoint table** with a verdict per row.
4. **Coverage table**: every internal control ID from `controls.md` marked findings / checked-clean / N/A (with reason) / UNVERIFIED (with what access is missing). Every sink class from Phase 3 marked searched or not.
5. **Tools run and not run**, with versions and reasons.
6. **Provider matrix** per `templates/PROVIDER-MATRIX.md`.
7. **Unknowns and questions for the owner.**
8. **Fix order**: what to do today, before release, and later.

Never report "no vulnerabilities" or "secure". Report what was checked, how, and what remains unverified.
