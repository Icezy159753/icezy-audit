# Secure build guide

Use this in start mode when you design or write code. The goal is that the secure way is the only easy way: each rule below is enforced by one shared module, type or database constraint, not repeated by hand in every handler. Adapt names to the project's existing conventions. When the project already has an equivalent mechanism, use it instead of adding a second one.

## 1. Structure

Organize the code so that every request passes through the same small number of choke points:

| Layer | Owns | Never does |
|---|---|---|
| `config` | Reads environment once at startup, validates types, fails fast when a required secret is missing | Provide default values for secrets, keys or database URLs |
| `security` | Authentication dependency or middleware, the `authorize(principal, action, resource)` policy, CSRF, rate limits, security headers, cookie settings | Business logic |
| `schemas` | Request and response models with explicit allowlisted fields, types, lengths and ranges | Accept a raw `dict`, `**kwargs` or `fields="__all__"` |
| `routes` / `views` | Parse the request into a schema, call one service function, map the result to a response schema | Query the database directly or build SQL, shell, HTML or URLs from input |
| `services` | Business rules, transactions, idempotency | Read request objects or trust client-supplied tenant, role, price or owner |
| `repositories` | All data access; every query takes the principal or tenant and filters by it | Expose an unscoped "get by id" to routes |
| `integrations` | Outbound HTTP, payment, email, SMS, AI clients with timeouts, retries, allowlists and verified webhooks | Forward user URLs unvalidated or log secrets |

Keep files small and single-purpose. Type-annotate public functions. Name things for the domain. One feature equals one route module, one service module and its tests.

## 2. Defaults that every project gets on day one

- **Secrets.** Secrets come only from the environment or a secret manager. Commit `.env.example` with placeholder values, add `.env`, keys and local databases to `.gitignore`, and fail at startup when a secret is missing or still has its example value.
- **Authentication.** Use a maintained identity provider or framework auth. Hash passwords with Argon2id (or scrypt or bcrypt through a maintained library). Login and recovery give the same response whether or not the account exists. Rate-limit login, signup, reset and OTP.
- **Tokens and sessions.** Prefer server sessions with cookies that are `Secure`, `HttpOnly` and `SameSite=Lax` (`__Host-` prefix where possible). When you use JWT, fix the algorithm list in code, verify `exp`, `iss` and `aud`, keep access tokens short-lived, and support revocation. Generate every token, reset code and share link with a CSPRNG (`secrets.token_urlsafe(32)`, `crypto.randomBytes(32)`), store only a hash, give it an expiry, and consume it once.
- **Authorization.** Deny by default. Every route declares the action it performs. Object access goes through repository functions scoped by the principal's tenant. Roles come from the server-side record, never from the request body or an unverified token claim.
- **Input.** Validate every request with a schema: type, length, range, enum, and positive amounts. Query with the ORM or bound parameters only. Never pass input to a shell; call a fixed executable with an argument list when a subprocess is unavoidable. Parse YAML with safe loaders and never unpickle untrusted data. Compile no regex from user input, and avoid nested quantifiers.
- **Output.** Let the template engine escape. Sanitize any HTML you must render (DOMPurify, bleach-style allowlists, sanitize-html). Errors return a generic message and a correlation ID; details go to logs only.
- **Browser.** Apply CSRF protection to every cookie-authenticated state change, and never change state on GET. CORS lists exact origins, and credentials are never combined with a wildcard. Set CSP, HSTS (HTTPS only), `X-Content-Type-Options: nosniff`, `frame-ancestors` and Referrer-Policy through one middleware (Helmet, Django `SECURE_*` settings, or an equivalent).
- **Files.** Enforce an allowlist of types checked by content, a size limit, server-generated names, storage outside any static or public root (or private object storage), authorization on every download, and `Content-Disposition: attachment` for user content. Extract archives only after you check that each member path stays inside the target and that sizes and counts stay within limits.
- **Outbound requests.** Fetch user-supplied URLs only through one helper that enforces scheme and port, resolves the host and rejects private, loopback, link-local and metadata addresses, revalidates on redirects, and limits time and response size.
- **Money, stock and bookings.** Use decimal types. Add database `CHECK` constraints (amount > 0, balance >= 0) and unique constraints (one booking per slot). Use a transaction with a row lock or an atomic conditional `UPDATE ... WHERE balance >= :amount`. Require an idempotency key for payment-like operations.
- **Workflows.** Model each business workflow (claim, order, booking, refund, approval) as an explicit state machine in the service layer. Each transition lists its allowed source states, the roles that may perform it, and its preconditions taken from the specification, such as a required attachment, approval or payment. Perform the transition as one conditional update. Clients cannot set the state directly.
- **Membership lifecycle.** Whenever users can join a tenant, also build the way out: remove a member, change a role, revoke pending invitations, and transfer or release what a removed member owned (bookings, files, records). Removing a member revokes their sessions and their access through every path (API, RLS, storage). Keep at least one admin per tenant.
- **Quotas.** Bound what one user can hold or create (active bookings, uploads, invitations, records per day) so that one account cannot exhaust a shared resource.
- **Webhooks.** Verify the signature over the raw body with the provider's SDK or a constant-time compare, enforce the timestamp tolerance, store the event ID to reject replays, and look up amounts and accounts on the server.
- **Logging.** Use structured logs with actor, action, resource and outcome. Redact the `Authorization` header, cookies, passwords, tokens and personal data. Never log full request bodies or headers.
- **Production config.** Debug off, allowed hosts set, docs and admin routes protected or disabled, the static root containing only built assets.
- **Dependencies and build.** Pin versions with a lockfile. Use maintained, current releases. Build the container from a slim, pinned base image and run it as a non-root user. Add Dependabot or Renovate.

## 3. Stack notes

- **FastAPI.** Pydantic models for every body, with `model_config = ConfigDict(extra="forbid")`. Use a `Depends(current_principal)` dependency on the router, not per route. Use SQLAlchemy sessions with explicit transactions. Disable `/docs` in production or protect it.
- **Django.** Keep `django.middleware.csrf` on and do not use `csrf_exempt` on cookie-authenticated views. Set `DEBUG=False`, `ALLOWED_HOSTS`, `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS` and `SECURE_CONTENT_TYPE_NOSNIFF`, and run `manage.py check --deploy`. Use ModelForm or serializer fields as explicit lists. Do not use `extra()`, `raw()` with formatting, or `|safe` on user data. Scope querysets with a tenant-aware manager.
- **Flask.** Use Flask-WTF or another CSRF extension, `SESSION_COOKIE_*` flags, and a strong `SECRET_KEY` from the environment. Use `send_from_directory` for files. Never use `render_template_string` with input or run with `debug=True` in production.
- **Express / Node.** Use `helmet()`, `app.disable("x-powered-by")`, `express-rate-limit`, a maintained CSRF middleware for cookie auth, and zod or joi validation. Use `jwt.verify(token, key, { algorithms: [...] })`. Use mongoose with `sanitizeFilter` or strict schema casting. Never deep-merge request bodies into objects. Serve static files only from a dedicated `public/` folder that holds no source or `.env`.
- **React, Next.js, TypeScript and Supabase/Firebase.** Follow `references/web-react-typescript.md` section 3. In short, authorize inside every server action, route handler and RLS policy, never only in components or middleware; parse every boundary with zod instead of `as` casts; pass DTOs, not ORM rows, to client components; and keep secrets out of public variables and the bundle.

## 4. Never do this

Each of these turns into a vulnerability. Do not write them, even temporarily or "for testing":

- Build SQL, shell, HTML or regex by concatenating input.
- Take tenant, owner, role, price, balance or `is_admin` from the request.
- Bind a request body to a model without a field allowlist.
- Hardcode a secret, or give a secret a default value in code. That includes "dev" defaults guarded only by an environment-name check, because a missing or misspelled environment name then runs production on the dev secret.
- Choose the JWT algorithm from the token, or disable signature verification.
- Use `random`/`Math.random`, MD5 or SHA-1 for anything security-related, or `==` to compare MACs.
- Return stack traces or exception text to clients, or log credentials.
- Use a CORS wildcard with credentials, or reflect any origin.
- Change state on GET, or exempt cookie-authenticated routes from CSRF.
- Serve the project root, uploads or `.env` as static files.
- Fetch user-supplied URLs without the outbound helper.
- Use `yaml.load`, `pickle`, `eval`, `exec` or `render_template_string` on untrusted data.
- Read-check-write a balance or stock level without a lock or atomic update.
- Ship with debug on, wildcard hosts or a root container.

## 5. Tests that ship with each feature

For every endpoint, write deny-path tests first: anonymous, wrong role, other user, other tenant. Then add tests for the feature's specific risks:

- Mass assignment: posting `role`, `tenant_id` or `balance` changes nothing.
- Injection: quote, operator object (`{"$ne": null}`) and path traversal fixtures are rejected.
- Money: negative and zero amounts are rejected; two concurrent spends of the full balance yield exactly one success.
- Workflow: every transition is attempted from every wrong state and with each precondition missing, and each attempt is rejected.
- Offboarding: after a member is removed, every read and write path (API, RLS, storage, existing session) denies them.
- Tokens: expired, reused, tampered and `alg: none` tokens are rejected.
- Webhooks: a bad signature, stale timestamp and replayed event ID are rejected.
- Files: an oversized file, a disallowed type and an archive with `../` member names are rejected.

Add CI from the first commit: lint, type check, tests, and the security scan. With the user's permission, copy `templates/ci/icezy-security-scan.yml` into `.github/workflows/`; it runs the bundled scanner (SAST, dependency audit, secret and BaaS-policy checks) on every pull request and fails on High or Critical findings. Run `scripts/security_scan.py` locally on the project before calling a feature done, and fix or explain every finding. Run `references/audit-method.md` Phases 2 to 4 against your own diff before calling a feature done, and report findings honestly.
