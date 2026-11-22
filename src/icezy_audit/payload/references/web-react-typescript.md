# React, Next.js and TypeScript web apps

Read this whenever the project uses React (Vite, Create React App, Remix, Next.js), TypeScript on the server, or a backend-as-a-service (Supabase, Firebase, Appwrite) called directly from the browser. It adds the frontend and full-stack specifics that `references/audit-method.md` and `references/secure-build.md` cover only generically. Both modes use it: audit mode as an extra checklist, start mode as build rules.

## The one rule behind everything here

**The browser is not a trust boundary.** Everything in a client component, the JS bundle, `localStorage`, a React route guard, a disabled button, a TypeScript type or a `VITE_`/`NEXT_PUBLIC_` variable is visible to and changeable by the user. Every authorization, validation, price, role and ownership decision must be enforced again where the user cannot reach it: the API, a server action, a route handler, database Row Level Security, or a storage policy.

## 1. Map the React-specific attack surface

Add these rows to the Phase 1 entrypoint table:

- **Next.js App Router.** Every `'use server'` function is a public POST endpoint, callable with any arguments, whether or not a page renders a form for it. Every `app/**/route.ts` handler, every `pages/api/**` file, `middleware.ts` (and what its `matcher` misses), Server Components that fetch data, `generateMetadata`, image and OG routes, and `next.config.*` (`images.remotePatterns`, `headers()`, `rewrites`, `productionBrowserSourceMaps`).
- **SPA with BaaS.** Every table, view, RPC function and storage bucket reachable with the public anon key is an entrypoint. List each with its RLS or security-rules status. Edge/Cloud Functions are entrypoints too.
- **Client-side.** Router routes and guards, `postMessage` listeners, deep links and query-parameter handling, file pickers, third-party scripts and SDKs, service workers.
- **Build output.** What ends up in the bundle: env vars with public prefixes, imported server modules, source maps, comments, API base URLs.

## 2. Audit checklist

### Authorization in React apps

- Next.js: check authorization **inside** each server action and route handler, not only in `middleware.ts` or a layout. Middleware is an optimization, not the security boundary: matchers miss paths, it does not run for every call shape, and middleware bypasses have happened (for example CVE-2025-29927 via the `x-middleware-subrequest` header). Confirm the Next.js version is patched.
- A server action or handler that accepts `userId`, `tenantId`, `orgId`, `role`, `price`, `status` or `ownerId` from its arguments or body and uses them without deriving them from the verified session is a finding (CWE-639, CWE-602).
- Admin and moderator pages protected only by a React route guard, a hidden menu or `if (user.role === 'admin')` in a component are findings unless the API or RLS enforces the same rule.
- Roles read from anything the user can write (a `profiles.role` column that the user's own UPDATE policy leaves editable, Supabase `user_metadata`, Firebase custom fields the client can set, a decoded but unverified JWT, `localStorage`) are findings. Supabase `app_metadata` and verified custom claims are server-controlled; `user_metadata` is not.

### Supabase, Firebase and other BaaS

- Every table in an exposed schema has RLS **enabled** and has policies. A table with RLS off is fully readable and writable with the anon key.
- `USING (true)` on a table holding private data, `auth.role() = 'authenticated'` used as if it meant "owner", and INSERT policies that let a user set `owner_id` to someone else are findings.
- RLS limits **rows, not columns**. An UPDATE policy such as `USING (owner_id = auth.uid())` stops a user from moving a row to another owner, because Postgres applies USING to the new row when WITH CHECK is absent. It does not stop the owner from changing `price`, `status`, `role`, `is_admin` or `credits` on their own row. Verify that sensitive columns are protected by `REVOKE UPDATE` plus column-level `GRANT UPDATE (...)`, a `BEFORE UPDATE` trigger, or an RPC function. Do not report "missing WITH CHECK" on its own as a vulnerability.
- Views and `SECURITY DEFINER` functions bypass RLS unless written carefully. Check `search_path`, the caller checks inside each RPC, and grants to `anon` and `authenticated`.
- Storage buckets: public buckets for private files, and object policies that do not tie the path to `auth.uid()`.
- The `service_role` key, Firebase Admin credentials or any secret in client code, a `VITE_`/`NEXT_PUBLIC_`/`REACT_APP_` variable or a committed `.env` file is Critical.
- Edge Functions: JWT verification enabled (`verify_jwt`), the caller authorized inside the function, CORS not `*` together with credentials, and outbound fetches safe from SSRF.
- Firebase: security rules for Firestore, Realtime Database and Storage, App Check where appropriate, and no rules of the form `allow read, write: if request.auth != null` on private data.

### XSS and dangerous rendering

React escapes text children, but not these sinks:

- `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`.
- Markdown or rich-text renderers that allow raw HTML (`react-markdown` with `rehype-raw`, `marked`, `markdown-it` with `html: true`) when no sanitizer such as DOMPurify or `rehype-sanitize` is applied.
- URL attributes: `href`, `src`, `action`, `formAction`, `xlink:href`, `window.location`, `window.open` and `router.push` with user data. Check the installed React version before rating a `javascript:` URL in a JSX attribute. React 19 rewrites `javascript:` URLs in these attributes to a URL that throws, so script does not run; there the finding is missing scheme validation (Low). React 16.9 to 18 only logs a warning and runs the script (High). Direct DOM APIs such as `window.location`, `window.open`, `element.setAttribute` and non-React code are never protected. Either way, allow only `http:`, `https:` and `mailto:`, parsed with `new URL()`.
- Rate a finding by what you verified in the installed framework version, not by the pattern alone. When the source of a framework or library is available (in `node_modules` or a lockfile version you can inspect), confirm the behavior, then either rate the finding or refute it. "Unverified" is for things you truly cannot check.
- `eval`, `new Function`, `setTimeout(string)`, and building `<script>` or `style` content from data.
- SVG uploads rendered inline, and user HTML in iframes without `sandbox`.
- Server-rendered HTML that embeds JSON state without escaping `</script>`.

### Data exposure from server to client

- A Server Component passing a whole database row or ORM object to a client component sends every field to the browser: password hashes, internal notes, other users' email addresses, tokens. Map to an explicit DTO first. Use `server-only` and `taint` APIs where available.
- `getServerSideProps`, loaders and route handlers that return more fields than the UI shows.
- Error responses and `error.tsx` boundaries that render `error.message` or stack traces in production.
- Secrets imported into a module that a client component imports. Mark server modules with `import 'server-only'`.

### Tokens, sessions and storage

- Access or refresh tokens, PII or authorization state in `localStorage`, `sessionStorage` or IndexedDB are readable by any XSS. Prefer HttpOnly, Secure, SameSite cookies managed by the server or the provider's SSR helpers. When a BaaS SDK requires local storage, compensate with a strict CSP and short-lived tokens, and record the risk.
- Cookie flags set in route handlers and middleware, logout that actually revokes, and session refresh handling.
- CSRF: Next.js server actions compare `Origin` with `Host` (check custom proxies and `serverActions.allowedOrigins`). Plain cookie-authenticated route handlers and API routes need their own CSRF defense or `SameSite` plus an origin check.

### Redirects, messaging and navigation

- Open redirects in `?next=`, `?redirect=`, `?returnTo=` passed to `router.push`, `redirect()`, `NextResponse.redirect` or `window.location`. Allow only same-origin relative paths that start with a single `/`, not `//` or `/\`.
- `window.addEventListener('message', ...)` without an exact `event.origin` check, and `postMessage(data, '*')` carrying sensitive data.
- OAuth `redirectTo` values built from user input.

### TypeScript is not validation

- `req.json() as Foo`, `body as Foo`, `any`, non-null assertions (`!`) and `@ts-ignore` on external data give no runtime protection. Every boundary (request bodies, search params, form data, server action arguments, webhook payloads, `localStorage` reads, `postMessage` data, third-party API responses) needs runtime parsing with zod, valibot, yup or similar, using strict object schemas that reject unknown keys.
- Mass assignment in TypeScript usually looks like `prisma.x.update({ data: body })`, `{ ...body }` or `Object.assign(record, input)`.
- `strict: true` in `tsconfig.json` is a code-quality baseline. Missing it is Low, not a vulnerability on its own.

### Server-side TypeScript specifics

- Prisma `$queryRawUnsafe` / `$executeRawUnsafe` with interpolation, and `Prisma.raw`. The tagged `$queryRaw` template is safe.
- Next.js `images.remotePatterns` with wildcard hosts, and image or OG proxy routes that fetch user URLs (SSRF).
- Webhooks: `stripe.webhooks.constructEvent` (or the provider's equivalent) on the **raw** body. In App Router, use `await req.text()`, not `req.json()`.
- `fetch` caching: user-specific data must not end up in shared caches (`cache: 'force-cache'`, ISR, or CDN caching of personalized responses).

### Headers, build and supply chain

- CSP that fits the app: nonce-based for Next.js (set in middleware), hash-based or strict for an SPA served statically. Also `frame-ancestors`, HSTS, `nosniff` and Referrer-Policy, set in `next.config` `headers()`, `netlify.toml`, `vercel.json`, `_headers` or the hosting config.
- Production source maps (`productionBrowserSourceMaps: true`, Vite `build.sourcemap: true` deployed publicly) expose source code. They are Low to Medium, and higher when they reveal secrets or internal endpoints.
- Third-party `<script>` tags without SRI or from unpinned CDNs, and analytics or chat widgets loaded before consent where consent is required.
- `package.json` ranges (`^`, `*`, `latest`), a missing lockfile, `postinstall` scripts in new dependencies, typosquatted package names, and outdated `next`, `react`, `react-dom` or auth libraries. Run `npm audit --omit=dev` (or the `pnpm`/`yarn` equivalent) and report it as NOT RUN when there is no lockfile.

### Dangerous-sink sweep additions

| Class | What to search in `.ts`, `.tsx`, `.js`, `.jsx`, `.sql`, `.toml`, `.json` |
|---|---|
| XSS | `dangerouslySetInnerHTML`, `innerHTML`, `rehype-raw`, `html: true`, `href={`, `src={`, `window.location`, `window.open(`, `router.push(` |
| Secrets in bundle | `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `service_role`, `sk_live`, `-----BEGIN`, `.env` files in the repo |
| Trust in client | `'use client'` files that make authorization decisions; `'use server'` functions with `userId`, `tenantId`, `role`, `price` or `status` parameters |
| Unvalidated input | ` as `, `: any`, `@ts-ignore`, `req.json()`, `formData.get(`, `searchParams.get(` |
| Data access | `$queryRawUnsafe`, `$executeRawUnsafe`, `.update({ data: body`, `...body`, `.from(` without matching RLS, `.rpc(` |
| BaaS policy | `enable row level security`, `create policy`, `using (true)`, `with check`, `security definer`, `allow read, write` |
| Messaging and storage | `addEventListener('message'`, `postMessage(`, `localStorage.setItem`, `sessionStorage.setItem` |
| Config | `productionBrowserSourceMaps`, `sourcemap:`, `remotePatterns`, `headers()`, `Content-Security-Policy`, `verify_jwt` |

## 3. Build rules for start mode

- **Structure (Next.js).** Keep data access in `server/` or `lib/server/` modules marked `import 'server-only'`. Every server action and route handler starts with `const session = await requireSession()`, then `authorize(session, action, resource)`, and parses its input with a zod schema. Client components receive DTOs, never ORM objects. One `lib/env.ts` validates server and public environment variables separately, with zod, at startup.
- **Structure (SPA + BaaS).** Treat the database policies as the backend. Write RLS for every table in the same migration that creates it. Owner columns default to `auth.uid()`, and policies pin them with `USING`/`WITH CHECK (owner_id = auth.uid())`. Revoke table-wide UPDATE from `authenticated` and grant UPDATE only on the columns users may edit, so price, status and role columns stay server-controlled. Write privileged operations as RPC functions or Edge Functions that check the caller. Keep roles in `app_metadata` or a table that users cannot update. Put the UI's role checks for display only.
- **Auth.** Use the provider's SSR or cookie helpers (`@supabase/ssr`, Auth.js, Clerk, Firebase session cookies) instead of storing tokens yourself. Protect routes on the server. Client guards only improve UX.
- **Rendering.** No `dangerouslySetInnerHTML` without DOMPurify. Markdown without raw HTML, or with `rehype-sanitize`. A `safeUrl()` helper for every user-supplied link, and a `safeRedirect()` helper for every redirect target.
- **Validation.** One zod schema per input, shared between the form and the server, with `.strict()`. Infer TypeScript types from schemas (`z.infer`) instead of casting.
- **Config.** CSP with nonces through middleware, or a strict static CSP. Security headers in `next.config` or the host config. Source maps off in public production builds, or uploaded privately to the error tracker. `strict: true` in `tsconfig.json`. ESLint with `eslint-plugin-security` and `@typescript-eslint` rules banning `any` and unsafe assertions on boundary code.
- **Secrets.** Only truly public values get `NEXT_PUBLIC_` or `VITE_`. Add a CI check that fails when a forbidden name (`SERVICE_ROLE`, `SECRET`, `sk_`) appears in a public variable or in the built bundle.
- **Tests.** For each server action, route handler, RLS policy and storage policy: anonymous, other user, other tenant, wrong role, and tampered field (owner, price, status) attempts are rejected. Test RLS with the Supabase CLI or emulator and real JWTs for two users, or with the Firebase emulator. Add an XSS fixture (`<img src=x onerror=...>`, `javascript:` URL) for every user-content renderer, and an open-redirect fixture for every redirect.
