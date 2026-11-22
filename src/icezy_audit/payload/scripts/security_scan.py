"""Read-only project security scan: built-in BaaS/config/secret checks plus standard scanners.

Findings are leads for review, not verdicts. A tool that could not run is reported as NOT_RUN,
never as clean. The scanned project is never written to; reports go to --out (default: OS temp).
"""
import argparse
import base64
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

SEVERITIES = ("critical", "high", "medium", "low", "info", "unrated")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".next",
             ".nuxt", ".svelte-kit", "coverage", ".turbo", ".vercel", ".netlify", "vendor", "target",
             ".pytest_cache", ".mypy_cache", ".idea", ".vscode"}
TEXT_LIMIT = 1_000_000
EXAMPLE_FILE = re.compile(r"(^|[._-])(example|sample|template|dist)([._-]|$)", re.I)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    file: str
    line: int
    tool: str
    detail: str
    fix: str = ""
    cwe: str = ""


@dataclass
class ToolRun:
    tool: str
    status: str
    reason: str = ""
    version: str = ""
    findings: int = 0
    seconds: float = 0.0


@dataclass
class Project:
    root: Path
    files: list = field(default_factory=list)
    texts: dict = field(default_factory=dict)

    def rel(self, path):
        return path.relative_to(self.root).as_posix()

    def text(self, path):
        if path not in self.texts:
            try:
                data = path.read_bytes()[:TEXT_LIMIT]
                self.texts[path] = "" if b"\0" in data[:4096] else data.decode("utf-8", "replace")
            except OSError:
                self.texts[path] = ""
        return self.texts[path]

    def named(self, *patterns):
        return [p for p in self.files if any(re.search(pat, self.rel(p), re.I) for pat in patterns)]

    def has(self, *patterns):
        return bool(self.named(*patterns))


def walk(root):
    project = Project(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_symlink() and path.is_file():
                project.files.append(path)
    project.files.sort()
    return project


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def redact(value):
    value = value.strip().strip("'\"")
    return value[:4] + "…" + f"({len(value)} chars)" if len(value) > 8 else "…"


def jwt_role(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except (IndexError, ValueError, AttributeError):
        return None


# ---------------------------------------------------------------- built-in checks

SECRET_PATTERNS = (
    ("critical", "AWS access key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("critical", "Stripe live secret key", r"\b(sk|rk)_live_[0-9A-Za-z]{16,}"),
    ("high", "Stripe test secret key", r"\bsk_test_[0-9A-Za-z]{16,}"),
    ("critical", "Private key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ("critical", "GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{40,}"),
    ("critical", "Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
    ("critical", "Anthropic API key", r"\bsk-ant-[0-9A-Za-z_-]{20,}"),
    ("critical", "OpenAI API key", r"\bsk-(proj-)?[0-9A-Za-z_-]{32,}"),
    ("critical", "Supabase secret key", r"\bsb_secret_[0-9A-Za-z_-]{20,}"),
    ("critical", "Database URL with password", r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{3,}@[^\s'\"]+"),
    ("high", "SendGrid/Twilio/Mailgun key", r"\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}|\bSK[0-9a-f]{32}\b|\bkey-[0-9a-f]{32}\b"),
)
JWT = re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}")
PUBLIC_PREFIX = r"(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)"
PUBLIC_SECRET_NAME = re.compile(PUBLIC_PREFIX + r"[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|ADMIN_KEY|SERVICE_KEY|STRIPE_SK)[A-Z0-9_]*")
SECRET_NAME = r"[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY|API_KEY|TOKEN|SIGNING_KEY|JWT_KEY)[A-Z0-9_]*"
SECRET_FALLBACK = re.compile(
    r"(?:(?:os\.environ\.get|os\.getenv|getenv|env)\(\s*['\"](" + SECRET_NAME + r")['\"]\s*,\s*['\"][^'\"]+['\"]"
    r"|process\.env\.(" + SECRET_NAME + r")\s*(?:\|\||\?\?)\s*['\"`][^'\"`]+['\"`])")
CODE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".rb", ".go", ".java",
                 ".php", ".cs", ".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".cfg", ".conf", ".sql",
                 ".sh", ".tf", ".properties", ".xml", ".html", ".md", ".txt", ".rules", ".dart", ".kt", ".swift"}


def is_env_file(project, path):
    return re.fullmatch(r"\.env(\..+)?", path.name) is not None and not EXAMPLE_FILE.search(path.name)


def scan_secrets(project):
    out = []
    for path in project.files:
        if path.suffix.lower() not in CODE_SUFFIXES and not path.name.startswith(".env"):
            continue
        text = project.text(path)
        rel = project.rel(path)
        example = bool(EXAMPLE_FILE.search(path.name))
        for severity, label, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                if example and severity != "critical":
                    continue
                out.append(Finding("low" if example else severity, "CRYPTO", f"{label} in source", rel,
                                   line_of(text, m.start()), "builtin:secrets",
                                   f"Value {redact(m.group(0))} is committed in the project."
                                   + (" File looks like an example; confirm it is a placeholder." if example else ""),
                                   "Revoke/rotate it now, move it to a secret store or server-only environment variable, and purge it from git history.",
                                   "CWE-798"))
        for m in JWT.finditer(text):
            role = jwt_role(m.group(0))
            if role == "service_role":
                out.append(Finding("critical", "CRYPTO", "Supabase service_role key in project files", rel,
                                   line_of(text, m.start()), "builtin:secrets",
                                   f"JWT {redact(m.group(0))} has role=service_role, which bypasses every RLS policy.",
                                   "Rotate the service_role key in Supabase, keep it only in server-side secrets, never in client code or VITE_/NEXT_PUBLIC_ variables.",
                                   "CWE-798"))
        for m in SECRET_FALLBACK.finditer(text):
            out.append(Finding("high", "CRYPTO", "Secret falls back to a hardcoded default", rel, line_of(text, m.start()),
                               "builtin:secrets", f"{m.group(1) or m.group(2)} silently uses a literal when the environment variable is missing.",
                               "Fail at startup when the secret is missing instead of using a default.", "CWE-1188"))
        for m in PUBLIC_SECRET_NAME.finditer(text):
            out.append(Finding("high", "CRYPTO", "Secret-looking variable with a public/client prefix", rel,
                               line_of(text, m.start()), "builtin:public-env",
                               f"{m.group(0)} is inlined into the browser bundle by the framework.",
                               "Rename it without the public prefix and use it only in server code.", "CWE-200"))
    return out


def scan_env_hygiene(project):
    out = []
    env_files = [p for p in project.files if is_env_file(project, p)]
    gitignore = project.root / ".gitignore"
    ignored = gitignore.is_file() and re.search(r"(?m)^\s*\*?\.env", project.text(gitignore))
    for path in env_files:
        text = project.text(path)
        for m in re.finditer(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(\S+)", text):
            name, value = m.group(1), m.group(2)
            role = jwt_role(value.strip("'\"")) if value.strip("'\"").startswith("eyJ") else None
            if re.match(PUBLIC_PREFIX, name) and role == "service_role":
                out.append(Finding("critical", "CRYPTO", "service_role key exposed through a public env variable",
                                   project.rel(path), line_of(text, m.start()), "builtin:public-env",
                                   f"{name} holds a service_role JWT and is bundled into client code.",
                                   "Use the anon/publishable key in the client; rotate the service_role key.", "CWE-798"))
    if env_files and not ignored:
        out.append(Finding("high", "CRYPTO", ".env files present and not ignored by git",
                           project.rel(env_files[0]), 1, "builtin:env",
                           f"{len(env_files)} env file(s) found and .gitignore does not exclude .env.",
                           "Add .env* (except .env.example) to .gitignore and remove committed env files from history.",
                           "CWE-538"))
    return out


SQL_TABLE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)", re.I)
SQL_RLS = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)\s+enable\s+row\s+level\s+security", re.I)
SQL_POLICY = re.compile(r"create\s+policy\s+(\"[^\"]+\"|\w+)\s+on\s+((?:\"?\w+\"?\.)?\"?\w+\"?)(.*?);", re.I | re.S)


SENSITIVE_COLUMN = re.compile(r"(role|roles|is_admin|is_moderator|is_staff|admin|price|amount|total|balance|credits?|"
                              r"status|state|approved|verified|is_verified|plan|tier|tenant_id|org_id|organization_id|"
                              r"company_id|team_id|owner_id|user_id|seller_id|author_id|created_by)")


def table_columns(text, start):
    """Column names of the CREATE TABLE whose parenthesised body starts at or after `start`."""
    open_at = text.find("(", start)
    if open_at < 0:
        return set()
    depth, index = 0, open_at
    for index in range(open_at, min(len(text), open_at + 20000)):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        if depth == 0:
            break
    body, parts, depth, current = text[open_at + 1:index], [], 0, ""
    for char in body:
        depth += {"(": 1, ")": -1}.get(char, 0)
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    names = set()
    for part in parts:
        m = re.match(r"\s*\"?(\w+)\"?\s+\w", part)
        if m and m.group(1).lower() not in ("constraint", "primary", "unique", "foreign", "check", "exclude", "like"):
            names.add(m.group(1).lower())
    return names


def table_key(name):
    parts = name.replace('"', "").lower().split(".")
    return ("public", parts[0]) if len(parts) == 1 else (parts[0], parts[1])


def scan_sql(project):
    out = []
    sql_files = [p for p in project.files if p.suffix.lower() == ".sql"]
    created, rls, columns, updatable, guarded = {}, set(), {}, {}, set()
    for path in sql_files:
        text = project.text(path)
        rel = project.rel(path)
        for m in SQL_TABLE.finditer(text):
            key = table_key(m.group(1))
            created.setdefault(key, (rel, line_of(text, m.start())))
            columns.setdefault(key, set()).update(table_columns(text, m.end()))
        for m in re.finditer(r"revoke\s+(?:all|update)[^;]*?\bon\s+(?:table\s+)?((?:\"?\w+\"?\.)?\"?\w+\"?)", text, re.I | re.S):
            guarded.add(table_key(m.group(1)))
        for m in re.finditer(r"before\s+update[^;]*?\bon\s+((?:\"?\w+\"?\.)?\"?\w+\"?)", text, re.I | re.S):
            guarded.add(table_key(m.group(1)))
        for m in SQL_RLS.finditer(text):
            rls.add(table_key(m.group(1)))
        for m in SQL_POLICY.finditer(text):
            body = re.sub(r"\s+", " ", m.group(3).lower())
            name, table = m.group(1), m.group(2)
            command = (re.search(r"\bfor\s+(all|select|insert|update|delete)\b", body) or [None, "all"])[1]
            line = line_of(text, m.start())
            open_using = re.search(r"using\s*\(\s*true\s*\)", body)
            open_check = re.search(r"with\s+check\s*\(\s*true\s*\)", body)
            to_anon = re.search(r"\bto\s+(public|anon)\b", body)
            if (open_using or open_check) and command != "select":
                out.append(Finding("high", "AUTHZ", f"Policy {name} allows {command} on any row", rel, line,
                                   "builtin:supabase-rls",
                                   f"{table}: USING/WITH CHECK (true) lets every permitted role {command} every row.",
                                   "Restrict to the owner or tenant, for example USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid()).",
                                   "CWE-284"))
            elif open_using and command == "select":
                out.append(Finding("medium" if to_anon or "to" not in body.split("using")[0] else "low", "AUTHZ",
                                   f"Policy {name} makes every row of {table} readable", rel, line, "builtin:supabase-rls",
                                   "SELECT USING (true): confirm the table holds no private columns, because column-level privacy is not enforced by this policy.",
                                   "Limit rows or move private columns to another table or a view.", "CWE-200"))
            if command in ("update", "all") and not (open_using or open_check):
                updatable.setdefault(table_key(table), []).append((name, body, rel, line))
            if re.search(r"auth\.role\(\)\s*=\s*'authenticated'", body) and command != "select":
                out.append(Finding("medium", "AUTHZ", f"Policy {name} only checks that a user is logged in", rel, line,
                                   "builtin:supabase-rls",
                                   f"{table}: auth.role() = 'authenticated' lets any signed-up user {command} any row.",
                                   "Check ownership or membership instead of just authentication.", "CWE-285"))
            if re.search(r"(user_metadata|raw_user_meta_data)", body):
                out.append(Finding("high", "AUTHZ", f"Policy {name} trusts user-editable metadata", rel, line,
                                   "builtin:supabase-rls",
                                   "user_metadata is writable by the user through supabase.auth.updateUser().",
                                   "Use app_metadata, a custom claim set by the server, or a membership table.", "CWE-807"))
        for m in re.finditer(r"create\s+(?:or\s+replace\s+)?function\s+([\w\".]+)(.*?)(?:\$\$|\$function\$)", text, re.I | re.S):
            header = m.group(2).lower()
            tail = text[m.end():m.end() + 4000].lower()
            if "security definer" in header + tail[:600] and "search_path" not in header + tail[:600]:
                out.append(Finding("medium", "AUTHZ", f"SECURITY DEFINER function {m.group(1)} without fixed search_path",
                                   rel, line_of(text, m.start()), "builtin:supabase-sql",
                                   "A definer function bypasses RLS; without SET search_path it can be hijacked by objects in other schemas.",
                                   "Add SET search_path = '' (or pg_catalog, public) and check the caller inside the function.",
                                   "CWE-426"))
        for m in re.finditer(r"grant\s+(all|insert|update|delete)[^;]*\bto\s+[^;]*\banon\b", text, re.I):
            out.append(Finding("high", "AUTHZ", "Write privileges granted to anon", rel, line_of(text, m.start()),
                               "builtin:supabase-sql", m.group(0)[:160],
                               "Grant anon only what unauthenticated visitors truly need, and rely on RLS for row limits.", "CWE-732"))
        for m in re.finditer(r"insert\s+into\s+storage\.buckets[^;]*", text, re.I | re.S):
            if re.search(r"\btrue\b", m.group(0), re.I):
                out.append(Finding("medium", "FILES", "Storage bucket created as public", rel, line_of(text, m.start()),
                                   "builtin:supabase-storage",
                                   "Public buckets serve every object by URL without authorization.",
                                   "Keep private files in a private bucket and serve them with short-lived signed URLs.", "CWE-284"))
        for m in re.finditer(r"create\s+policy[^;]*on\s+storage\.objects[^;]*;", text, re.I | re.S):
            body = m.group(0).lower()
            if "auth.uid()" not in body and "storage.foldername" not in body and re.search(r"\bfor\s+(insert|update|delete|all)\b", body):
                out.append(Finding("high", "FILES", "Storage write policy not tied to the uploader", rel,
                                   line_of(text, m.start()), "builtin:supabase-storage",
                                   "The policy checks only the bucket, so any permitted user can write or delete any path in it.",
                                   "Bind the object path to auth.uid(), for example (storage.foldername(name))[1] = auth.uid()::text.",
                                   "CWE-639"))
    for key, policies in sorted(updatable.items()):
        if key in guarded:
            continue
        pinned = set(re.findall(r"\b(\w+)\b", " ".join(body for _, body, _, _ in policies)))
        exposed = sorted(c for c in columns.get(key, ()) if SENSITIVE_COLUMN.fullmatch(c) and c not in pinned)
        if exposed:
            name, _, rel, line = policies[0]
            out.append(Finding("medium", "AUTHZ", f"Row owners can change sensitive columns of {key[1]}", rel, line,
                               "builtin:supabase-rls",
                               f"UPDATE policy {name} limits which rows can change, not which columns. A user who may update a "
                               f"row can also set {', '.join(exposed)} to any value.",
                               "Revoke table-level UPDATE and grant UPDATE only on editable columns, or enforce the rule with a "
                               "BEFORE UPDATE trigger or an RPC function.", "CWE-639"))
    for key, (rel, line) in sorted(created.items()):
        schema, table = key
        if schema in ("public",) and key not in rls:
            out.append(Finding("high", "AUTHZ", f"Table {table} has no row level security", rel, line,
                               "builtin:supabase-rls",
                               "In Supabase, tables in the public schema are reachable with the anon key through the Data API; without RLS anyone can read and write them.",
                               f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; then add owner/tenant policies.", "CWE-284"))
    return out


def scan_supabase_config(project):
    out = []
    for path in project.named(r"(^|/)supabase/config\.toml$"):
        text = project.text(path)
        for m in re.finditer(r"(?m)^\s*verify_jwt\s*=\s*false", text):
            out.append(Finding("medium", "AUTH", "Edge Function with verify_jwt = false", project.rel(path),
                               line_of(text, m.start()), "builtin:supabase-config",
                               "The function accepts requests without a valid Supabase JWT.",
                               "Keep verify_jwt = true unless the function verifies its own signature (for example a webhook).",
                               "CWE-306"))
    for path in project.named(r"(^|/)supabase/functions/.+\.(ts|js)$"):
        text = project.text(path)
        rel = project.rel(path)
        m = re.search(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]", text)
        if m:
            out.append(Finding("low", "HEADERS", "Edge Function allows any CORS origin", rel, line_of(text, m.start()),
                               "builtin:supabase-functions", "Any website can call this function from a browser.",
                               "Allow only the app's origins, especially when the function acts with elevated keys.", "CWE-942"))
        if "SERVICE_ROLE" in text and not re.search(r"auth\.getUser|getUser\(|verify|jwt", text, re.I):
            out.append(Finding("high", "AUTHZ", "Edge Function uses the service_role key without checking the caller",
                               rel, 1, "builtin:supabase-functions",
                               "The function bypasses RLS and no caller verification was found in it.",
                               "Verify the caller's JWT (supabase.auth.getUser(token)) and authorize before using service_role.",
                               "CWE-862"))
    return out


def scan_firebase(project):
    out = []
    for path in project.named(r"(^|/)(firestore|storage)[\w.-]*\.rules$", r"\.rules$"):
        text = project.text(path)
        rel = project.rel(path)
        for m in re.finditer(r"allow\s+([\w\s,]+?)\s*(?::\s*if\s+([^;]+))?;", text):
            ops, cond = m.group(1), (m.group(2) or "").strip()
            line = line_of(text, m.start())
            writes = bool(re.search(r"\b(write|create|update|delete)\b", ops))
            scope = text[:m.start()].rsplit("match", 1)[-1]
            wide = bool(re.search(r"\{\w+=\*\*\}", scope))
            if not cond or cond == "true":
                out.append(Finding("critical" if writes or wide else "medium", "AUTHZ",
                                   f"Firebase rule allows {ops.strip()} for everyone", rel, line,
                                   "builtin:firebase-rules", f"`allow {ops.strip()}{': if ' + cond if cond else ''}` has no real condition."
                                   + ("" if writes or wide else " Public read can be intended; confirm no private fields live here."),
                                   "Require request.auth and check ownership, e.g. request.auth.uid == resource.data.ownerId.", "CWE-284"))
            elif re.fullmatch(r"request\.auth\s*!=\s*null", cond):
                out.append(Finding("high" if wide or (writes and not re.fullmatch(r"\s*create\s*", ops)) else "medium", "AUTHZ",
                                   f"Firebase rule allows {ops.strip()} for any signed-in user", rel, line,
                                   "builtin:firebase-rules",
                                   "Any account (anyone can sign up) gets this access" + (" to every document." if wide else "."),
                                   "Check ownership or role, not only authentication.", "CWE-285"))
            elif re.search(r"request\.time\s*<\s*timestamp\.date", cond):
                out.append(Finding("critical", "AUTHZ", "Firebase test-mode rule (time-limited open access)", rel, line,
                                   "builtin:firebase-rules", "Test-mode rules open the whole database until the date passes.",
                                   "Replace with real ownership rules before launch.", "CWE-284"))
    for path in project.named(r"(^|/)database\.rules\.json$", r"(^|/)database[\w.-]*rules[\w.-]*\.json$"):
        text = project.text(path)
        for m in re.finditer(r"\"\.(read|write)\"\s*:\s*(true|\"true\"|\"auth\s*!=\s*null\")", text):
            open_all = "true" in m.group(2)
            out.append(Finding("critical" if open_all else "high", "AUTHZ",
                               f"Realtime Database rule .{m.group(1)} = {m.group(2)}", project.rel(path),
                               line_of(text, m.start()), "builtin:firebase-rules",
                               ("Everyone" if open_all else "Every signed-in user") + " can access this path.",
                               "Scope rules to $uid paths and check auth.uid.", "CWE-284"))
    for path in project.files:
        if path.suffix.lower() != ".json":
            continue
        text = project.text(path)
        if '"type": "service_account"' in text.replace("'", '"') and "private_key" in text:
            out.append(Finding("critical", "CRYPTO", "Google/Firebase service account key file", project.rel(path), 1,
                               "builtin:firebase", "A service account private key grants admin access and bypasses security rules.",
                               "Delete the key in Google Cloud IAM, remove the file from the repo and history, and use workload identity or a secret manager.",
                               "CWE-798"))
    for path in project.named(r"(^|/)firebase\.json$"):
        if "headers" not in project.text(path):
            out.append(Finding("low", "HEADERS", "Firebase Hosting config sets no headers", project.rel(path), 1,
                               "builtin:firebase", "No CSP, HSTS or nosniff headers are configured for hosting.",
                               "Add a headers block with CSP, X-Content-Type-Options and frame-ancestors.", "CWE-693"))
    return out


def scan_web_config(project):
    out = []
    for path in project.named(r"(^|/)vite\.config\.[cm]?[jt]s$"):
        text = project.text(path)
        m = re.search(r"sourcemap\s*:\s*(true|['\"](inline|hidden)?['\"])", text)
        if m and "hidden" not in m.group(0):
            out.append(Finding("low", "CONFIG", "Production source maps enabled", project.rel(path), line_of(text, m.start()),
                               "builtin:web-config", "Public source maps expose the original source code.",
                               "Disable them or upload them privately to the error tracker.", "CWE-540"))
    for path in project.named(r"(^|/)next\.config\.[cm]?[jt]s$"):
        text = project.text(path)
        rel = project.rel(path)
        m = re.search(r"productionBrowserSourceMaps\s*:\s*true", text)
        if m:
            out.append(Finding("low", "CONFIG", "productionBrowserSourceMaps enabled", rel, line_of(text, m.start()),
                               "builtin:web-config", "Browser source maps expose the original source code.",
                               "Remove it or upload maps privately.", "CWE-540"))
        m = re.search(r"hostname\s*:\s*['\"](\*\*|\*)['\"]", text)
        if m:
            out.append(Finding("medium", "FETCH", "next/image allows any remote host", rel, line_of(text, m.start()),
                               "builtin:web-config", "The image optimizer can be used to fetch and proxy arbitrary hosts.",
                               "List exact hostnames in images.remotePatterns.", "CWE-918"))
        m = re.search(r"allowedOrigins\s*:\s*\[[^\]]*['\"]\*", text)
        if m:
            out.append(Finding("medium", "CSRF", "serverActions.allowedOrigins contains a wildcard", rel, line_of(text, m.start()),
                               "builtin:web-config", "Check what the installed Next.js version does with this pattern before rating it.",
                               "List exact origins.", "CWE-352"))
    web = project.has(r"(^|/)index\.html$", r"(^|/)next\.config\.", r"(^|/)vite\.config\.", r"(^|/)app/layout\.(t|j)sx?$")
    configs = project.named(r"netlify\.toml$", r"vercel\.json$", r"(^|/)_headers$", r"next\.config\.", r"firebase\.json$",
                            r"(^|/)middleware\.(t|j)s$", r"(^|/)proxy\.(t|j)s$", r"nginx.*\.conf$", r"staticwebapp\.config\.json$")
    if web and not any("content-security-policy" in project.text(p).lower() for p in configs):
        out.append(Finding("low", "HEADERS", "No Content-Security-Policy found in the repo", "", 0, "builtin:web-config",
                           "No CSP is set in framework or hosting config. It may be set at a CDN; mark UNVERIFIED until checked live.",
                           "Add a CSP (nonce-based for Next.js) plus nosniff, frame-ancestors and Referrer-Policy.", "CWE-693"))
    return out


def scan_build_hygiene(project):
    out = []
    for path in project.named(r"(^|/)package\.json$"):
        folder = path.parent
        if not any((folder / lock).is_file() for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")):
            out.append(Finding("medium", "SUPPLY", "No lockfile next to package.json", project.rel(path), 1, "builtin:supply",
                               "Installs are not reproducible and npm audit cannot run against exact versions.",
                               "Commit the lockfile and install with npm ci.", "CWE-1357"))
        text = project.text(path)
        for m in re.finditer(r"\"([@\w./-]+)\"\s*:\s*\"(\*|latest|x)\"", text):
            out.append(Finding("medium", "SUPPLY", f"Dependency {m.group(1)} is unpinned ({m.group(2)})", project.rel(path),
                               line_of(text, m.start()), "builtin:supply", "Any future release, including a malicious one, is installed.",
                               "Pin a version range and commit the lockfile.", "CWE-1357"))
    for path in project.named(r"(^|/)requirements[\w.-]*\.txt$"):
        text = project.text(path)
        loose = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith(("#", "-")) and "==" not in l]
        if loose:
            out.append(Finding("low", "SUPPLY", f"{len(loose)} Python requirement(s) not pinned with ==", project.rel(path), 1,
                               "builtin:supply", ", ".join(l.strip() for l in loose[:6]),
                               "Pin exact versions (pip-tools or uv lock) and use hashes for production.", "CWE-1357"))
    for path in project.named(r"(^|/)Dockerfile[\w.-]*$"):
        text = project.text(path)
        rel = project.rel(path)
        if not re.search(r"(?mi)^\s*USER\s+(?!root\b)\S+", text):
            out.append(Finding("medium", "CONFIG", "Container runs as root", rel, 1, "builtin:docker",
                               "No non-root USER instruction found.", "Add a non-root user and USER instruction.", "CWE-250"))
        for m in re.finditer(r"(?mi)^\s*FROM\s+([^\s]+)", text):
            image = m.group(1)
            if image.lower() != "scratch" and "@sha256:" not in image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
                out.append(Finding("low", "SUPPLY", f"Base image {image} is not pinned", rel, line_of(text, m.start()),
                                   "builtin:docker", "Unpinned tags change under you.", "Pin a version tag, ideally with a digest.", "CWE-1357"))
        for m in re.finditer(r"(?mi)^\s*(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|API_KEY)\w*\s*=?\s*\S+", text):
            out.append(Finding("high", "CRYPTO", "Secret set in Dockerfile", rel, line_of(text, m.start()), "builtin:docker",
                               "ENV/ARG values are stored in image layers.", "Pass secrets at runtime or with BuildKit secrets.", "CWE-798"))
    return out


BUILTINS = (scan_secrets, scan_env_hygiene, scan_sql, scan_supabase_config, scan_firebase, scan_web_config, scan_build_hygiene)


# ---------------------------------------------------------------- external tools

def which(name):
    return shutil.which(name) or shutil.which(name + ".cmd") or shutil.which(name + ".exe")


def run(cmd, cwd, timeout):
    started = time.time()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, stdin=subprocess.DEVNULL, env={**os.environ, "NO_COLOR": "1"})
    return proc, time.time() - started


def json_object(text):
    """The JSON object a tool printed, or None when it printed none (a crash, not a clean result)."""
    start = (text or "").find("{")
    if start < 0:
        return None
    try:
        data = json.loads(text[start:])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def tail(text, size=200):
    return " ".join((text or "").split())[-size:]


def via_uvx(tool, args):
    uvx = which("uvx")
    if which(tool):
        return [which(tool), *args]
    return [uvx, "--quiet", tool, *args] if uvx else None


def npm_audit(project, ctx):
    out, notes, audited = [], [], 0
    npm = which("npm")
    manifests = project.named(r"(^|/)package\.json$")
    if not manifests:
        return None, "no package.json"
    if not npm:
        return [], "NOT_RUN: npm not installed"
    for manifest in manifests[:5]:
        folder = manifest.parent
        with tempfile.TemporaryDirectory(prefix="icezy-npm-") as temp:
            work = Path(temp)
            shutil.copy2(manifest, work / "package.json")
            lock = folder / "package-lock.json"
            if lock.is_file():
                shutil.copy2(lock, work / "package-lock.json")
            elif ctx.offline:
                notes.append(f"{project.rel(manifest)}: no lockfile and --offline")
                continue
            else:
                proc, _ = run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                               "--loglevel=error"], work, ctx.timeout)
                if proc.returncode != 0:
                    notes.append(f"{project.rel(manifest)}: lockfile generation failed ({proc.stderr.strip()[:160]})")
                    continue
                notes.append(f"{project.rel(manifest)}: audited a lockfile generated in temp from package.json ranges")
            proc, _ = run([npm, "audit", "--json", "--omit=dev"], work, ctx.timeout)
            data = json_object(proc.stdout)
            if data is None or "error" in data and "vulnerabilities" not in data:
                notes.append(f"{project.rel(manifest)}: npm audit failed ({tail(proc.stderr or proc.stdout)})")
                continue
            audited += 1
            for name, vuln in (data.get("vulnerabilities") or {}).items():
                advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
                if not advisories:
                    continue
                ids = ", ".join(sorted({a.get("url", "").rsplit("/", 1)[-1] for a in advisories if a.get("url")}))
                titles = "; ".join(sorted({a.get("title", "") for a in advisories}))[:300]
                fix = vuln.get("fixAvailable")
                fix_text = f"Upgrade to {fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict) else (
                    "Run npm audit fix after reviewing changes" if fix else "No fix available; replace or mitigate")
                sev = {"moderate": "medium"}.get(vuln.get("severity"), vuln.get("severity", "unrated"))
                out.append(Finding(sev, "SUPPLY", f"Vulnerable dependency {name} {vuln.get('range', '')}".strip(),
                                   project.rel(manifest), 1, "npm-audit", f"[{ids}] {titles}", fix_text, ""))
    if audited:
        return out, "; ".join(notes)
    return out, ("NOT_RUN: " if ctx.offline else "FAILED: ") + "; ".join(notes)


def pip_audit(project, ctx):
    reqs = project.named(r"(^|/)requirements[\w.-]*\.txt$")
    if not reqs:
        return None, "no requirements*.txt"
    if ctx.offline:
        return [], "NOT_RUN: --offline (needs the PyPI/OSV feed)"
    if not via_uvx("pip-audit", []):
        return [], "NOT_RUN: neither pip-audit nor uvx installed"
    out, notes, audited = [], [], 0
    for req in reqs[:5]:
        rel = project.rel(req)
        proc, _ = run(via_uvx("pip-audit", ["-r", str(req), "-f", "json", "--progress-spinner", "off"]),
                      project.root, ctx.timeout)
        data = json_object(proc.stdout)
        if data is None:
            pinned = [l.split("#")[0].strip() for l in project.text(req).splitlines()
                      if re.match(r"^\s*[A-Za-z0-9_.\[\]-]+\s*==\s*[\w.!+-]+\s*(#.*)?$", l)]
            loose = [l.strip() for l in project.text(req).splitlines()
                     if l.strip() and not l.lstrip().startswith(("#", "-")) and l.split("#")[0].strip() not in pinned]
            if not pinned:
                notes.append(f"{rel}: dependency resolution failed and nothing is pinned with == "
                             f"({tail(proc.stderr)})")
                continue
            with tempfile.TemporaryDirectory(prefix="icezy-pip-") as temp:
                pinned_file = Path(temp) / "pinned.txt"
                pinned_file.write_text("\n".join(pinned) + "\n", encoding="utf-8")
                proc, _ = run(via_uvx("pip-audit", ["-r", str(pinned_file), "--disable-pip", "--no-deps", "-f", "json",
                                                    "--progress-spinner", "off"]), project.root, ctx.timeout)
                data = json_object(proc.stdout)
            if data is None:
                notes.append(f"{rel}: pip-audit failed ({tail(proc.stderr)})")
                continue
            notes.append(f"{rel}: full resolution failed, so only the {len(pinned)} '=='-pinned package(s) were "
                         f"audited without their dependencies; NOT audited: {', '.join(loose) or 'none'}")
        audited += 1
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulns", [])
            if not vulns:
                continue
            ids = sorted({i for v in vulns for i in [v.get("id", "")] + v.get("aliases", []) if i},
                         key=lambda i: (not i.startswith("CVE"), i))
            fixes = sorted({f for v in vulns for f in v.get("fix_versions") or []},
                           key=lambda s: [int(p) if p.isdigit() else 0 for p in re.split(r"[.+-]", s)])
            out.append(Finding("unrated", "SUPPLY", f"Vulnerable dependency {dep.get('name')} {dep.get('version')}",
                               project.rel(req), 1, "pip-audit",
                               f"{len(vulns)} advisories [{', '.join(ids[:12])}{', …' if len(ids) > 12 else ''}]. "
                               f"First: {' '.join((vulns[0].get('description') or '').split())[:200]}",
                               f"Upgrade to {fixes[-1] if fixes else 'a fixed release'} or later (fixes needed for every advisory)"))
    return out, ("" if audited else "FAILED: ") + "; ".join(notes)


def bandit(project, ctx):
    if not any(p.suffix == ".py" for p in project.files):
        return None, "no Python files"
    cmd = via_uvx("bandit", ["-r", str(project.root), "-f", "json", "-q", "-x",
                             ",".join(str(project.root / d) for d in (".venv", "venv", "node_modules", "tests"))])
    if not cmd:
        return [], "NOT_RUN: neither bandit nor uvx installed"
    if ctx.offline and not which("bandit"):
        return [], "NOT_RUN: --offline and bandit not installed"
    proc, _ = run(cmd, project.root, ctx.timeout)
    data = json_object(proc.stdout)
    if data is None:
        return [], f"FAILED: {tail(proc.stderr)}"
    out = []
    for r in data.get("results", []):
        sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(r.get("issue_severity"), "unrated")
        path = Path(r.get("filename", ""))
        rel = project.rel(path.resolve()) if path.is_absolute() else path.as_posix()
        out.append(Finding(sev, "CODE", f"{r.get('test_id')} {r.get('test_name')}", rel, r.get("line_number", 0), "bandit",
                           r.get("issue_text", ""), "", f"CWE-{(r.get('issue_cwe') or {}).get('id', '')}".rstrip("-")))
    return out, ""


def semgrep(project, ctx):
    if ctx.offline:
        return [], "NOT_RUN: --offline (semgrep rules come from the registry)"
    cmd = via_uvx("semgrep", ["scan", "--config", "p/default", "--json", "--metrics=off", "--quiet",
                              "--timeout", "30", str(project.root)])
    if not cmd:
        return [], "NOT_RUN: neither semgrep nor uvx installed"
    proc, _ = run(cmd, project.root, ctx.timeout)
    data = json_object(proc.stdout)
    if data is None:
        return [], f"FAILED: {tail(proc.stderr)}"
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(extra.get("severity"), "unrated")
        cwe = extra.get("metadata", {}).get("cwe", "")
        cwe = (cwe[0] if isinstance(cwe, list) and cwe else cwe) or ""
        path = Path(r.get("path", ""))
        try:
            rel = project.rel(path.resolve())
        except ValueError:
            rel = path.as_posix()
        out.append(Finding(sev, "CODE", r.get("check_id", "").rsplit(".", 1)[-1], rel,
                           r.get("start", {}).get("line", 0), "semgrep", extra.get("message", "")[:300], "",
                           str(cwe).split(":")[0]))
    errors = [e.get("message", "")[:120] for e in data.get("errors", [])][:3]
    return out, ("partial errors: " + " | ".join(errors)) if errors else ""


def binary_tool(name, args_fn, parse):
    def runner(project, ctx):
        exe = which(name)
        if not exe:
            return [], f"NOT_RUN: {name} not installed (install it from the official release page to enable)"
        with tempfile.TemporaryDirectory(prefix=f"icezy-{name}-") as temp:
            report = Path(temp) / "report.json"
            proc, _ = run([exe, *args_fn(project, report)], project.root, ctx.timeout)
            raw = report.read_text(encoding="utf-8", errors="replace") if report.is_file() else proc.stdout
            try:
                return parse(project, json.loads(raw or "null")), ""
            except ValueError:
                return [], f"FAILED: {proc.stderr.strip()[-200:]}"
    return runner


def parse_gitleaks(project, data):
    return [Finding("critical", "CRYPTO", f"Secret: {r.get('RuleID')}", r.get("File", ""), r.get("StartLine", 0),
                    "gitleaks", f"Match {redact(r.get('Secret', ''))}", "Rotate and remove from history.", "CWE-798")
            for r in data or []]


def parse_trivy(project, data):
    out = []
    for res in (data or {}).get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            out.append(Finding(v.get("Severity", "unrated").lower(), "SUPPLY",
                               f"{v.get('PkgName')} {v.get('InstalledVersion')} {v.get('VulnerabilityID')}",
                               res.get("Target", ""), 1, "trivy", (v.get("Title") or "")[:200],
                               f"Fixed in {v.get('FixedVersion') or 'n/a'}"))
        for m in res.get("Misconfigurations") or []:
            out.append(Finding(m.get("Severity", "unrated").lower(), "CONFIG", m.get("Title", ""), res.get("Target", ""),
                               (m.get("CauseMetadata") or {}).get("StartLine", 0), "trivy", m.get("Message", "")[:200],
                               m.get("Resolution", "")))
    return out


def parse_osv(project, data):
    out = []
    for res in (data or {}).get("results", []):
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            for v in pkg.get("vulnerabilities", []):
                out.append(Finding("unrated", "SUPPLY", f"{info.get('name')} {info.get('version')} {v.get('id')}",
                                   project.rel(Path(res.get("source", {}).get("path", project.root)).resolve())
                                   if res.get("source") else "", 1, "osv-scanner", (v.get("summary") or "")[:200]))
    return out


TOOLS = (
    ("npm-audit", npm_audit),
    ("pip-audit", pip_audit),
    ("semgrep", semgrep),
    ("bandit", bandit),
    ("gitleaks", binary_tool("gitleaks", lambda p, r: ["detect", "--no-git", "--source", str(p.root),
                                                       "--report-format", "json", "--report-path", str(r)], parse_gitleaks)),
    ("trivy", binary_tool("trivy", lambda p, r: ["fs", "--quiet", "--scanners", "vuln,misconfig,secret", "--format", "json",
                                                 "--output", str(r), str(p.root)], parse_trivy)),
    ("osv-scanner", binary_tool("osv-scanner", lambda p, r: ["scan", "source", "-r", "--format", "json",
                                                             "--output", str(r), str(p.root)], parse_osv)),
)


# ---------------------------------------------------------------- orchestration and report

def scan(root, ctx):
    project = walk(root)
    findings, runs = [], []
    for check in BUILTINS:
        started = time.time()
        found = check(project)
        findings += found
        runs.append(ToolRun(f"builtin:{check.__name__.removeprefix('scan_')}", "ran", findings=len(found),
                            seconds=round(time.time() - started, 2)))
    if not ctx.builtin_only:
        for name, runner in TOOLS:
            started = time.time()
            try:
                found, note = runner(project, ctx)
            except subprocess.TimeoutExpired:
                found, note = [], f"FAILED: timed out after {ctx.timeout}s"
            except OSError as exc:
                found, note = [], f"FAILED: {exc.__class__.__name__}"
            if found is None:
                runs.append(ToolRun(name, "not_applicable", note))
                continue
            status = "not_run" if note.startswith("NOT_RUN") else "failed" if note.startswith("FAILED") else "ran"
            findings += found
            runs.append(ToolRun(name, status, note, findings=len(found), seconds=round(time.time() - started, 1)))
    findings.sort(key=lambda f: (RANK.get(f.severity, 9), f.file, f.line))
    return project, findings, runs


def summarize(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity if f.severity in counts else "unrated"] += 1
    return counts


def markdown(root, findings, runs, counts):
    lines = [f"# Security scan: {root.name}", "",
             "Automated leads for review. Each finding must be confirmed against the code and the installed versions; "
             "tools marked NOT RUN or FAILED give no assurance.", "",
             "| Severity | Count |", "|---|---|"] + [f"| {s} | {n} |" for s, n in counts.items() if n] + [
             "", "## Tools", "", "| Tool | Status | Findings | Note |", "|---|---|---|---|"]
    lines += [f"| {r.tool} | {r.status.upper()} | {r.findings} | {r.reason.replace('|', '/')[:200]} |" for r in runs]
    lines += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        where = f"`{f.file}:{f.line}`" if f.file else "project"
        lines.append(f"{i}. **[{f.severity.upper()}] {f.title}** {where} ({f.tool}{', ' + f.cwe if f.cwe else ''})")
        lines.append(f"   {f.detail}" + (f" Fix: {f.fix}" if f.fix else ""))
    return "\n".join(lines) + "\n"


class Context:
    def __init__(self, args):
        self.offline = args.offline
        self.builtin_only = args.builtin_only
        self.timeout = args.timeout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", help="project directory to scan (read-only)")
    parser.add_argument("--out", help="directory for report.json and report.md (default: a new OS temp dir)")
    parser.add_argument("--offline", action="store_true", help="skip tools that need network feeds or downloads")
    parser.add_argument("--builtin-only", action="store_true", help="run only the built-in checks")
    parser.add_argument("--timeout", type=int, default=600, help="per-tool timeout in seconds")
    parser.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "never"), default="never",
                        help="exit 1 when a finding at or above this severity exists (for CI)")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    out = Path(args.out).resolve() if args.out else Path(tempfile.mkdtemp(prefix="icezy-scan-"))
    if out == root or root in out.parents:
        parser.error("--out must be outside the scanned project")
    out.mkdir(parents=True, exist_ok=True)
    project, findings, runs = scan(root, Context(args))
    counts = summarize(findings)
    report = {"root": str(root), "files_scanned": len(project.files), "summary": counts,
              "tools": [asdict(r) for r in runs], "findings": [asdict(f) for f in findings],
              "security_certification": False}
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md = markdown(root, findings, runs, counts)
    (out / "report.md").write_text(md, encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(md)
    print(f"Reports: {out / 'report.md'} and {out / 'report.json'}")
    if args.fail_on != "never" and any(RANK.get(f.severity, 9) <= RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
