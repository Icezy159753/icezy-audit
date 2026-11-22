"""Offline tests for security_scan.py built-in checks; external tools are never invoked."""
import base64
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import security_scan as scan  # noqa: E402


def fake_jwt(role):
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256', 'typ': 'JWT'})}.{part({'iss': 'supabase', 'role': role, 'ref': 'abcdefghij'})}.c2lnbmF0dXJlc2lnbmF0dXJl"


SERVICE_JWT = fake_jwt("service_role")
ANON_JWT = fake_jwt("anon")
STRIPE_LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="icezy-scan-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()

    def write(self, files):
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def findings(self, files):
        shutil.rmtree(self.root)
        self.root.mkdir()
        self.write(files)
        project = scan.walk(self.root)
        return [f for check in scan.BUILTINS for f in check(project)]

    def titles(self, files):
        return [f.title for f in self.findings(files)]

    def assert_found(self, files, fragment, severity=None):
        found = [f for f in self.findings(files) if fragment in f.title]
        self.assertTrue(found, f"expected a finding containing {fragment!r}")
        if severity:
            self.assertEqual(found[0].severity, severity)
        return found

    def assert_absent(self, files, fragment):
        self.assertFalse([t for t in self.titles(files) if fragment in t], f"unexpected finding {fragment!r}")

    def test_supabase_table_without_rls(self):
        sql = "create table public.notes (id uuid primary key, owner uuid);\n"
        self.assert_found({"supabase/migrations/1.sql": sql}, "has no row level security", "high")
        self.assert_absent({"supabase/migrations/1.sql": sql + "alter table public.notes enable row level security;\n"},
                           "has no row level security")

    def test_supabase_open_write_policy(self):
        sql = ("create table notes (id int);\nalter table notes enable row level security;\n"
               "create policy \"anyone edits\" on notes for update using (true) with check (true);\n")
        self.assert_found({"m.sql": sql}, "allows update on any row", "high")
        safe = ("create table notes (id int, owner uuid);\nalter table notes enable row level security;\n"
                "create policy \"own\" on notes for update using (owner = auth.uid()) with check (owner = auth.uid());\n")
        self.assert_absent({"m.sql": safe}, "any row")

    def test_update_policy_leaves_sensitive_columns_editable(self):
        table = ("create table listings (\n  id uuid primary key,\n  seller_id uuid not null,\n  title text,\n"
                 "  price numeric(10,2) not null,\n  status text default 'active'\n);\n"
                 "alter table listings enable row level security;\n"
                 "create policy own on listings for update using (seller_id = auth.uid());\n")
        found = self.assert_found({"m.sql": table}, "sensitive columns", "medium")
        self.assertIn("price", found[0].detail)
        self.assertIn("status", found[0].detail)
        self.assertNotIn("seller_id", found[0].detail, "a column pinned by USING is protected")
        guarded = table + ("revoke update on listings from authenticated;\n"
                           "grant update (title) on listings to authenticated;\n")
        self.assert_absent({"m.sql": guarded}, "sensitive columns")
        self.assert_found({"m.sql": table + "grant update (title) on listings to authenticated;\n"}, "sensitive columns")
        self.assert_absent({"m.sql": table.replace("price numeric(10,2) not null,\n  status text default 'active'", "body text")},
                           "sensitive columns")
        self.assert_absent({"m.sql": table}, "WITH CHECK")

    def test_supabase_user_metadata_policy(self):
        sql = "create policy mods on listings for update using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'mod') with check (true);\n"
        self.assert_found({"m.sql": sql}, "trusts user-editable metadata", "high")

    def test_security_definer_without_search_path(self):
        bad = "create function f() returns void language plpgsql security definer as $$ begin end; $$;\n"
        self.assert_found({"m.sql": bad}, "without fixed search_path", "medium")
        good = "create function f() returns void language plpgsql security definer set search_path = '' as $$ begin end; $$;\n"
        self.assert_absent({"m.sql": good}, "search_path")

    def test_storage_policy_and_public_bucket(self):
        sql = ("insert into storage.buckets (id, name, public) values ('media', 'media', true);\n"
               "create policy \"upload\" on storage.objects for insert to authenticated with check (bucket_id = 'media');\n")
        titles = self.titles({"m.sql": sql})
        self.assertIn("Storage bucket created as public", titles)
        self.assertIn("Storage write policy not tied to the uploader", titles)
        safe = ("create policy \"upload\" on storage.objects for insert to authenticated with check "
                "(bucket_id = 'media' and (storage.foldername(name))[1] = auth.uid()::text);\n")
        self.assert_absent({"m.sql": safe}, "not tied to the uploader")

    def test_supabase_function_config(self):
        self.assert_found({"supabase/config.toml": "[functions.hook]\nverify_jwt = false\n"}, "verify_jwt = false")
        fn = "const k = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')\nserve(async (req) => new Response('ok'))\n"
        self.assert_found({"supabase/functions/x/index.ts": fn}, "without checking the caller", "high")
        checked = fn + "const { data } = await supabase.auth.getUser(token)\n"
        self.assert_absent({"supabase/functions/x/index.ts": checked}, "without checking the caller")

    def test_service_role_jwt_and_public_env(self):
        found = self.findings({".env": f"VITE_SUPABASE_SERVICE_ROLE_KEY={SERVICE_JWT}\nVITE_SUPABASE_ANON_KEY={ANON_JWT}\n"})
        titles = [f.title for f in found]
        self.assertIn("Supabase service_role key in project files", titles)
        self.assertIn("service_role key exposed through a public env variable", titles)
        self.assertIn("Secret-looking variable with a public/client prefix", titles)
        self.assertEqual(sum("service_role key in project" in t for t in titles), 1, "anon JWT must not be flagged")

    def test_env_not_gitignored(self):
        self.assert_found({".env": "X=1\n"}, ".env files present and not ignored by git", "high")
        self.assert_absent({".env": "X=1\n", ".gitignore": ".env*\n!.env.example\n"}, "not ignored by git")

    def test_secret_patterns_and_redaction(self):
        found = self.assert_found({"src/pay.ts": f"const key = '{STRIPE_LIVE}'\n"}, "Stripe live secret key", "critical")
        self.assertNotIn(STRIPE_LIVE, found[0].detail)
        self.assert_found({"cfg.py": "DB = 'postgresql://app:hunter22@db.internal/app'\n"}, "Database URL with password", "critical")
        self.assert_found({"deploy/key.yml": "key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  abc\n"}, "Private key", "critical")

    def test_example_file_is_downgraded(self):
        found = self.assert_found({".env.example": "DATABASE_URL=postgres://user:password@localhost/db\n"}, "Database URL")
        self.assertEqual(found[0].severity, "low")

    def test_secret_fallback(self):
        self.assert_found({"c.py": "SECRET = os.environ.get('JWT_SECRET', 'change-me')\n"}, "hardcoded default", "high")
        self.assert_found({"s.js": "const s = process.env.SESSION_SECRET || 'dev'\n"}, "hardcoded default", "high")
        self.assert_absent({"c.py": "SECRET = os.environ['JWT_SECRET']\nPORT = os.environ.get('PORT', '8000')\n"},
                           "hardcoded default")

    def test_firebase_rules(self):
        self.assert_found({"firestore.rules": "match /{document=**} { allow read, write: if true; }\n"},
                          "allows read, write for everyone", "critical")
        self.assert_found({"firestore.rules": "match /{document=**} { allow read, write: if request.auth != null; }\n"},
                          "any signed-in user", "high")
        self.assert_found({"storage.rules": "allow read, write: if request.time < timestamp.date(2030, 1, 1);\n"},
                          "test-mode rule", "critical")
        self.assert_found({"firestore.rules": "match /posts/{id} { allow read: if true; }\n"},
                          "allows read for everyone", "medium")
        self.assert_found({"firestore.rules": "match /orders/{id} { allow read, write: if request.auth != null; }\n"},
                          "any signed-in user", "high")
        self.assert_found({"firestore.rules": "match /posts/{id} { allow create: if request.auth != null; }\n"},
                          "any signed-in user", "medium")
        owner = "match /notes/{id} { allow read: if request.auth.uid == resource.data.owner; }\n"
        self.assertEqual(self.findings({"firestore.rules": owner}), [])

    def test_realtime_database_and_service_account(self):
        self.assert_found({"database.rules.json": '{"rules": {".read": true, ".write": "auth != null"}}'},
                          ".read = true", "critical")
        sa = '{"type": "service_account", "project_id": "p", "private_key": "x"}'
        self.assert_found({"keys/sa.json": sa}, "service account key file", "critical")

    def test_web_config(self):
        titles = self.titles({"vite.config.ts": "export default { build: { sourcemap: true } }\n", "index.html": "<html>"})
        self.assertIn("Production source maps enabled", titles)
        self.assertIn("No Content-Security-Policy found in the repo", titles)
        self.assert_absent({"vite.config.ts": "export default { build: { sourcemap: 'hidden' } }\n", "index.html": "<html>",
                            "netlify.toml": "[[headers]]\n  [headers.values]\n  Content-Security-Policy = \"default-src 'self'\"\n"},
                           "Content-Security-Policy")
        nxt = "export default { images: { remotePatterns: [{ hostname: '**' }] }, productionBrowserSourceMaps: true }\n"
        titles = self.titles({"next.config.ts": nxt})
        self.assertIn("next/image allows any remote host", titles)
        self.assertIn("productionBrowserSourceMaps enabled", titles)

    def test_build_hygiene(self):
        titles = self.titles({"package.json": '{"dependencies": {"left-pad": "*"}}',
                              "Dockerfile": "FROM node:latest\nENV API_KEY=abc123\n", "requirements.txt": "flask\n"})
        for expected in ("No lockfile next to package.json", "Dependency left-pad is unpinned (*)", "Container runs as root",
                         "Base image node:latest is not pinned", "Secret set in Dockerfile",
                         "1 Python requirement(s) not pinned with =="):
            self.assertIn(expected, titles)
        clean = {"package.json": '{"dependencies": {"react": "^18.3.1"}}', "package-lock.json": "{}",
                 "Dockerfile": "FROM python:3.12-slim\nUSER app\n", "requirements.txt": "flask==3.0.3\n"}
        self.assertEqual(self.findings(clean), [])

    def test_skips_dependency_folders(self):
        self.assertEqual(self.findings({"node_modules/x/index.js": f"'{STRIPE_LIVE}'"}), [])

    def test_cli_is_read_only_and_reports(self):
        self.write({".env": f"VITE_SUPABASE_SERVICE_ROLE_KEY={SERVICE_JWT}\n", "m.sql": "create table t (id int);\n"})
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        out = Path(self.temp.name) / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            code = scan.main([str(self.root), "--builtin-only", "--out", str(out), "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertFalse(report["security_certification"])
        self.assertGreaterEqual(report["summary"]["critical"], 1)
        self.assertNotIn(SERVICE_JWT, (out / "report.json").read_text(encoding="utf-8"))
        self.assertNotIn(SERVICE_JWT, (out / "report.md").read_text(encoding="utf-8"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(scan.main([str(self.root), "--builtin-only", "--out", str(out), "--fail-on", "never"]), 0)

    def fake_tools(self, outputs):
        calls = []

        class Proc:
            def __init__(self, stdout):
                self.stdout, self.stderr, self.returncode = stdout, "ERROR: Failed to build 'Pillow'", 1

        def fake_run(cmd, cwd, timeout):
            calls.append(cmd)
            return Proc(outputs[min(len(calls), len(outputs)) - 1]), 0.0

        originals = scan.run, scan.which
        scan.run, scan.which = fake_run, lambda name: f"/bin/{name}"
        self.addCleanup(lambda: (setattr(scan, "run", originals[0]), setattr(scan, "which", originals[1])))
        return calls

    def tool_run(self, files, tool):
        self.write(files)
        ctx = type("Ctx", (), {"offline": False, "builtin_only": False, "timeout": 5})()
        _, _, runs = scan.scan(self.root, ctx)
        return next(r for r in runs if r.tool == tool)

    def test_crashed_tool_is_failed_not_clean(self):
        self.fake_tools([""])
        run = self.tool_run({"requirements.txt": "django>=5\n"}, "pip-audit")
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.findings, 0)
        semgrep = self.tool_run({"app.py": "print(1)\n"}, "semgrep")
        self.assertEqual(semgrep.status, "failed")

    def test_pip_audit_falls_back_to_pinned_packages(self):
        vuln = json.dumps({"dependencies": [{"name": "pillow", "version": "9.0.0",
                                             "vulns": [{"id": "PYSEC-2022-1", "aliases": ["CVE-2022-22817"],
                                                        "fix_versions": ["9.0.1"], "description": "eval in ImageMath"}]}]})
        calls = self.fake_tools(["", vuln])
        self.write({"requirements.txt": "Django>=5.0\nPillow==9.0.0\n"})
        ctx = type("Ctx", (), {"offline": False, "builtin_only": False, "timeout": 5})()
        found, note = scan.pip_audit(scan.walk(self.root), ctx)
        self.assertIn("--no-deps", calls[-1])
        self.assertFalse(note.startswith("FAILED"))
        self.assertIn("NOT audited: Django>=5.0", note)
        self.assertEqual([f.title for f in found], ["Vulnerable dependency pillow 9.0.0"])
        self.assertIn("CVE-2022-22817", found[0].detail)

    def test_cli_refuses_output_inside_project(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            scan.main([str(self.root), "--builtin-only", "--out", str(self.root / "reports")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
