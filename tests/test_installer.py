"""Isolated stdlib tests: never install into the executing user's home."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from icezy_audit import cli


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="icezy-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home with spaces ü"
        self.payload = self.root / "payload"
        self.files = {
            "SKILL.md": b"---\nversion: 0.1.2\n---\nBaseline\n",
            "references/controls.md": b"Controls\n",
            "references/sources.md": b"Sources\n",
            "references/evidence-format.md": b"Evidence\n",
            "scripts/check.py": b"print('fixture')\n",
            "templates/project-start/.github/copilot-instructions.md": b"Nested dotfile\n",
        }
        for name, data in self.files.items():
            dest = self.payload / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        (self.payload / "__pycache__").mkdir()
        (self.payload / "__pycache__/cache.pyc").write_bytes(b"ignored")
        (self.payload / "other.pyc").write_bytes(b"ignored")
        self.sha = cli.tree_digest(self.files)
        self.addCleanup(patch.stopall)
        patch.object(cli, "PAYLOAD", self.payload).start()
        patch.object(cli, "PAYLOAD_DIGEST", self.sha).start()

    def call(self, command="install", *arguments, code=0):
        output = io.StringIO()
        with redirect_stdout(output):
            actual = cli.main([command, "--home", str(self.home), *arguments])
        result = json.loads(output.getvalue())
        self.assertEqual(actual, code, result)
        return result

    def target(self, agent="claude"):
        return self.home / cli.DESTINATIONS[agent]

    def install(self, *args):
        return self.call("install", "--apply", *args)

    def state(self):
        return json.loads((self.home / cli.STATE).read_text(encoding='utf-8'))

    def write_state(self, obj):
        target = self.home / cli.STATE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(obj))

    def snapshot(self):
        if not self.home.exists():
            return {}
        return {p.relative_to(self.home).as_posix(): p.read_bytes()
                for p in self.home.rglob("*") if p.is_file()}

    def test_dry_run_no_directories(self):
        result = self.call()
        self.assertFalse(result["apply"])
        self.assertEqual(set(result["paths"]), set(cli.DESTINATIONS.values()))
        self.assertFalse(self.home.exists())
        self.call("uninstall")
        self.call("status")
        self.call("state")
        self.assertFalse(self.home.exists())

    def test_install_complete_payload_and_adapters(self):
        self.install()
        baseline = cli.baseline_path(self.home, self.sha)
        self.assertEqual(cli.tree(baseline), self.files)
        self.assertFalse((baseline / "__pycache__").exists())
        self.assertTrue((baseline / "templates/project-start/.github/copilot-instructions.md").is_file())
        state = self.state()
        self.assertEqual(state["version"], 1)
        self.assertEqual(len(state["adapters"]), 5)
        for agent in cli.DESTINATIONS:
            data = self.target(agent).read_bytes()
            prompt = tomllib.loads(data.decode('utf-8'))['prompt'] if agent == 'gemini' else data.decode('utf-8')
            decoded_path, _ = json.JSONDecoder().raw_decode(prompt.split('filesystem path: ', 1)[1])
            self.assertEqual(decoded_path, str(baseline / 'SKILL.md'))
            if agent in ("claude", "codex", "hermes"):
                self.assertIn(b"name: icezy", data)
        self.assertIn(b"disable-model-invocation: true", self.target().read_bytes())
        self.assertIn(b"$icezy audit", self.target("codex").read_bytes())
        self.assertIn(b"/icezy audit", self.target("hermes").read_bytes())
        parsed = tomllib.loads(self.target("gemini").read_text(encoding='utf-8'))
        self.assertIn("{{args}}", parsed["prompt"])
        self.assertNotIn("!{", parsed["prompt"])
        self.assertTrue(self.call("status")["ok"])

    def test_idempotent_preserves_managed_file_timestamps(self):
        self.install()
        before = self.snapshot()
        timestamps = {p: (self.home / p).stat().st_mtime_ns for p in before}
        self.install()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(timestamps, {p: (self.home / p).stat().st_mtime_ns for p in before})

    def test_unowned_adapter_refused_even_identical(self):
        target = self.target()
        target.parent.mkdir(parents=True)
        target.write_bytes(cli.adapter("claude", cli.baseline_path(self.home, self.sha)))
        before = self.snapshot()
        result = self.call("install", "--apply", code=1)
        self.assertEqual(result["conflicts"][0]["reason"], "unowned")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.home / ".icezy-audit").exists())

    def test_modified_managed_adapter_refused(self):
        self.install()
        self.target().write_text("Owner edits\n")
        before = self.snapshot()
        self.call("install", "--apply", code=1)
        self.assertEqual(before, self.snapshot())
        result = self.call("status", code=1)
        self.assertIn("modified", [item["status"] for item in result["adapters"]])

    def test_uninstall_keeps_modified_and_baseline_and_user_files(self):
        self.install()
        self.target().write_text("Keep owner edits")
        unrelated = self.home / ".hermes/config.yaml"
        unrelated.write_text("owner: untouched\n")
        self.call("uninstall", "--apply", code=1)
        self.assertTrue(self.target().exists())
        self.assertFalse(self.target("codex").exists())
        self.assertEqual(len(self.state()["adapters"]), 1)
        self.assertEqual(unrelated.read_text(encoding='utf-8'), "owner: untouched\n")
        self.assertEqual(cli.tree(cli.baseline_path(self.home, self.sha)), self.files)

    def test_uninstall_only_unchanged_managed_adapters(self):
        self.install()
        before = self.snapshot()
        self.call("uninstall")
        self.assertEqual(before, self.snapshot())
        self.call("uninstall", "--apply")
        self.assertEqual(self.state()["adapters"], [])
        for agent in cli.DESTINATIONS:
            self.assertFalse(self.target(agent).exists())
            self.assertTrue(self.target(agent).parent.is_dir())
        self.assertTrue(cli.baseline_path(self.home, self.sha).is_dir())
        self.call("uninstall", "--apply")

    def test_selected_agents_and_global_home_option(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main(["--home", str(self.home), "install", "--agents", "codex,gemini", "--apply"])
        self.assertEqual(code, 0)
        self.assertTrue(self.target("codex").exists())
        self.assertFalse(self.target().exists())
        self.assertEqual(len(self.state()["adapters"]), 2)

    def test_unknown_and_duplicate_agents(self):
        for agents in ("bogus", "claude,claude", "", "claude, codex"):
            self.call("install", "--apply", "--agents", agents, code=1)
            self.assertFalse(self.home.exists())

    def test_upgrade_requires_matching_previous_hash(self):
        self.install()
        old_sha = self.sha
        self.files["SKILL.md"] += b"Upgrade\n"
        (self.payload / "SKILL.md").write_bytes(self.files["SKILL.md"])
        new_sha = cli.tree_digest(self.files)
        with patch.object(cli, "PAYLOAD_DIGEST", new_sha):
            self.install()
        self.assertTrue(cli.baseline_path(self.home, old_sha).is_dir())
        self.assertTrue(cli.baseline_path(self.home, new_sha).is_dir())
        self.assertEqual({e["baseline"] for e in self.state()["adapters"]}, {new_sha})

    def test_payload_tampering_refused_before_writes(self):
        (self.payload / "SKILL.md").write_bytes(b"tampered")
        self.call("install", "--apply", code=1)
        self.assertFalse(self.home.exists())

    def test_installed_baseline_tampering_refused(self):
        self.install()
        base = cli.baseline_path(self.home, self.sha)
        (base / "SKILL.md").write_bytes(b"edited")
        before = self.snapshot()
        self.call("install", "--apply", code=1)
        self.assertEqual(before, self.snapshot())
        self.call("status", code=1)

    def test_missing_adapter_status_and_reinstall(self):
        self.install()
        self.target().unlink()
        self.call("status", code=1)
        self.install()
        self.call("status")

    def test_invalid_state_schema_and_destinations(self):
        entry = {"path": cli.DESTINATIONS["claude"], "sha256": "a" * 64, "baseline": "b" * 64}
        bad = [None, [], {}, {"version": True, "adapters": []}, {"version": 2, "adapters": []},
               {"version": 1, "adapters": [], "extra": 1}, {"version": 1, "adapters": [entry, entry]}]
        for path in ("../escaped", "/tmp/escaped", "C:\\escaped", ".hermes/config.yaml", ".claude/skills/icezy/../SKILL.md"):
            bad.append({"version": 1, "adapters": [dict(entry, path=path)]})
        for key, value in (("sha256", "x" * 64), ("baseline", "../bad"), ("path", [])):
            bad.append({"version": 1, "adapters": [dict(entry, **{key: value})]})
        for state in bad:
            with self.subTest(state=state):
                self.write_state(state)
                before = self.snapshot()
                for command in ("install", "uninstall"):
                    self.call(command, "--apply", code=1)
                    self.assertEqual(before, self.snapshot())
                self.call("status", code=1)

    def test_corrupt_and_duplicate_json_keys_refused(self):
        for raw in (b"not JSON", b"\xff", b'{"version":1,"version":1,"adapters":[]}', b'[' * 2000):
            target = self.home / cli.STATE
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            self.call("install", "--apply", code=1)
            self.assertEqual(target.read_bytes(), raw)
            self.assertFalse((target.parent / "install.lock").exists())

    def symlink(self, link, target, directory=False):
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")

    def test_symlink_adapter_refused(self):
        external = self.root / "owner"
        external.write_text("untouched")
        self.symlink(self.target(), external)
        self.call("install", "--apply", code=1)
        self.assertEqual(external.read_text(encoding='utf-8'), "untouched")
        self.assertFalse((self.home / ".icezy-audit").exists())

    def test_symlink_parent_and_home_refused(self):
        external = self.root / "elsewhere"
        external.mkdir()
        self.symlink(self.home / ".claude", external, True)
        self.call("install", "--apply", code=1)
        self.assertEqual(list(external.iterdir()), [])
        (self.home / ".claude").unlink()
        self.home.rmdir()
        self.symlink(self.home, external, True)
        self.call("install", "--apply", code=1)
        self.assertEqual(list(external.iterdir()), [])

    def test_symlink_state_refused(self):
        external = self.root / "state"
        external.write_text('{"version":1,"adapters":[]}')
        self.symlink(self.home / cli.STATE, external)
        self.call("uninstall", "--apply", code=1)
        self.call("install", "--apply", code=1)
        self.assertEqual(external.read_text(encoding='utf-8'), '{"version":1,"adapters":[]}')

    def test_symlink_payload_refused(self):
        external = self.root / "outside"
        external.write_text("do not copy")
        self.symlink(self.payload / "credential", external)
        self.call("install", "--apply", code=1)
        self.assertFalse(self.home.exists())

    def test_symlink_baseline_parent_refused(self):
        external = self.root / "outside"
        external.mkdir()
        self.symlink(self.home / ".icezy-audit/releases", external, True)
        self.call("install", "--apply", code=1)
        self.assertEqual(list(external.iterdir()), [])

    def test_special_file_directory_refused(self):
        self.target().mkdir(parents=True)
        self.call("install", "--apply", code=1)
        self.assertFalse((self.home / ".icezy-audit").exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_fifo_refused_without_blocking(self):
        self.target().parent.mkdir(parents=True)
        os.mkfifo(self.target())
        self.call("install", "--apply", code=1)
        self.assertFalse((self.home / ".icezy-audit").exists())

    def test_oversized_state_refused(self):
        target = self.home / cli.STATE
        target.parent.mkdir(parents=True)
        with target.open("wb") as stream:
            stream.truncate(cli.LIMIT + 1)
        self.call("install", "--apply", code=1)
        self.assertFalse((target.parent / "install.lock").exists())

    def test_cooperative_lock_refuses_concurrency(self):
        lock = self.home / ".icezy-audit/install.lock"
        lock.parent.mkdir(parents=True)
        lock.write_text("owner lock")
        before = self.snapshot()
        self.call("install", "--apply", code=1)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(lock.read_text(encoding='utf-8'), "owner lock")

    def test_scope_language_and_toml_special_paths(self):
        base = Path('space ü "quote" $dollar `tick` !{never-run} {{args}} \\backslash')
        for agent in cli.DESTINATIONS:
            data = cli.adapter(agent, base).decode()
            prompt = tomllib.loads(data)["prompt"] if agent == "gemini" else data
            for phrase in ("READ-ONLY", "paid APIs", "live probes", "impact-scoped", "every provider", "Firebase is never a default"):
                self.assertIn(phrase, prompt)
            self.assertNotIn("!{", prompt)
            encoded = prompt.split("JSON-encoded filesystem path: ", 1)[1]
            decoded, _ = json.JSONDecoder().raw_decode(encoded)
            self.assertEqual(decoded, str(base / "SKILL.md"))
            if agent == "gemini":
                self.assertEqual(prompt.count("{{args}}"), 1)

    def test_promotion_failure_keeps_existing_adapter_and_state(self):
        self.install()
        before = self.snapshot()
        original_adapter = cli.adapter
        def updated(agent, baseline):
            return original_adapter(agent, baseline) + b"\nNew wrapper version\n"
        with patch.object(cli, "adapter", side_effect=updated), patch.object(cli.os, "replace", side_effect=OSError("injected promotion failure")):
            self.call("install", "--apply", code=1)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.home / ".icezy-audit/install.lock").exists())
        self.assertFalse(list(self.home.rglob(".icezy-stage-*")))

    def test_unselected_managed_symlink_blocks_install_before_writes(self):
        self.install()
        external = self.root / "external"
        external.write_text("owner content")
        self.target("hermes").unlink()
        self.symlink(self.target("hermes"), external)
        self.call("install", "--apply", "--agents", "claude", code=1)
        self.assertEqual(external.read_text(encoding='utf-8'), "owner content")
        self.assertFalse((self.home / ".icezy-audit/install.lock").exists())

    def test_non_target_environment_does_not_redirect_installation(self):
        elsewhere = self.root / "not-authorized"
        with patch.dict(os.environ, {"HERMES_HOME": str(elsewhere), "CLAUDE_CONFIG_DIR": str(elsewhere), "CODEX_HOME": str(elsewhere)}):
            self.install()
        self.assertFalse(elsewhere.exists())


class BundledPayloadTests(unittest.TestCase):
    def test_bundled_text_uses_lf_for_cross_platform_hashes(self):
        for name, data in cli.tree(cli.PAYLOAD).items():
            with self.subTest(path=name):
                self.assertNotIn(b'\r\n', data)

    def test_actual_payload_integrity_and_nested_dotfiles(self):
        files = cli.tree(cli.PAYLOAD)
        self.assertEqual(cli.tree_digest(files), cli.PAYLOAD_DIGEST)
        self.assertEqual(len(files), 17)
        self.assertIn("templates/project-start/.github/copilot-instructions.md", files)
        self.assertIn("templates/project-start/.cursor/rules/security-baseline.mdc", files)

    def test_actual_payload_full_install_in_isolated_home(self):
        with tempfile.TemporaryDirectory(prefix="icezy-real-payload-") as temp:
            home = Path(temp).resolve() / "isolated home"
            output = io.StringIO()
            with redirect_stdout(output):
                result = cli.main(["install", "--home", str(home), "--apply"])
            self.assertEqual(result, 0, output.getvalue())
            self.assertEqual(cli.tree(cli.baseline_path(home, cli.PAYLOAD_DIGEST)), cli.tree(cli.PAYLOAD))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["status", "--home", str(home)]), 0)
                self.assertEqual(cli.main(["uninstall", "--home", str(home), "--apply"]), 0)


if __name__ == "__main__":
    unittest.main()
