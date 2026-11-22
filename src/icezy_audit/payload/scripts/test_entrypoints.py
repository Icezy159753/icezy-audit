"""Static entrypoint/layout checks only; no native coding agent is invoked."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
START = ROOT / 'templates/project-start'


class EntrypointTests(unittest.TestCase):
    def test_all_documented_entrypoints_exist(self):
        for p in ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.github/copilot-instructions.md', '.cursor/rules/security-baseline.mdc', 'START-HERE.md']:
            with self.subTest(path=p): self.assertTrue((START / p).is_file())

    def test_claude_import_points_to_existing_file(self):
        text = (START / 'CLAUDE.md').read_text(encoding='utf-8')
        imports = re.findall(r'^@([^\s]+)$', text, re.M)
        self.assertEqual(imports, ['AGENTS.md'])
        self.assertTrue((START / imports[0]).is_file())

    def test_gemini_import_points_to_existing_file(self):
        text = (START / 'GEMINI.md').read_text(encoding='utf-8')
        imports = re.findall(r'^@([^\s]+)$', text, re.M)
        self.assertEqual(imports, ['./AGENTS.md'])
        self.assertTrue((START / imports[0]).is_file())

    def test_cursor_always_apply_metadata(self):
        text = (START / '.cursor/rules/security-baseline.mdc').read_text(encoding='utf-8')
        self.assertTrue(text.startswith('---\n'))
        front = text.split('---', 2)[1]
        self.assertRegex(front, r'(?m)^alwaysApply: true$')

    def test_agent_entry_reads_canonical_baseline(self):
        text = (START / 'AGENTS.md').read_text(encoding='utf-8')
        self.assertIn('~/.claude/skills/icezy/SKILL.md', text)
        self.assertIn('ALL in-scope services', text)
        self.assertIn('not OS-enforced policy', text)
        self.assertTrue((ROOT / 'SKILL.md').is_file())

    def test_copilot_is_not_assumed_import(self):
        text = (START / '.github/copilot-instructions.md').read_text(encoding='utf-8')
        self.assertIn('`icezy` skill', text)
        self.assertIn('depends on the Copilot client', text)

    def test_no_reference_to_uninstalled_project_copy(self):
        # The installer keeps the baseline under the user's home, never in the project.
        for path in docs():
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertNotIn('secure-project-baseline/', path.read_text(encoding='utf-8'))

    def test_referenced_payload_files_exist(self):
        pattern = re.compile(r'`((?:references|templates|scripts)/[\w./-]+)`')
        for path in docs():
            for ref in pattern.findall(path.read_text(encoding='utf-8')):
                with self.subTest(path=path.relative_to(ROOT).as_posix(), ref=ref):
                    self.assertTrue((ROOT / ref).exists())

    def test_baseline_uses_no_client_specific_tool_syntax(self):
        text = (ROOT / 'SKILL.md').read_text(encoding='utf-8')
        for token in ('terminal(command=', 'skill_view', '/skill '):
            with self.subTest(token=token):
                self.assertNotIn(token, text)


def docs():
    return sorted(p for p in ROOT.rglob('*') if p.suffix in {'.md', '.mdc'} and p.is_file())

    def test_primary_sources_recorded(self):
        text = (ROOT / 'references/agent-entrypoints.md').read_text(encoding='utf-8')
        for domain in ['developers.openai.com', 'code.claude.com', 'geminicli.com', 'docs.github.com', 'cursor.com']:
            self.assertIn(domain, text)

    def test_existing_project_warning_present(self):
        text = (START / 'START-HERE.md').read_text(encoding='utf-8')
        self.assertIn('อย่าแตกไฟล์ทับ', text)
        self.assertIn('AGENTS.override.md', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
