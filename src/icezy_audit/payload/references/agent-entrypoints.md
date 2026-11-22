# Multi-agent project entrypoints

Primary documentation checked 2026-11-22. Behavior depends on client version, project root, workspace trust, overrides and instruction size/settings; do not promise universal automatic activation or obedience.

- OpenAI Codex project instruction discovery: https://developers.openai.com/codex/agent-configuration/agents-md . AGENTS.override.md can override AGENTS.md at a directory; instruction chain and size limits apply. AGENTS.md is not a native import processor for arbitrary referenced files; explicitly instruct reading the shared baseline.
- Claude Code memory/context and @imports: https://code.claude.com/docs/en/memory . Root CLAUDE.md imports AGENTS.md. Context instructions are not tool-blocking policy. Do not duplicate entire baseline across wrappers.
- Gemini CLI GEMINI.md context/imports: https://geminicli.com/docs/cli/gemini-md/ . @./AGENTS.md imports relative context; /memory show inspects it. Do not extrapolate CLI support to Gemini web/Code Assist without verifying that product.
- GitHub Copilot repository-wide instructions: https://docs.github.com/copilot/customizing-copilot/adding-repository-custom-instructions-for-github-copilot . .github/copilot-instructions.md support varies across surfaces. This wrapper includes essential instructions directly, not an assumed universal @import.
- Cursor rules: https://cursor.com/docs/rules.md . .cursor/rules/*.mdc supports alwaysApply; ordinary .md in this directory is not the same rule format. AlwaysApply includes context, not a hard execution/release gate.

Package builder includes templates/project-start contents at archive ROOT plus the shared secure-project-baseline/ directory. Never make the entire starter directory itself the baseline directory: root placement determines discovery. For existing projects, merge entrypoints without overwriting instructions. Check AGENTS.override.md/nested rules and managed policies rather than overriding them to force behavior. Do not configure global hooks or add providers/credentials merely to install project context.

Verification scope: validate file layout/import targets/metadata and run the packaged helper tests in an extracted synthetic workspace. Unless actual native agent sessions were started and their loaded-context evidence inspected, report discovery behavior as documented support, not live cross-client acceptance. No paid inference is authorized by packaging alone.
