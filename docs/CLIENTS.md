# Native client adapters

Primary documentation checked 2026-11-22. Documentation support is not live client-session acceptance. No model/provider switch, login, paid inference or global approval configuration is part of installation.

- Claude Code personal skills: `~/.claude/skills/icezy/SKILL.md`, `/icezy audit`. https://code.claude.com/docs/en/slash-commands . Commands have merged into skills; disable-model-invocation makes this explicit-use workflow. Restart the client as needed.
- Codex local user skills: `~/.agents/skills/icezy/SKILL.md`, `$icezy audit` or select in `/skills`. https://developers.openai.com/codex/build-skills . Do not advertise an unsupported `/icezy` custom slash command for Codex.
- Gemini CLI user custom commands: `~/.gemini/commands/icezy.toml`, `/icezy audit`; prompt uses TOML and {{args}}, not shell expansion. https://geminicli.com/docs/cli/custom-commands/ . Project commands can override user commands; reload/start a fresh session as documented by the installed client.
- Cursor global commands: `~/.cursor/commands/icezy.md`, `/icezy audit`. https://cursor.com/docs/agent/chat/commands . Beta command behavior may change; check current version.
- Hermes default user skill: `~/.hermes/skills/icezy/SKILL.md`, dynamic `/icezy audit` where supported, otherwise load the skill by name. https://hermes-agent.nousresearch.com/docs/reference/slash-commands . The installer deliberately does not modify another Hermes profile, config, plugin or alias. Nondefault-profile installation is not implemented in this release.

Global installation supplies on-demand commands. It does NOT force every future project/task to invoke them automatically. Project AGENTS/CLAUDE/GEMINI entrypoints or stronger protected CI gates remain separate opt-in mechanisms.

All adapters refer to a locally installed immutable baseline, not to an arbitrary unpinned web prompt. ChatGPT/Gemini/Claude ordinary web chats do not read these local files automatically. A web UI supporting imported skills has its own installation policy; not covered by the local CLI installer.
