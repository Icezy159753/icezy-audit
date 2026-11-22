# Icezy Audit security profile

## Scope

A public, stdlib-only local Python installer and reusable AI security-development guidance. This is not a hosted application, vulnerability scanner, security certification, identity provider, or managed deployment gate. No passwords, keys, prompts, telemetry or project source are transmitted by the installer.

## Data and principals

The owner authorizes installation in their own home directory without administrator privileges. The installer writes explicitly selected AI command/skill adapters, a content-addressed baseline copy and a small management manifest. Source projects and other profiles/configuration are out of scope. Audit commands are read-only scoped guidance unless the user explicitly authorizes a different operation; start mode prepares project security design before implementation.

## Providers

- GitHub: public source/tags/CI distribution; reviewed source and tag/commit integrity matter. Hosting security controls remain GitHub-managed; this project has not audited GitHub's control plane.
- Python packaging/build tooling and official registries: optional installation-time delivery dependencies. Runtime has no third-party package dependencies.
- AI coding clients (Claude Code, Codex, Gemini CLI, Cursor, Hermes): each owns instruction discovery, workspace trust, approvals and model/network policy. Installed prompt files cannot override them or guarantee obedience.
- Any AI/model or cloud provider used by a target project: NOT audited or contacted by installation. The baseline requires their own inventory/authorization/evidence in that project, with no vendor default.

## Safe defaults

Install defaults to preview; writes require --apply. User-agent adapter paths are an exact allowlist. Existing unowned or modified files must block, not be replaced. Relative managed paths and all parents are validated; no traversal/symlinks/special files. Stored hashes establish local content consistency, not authenticity of upstream models or safety against a malicious same-user process. Uninstall only removes unchanged owned adapters and preserves modified files/shared baseline.

## Assurance and release scope

Tests run against synthetic temporary homes, never the real user's clients. Packaging tests verify adapter layout/syntax, not live instruction loading/obedience in each native client. Official documentation is the basis for supported discovery conventions. No global config hooks, sandbox bypasses, provider credentials or production CI protection are installed.

Before public release: actual regression/package smoke tests, secret-pattern review, scoped code review, exact GitHub readback and clear remaining limits. This tooling release does not claim ASVS/MASVS/PDPA compliance or production-app audit completion.
