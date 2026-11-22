# Project security instructions

Before architecture/scaffolding or implementation, read the project-root `AGENTS.md`, `secure-project-baseline/SKILL.md`, and relevant baseline references. Apply the actual project's security scope, all in-scope provider boundaries and real test/evidence requirements. Do not claim a full baseline read from this short file alone. If files or a required control plane cannot be accessed, report the gap rather than mark checks passed.

Never treat UI checks as authorization, expose secrets, alter owner data, invoke paid/private external services without authorization or claim production readiness from unexecuted checks. Preserve existing project instructions. For existing small changes, scope verification to affected security boundaries rather than launching an unrequested full audit. Mention actual baseline loading and material gaps once at the first development status.

These instructions are context, not a guaranteed enforcement mechanism. Support depends on the Copilot client/surface and its configuration. Protected CI/deployment gates require separate setup.
