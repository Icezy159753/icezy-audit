# Icezy Audit threat model

## Trust boundaries

1. Downloaded GitHub source/build versus the local user's execution authority. A pinned tag improves repeatability but a tag can move; prefer reviewed immutable commit when stronger integrity is needed. GitHub publication is not a third-party security certification.
2. Bundled reviewed baseline versus arbitrary local adapter files. Never overwrite a pre-existing unmanaged or user-edited command. Never trust a management manifest to nominate arbitrary filesystem paths.
3. Selected home directory versus unrelated projects, credentials, profiles and system locations. Only exact managed paths may be changed; reject symlink parents and special files, validate state before writes, require explicit --apply.
4. Concurrent cooperating installations versus partial state. Use an exclusive lock and atomic file promotion; refuse ambiguity rather than silently overwrite. A crash may require bounded status/readback recovery; do not treat a partially written adapter as unowned permission to overwrite.
5. AI instruction context versus application enforcement. A prompt is not a sandbox, auth boundary or deploy permission. Never imply that '/icezy audit' performs an independent penetration test or guarantees client/model compliance.

## Abuse cases and negative checks

- Forged state includes ../../.ssh/authorized_keys or absolute paths: reject before side effects.
- Adapter directory or managed state replaced by a symlink/FIFO: fail safely, never follow or hang.
- Existing owner command conflicts: leave bytes unchanged, report conflict.
- Owner edits installed command: preserve it during updates and uninstall; retain referenced baseline.
- Different payload hashes or corrupt/incomplete immutable baseline: refuse reuse until integrity is verified.
- Concurrent installer: one lock holder only; no parallel writes or silent lock removal.
- Malicious API/model output: installer never executes model output or invokes models; audit prompts preserve trust/approval boundaries.
- Public packaging includes home credentials/caches: package only explicit project code/data and inspect wheel/Git paths before publish.

## Residual limits

Filesystem checks are intended for a quiescent owner-controlled home and cooperating installer processes. They are not a compositor-atomic defense against a malicious same-user process racing every read/path rename. Content hashes and agent acknowledgments do not establish authenticity or truth of evidence. Native coding-client behavior remains unverified until its own real session is inspected. Windows/macOS behavior needs platform CI or native tests; Linux execution alone cannot certify them.
