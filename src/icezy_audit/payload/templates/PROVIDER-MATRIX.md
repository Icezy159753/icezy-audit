# Project provider matrix

Inventory all actually used services, not a single favored vendor. Do not print secret values. Classify configured/live/legacy/unknown; preserve uncertainty. Each production dependency must have a corresponding manifest provider ID and controls/evidence linked to that ID.

For EACH provider record:
- Stable service ID, product/provider, purpose and environment; target domain/project/resource identifier without bearer URLs or credentials.
- Owner/operator; whether the team, a hosting vendor or a third party controls this layer.
- Data sent/stored, processors/subprocessors and region/transfer/retention/deletion questions.
- Actual enforcement: IAM, middleware, BaaS rules/RLS, DB grants, edge policy, signed URLs and service identities; describe bypass/admin paths.
- Applicable internal control IDs and any exact versioned standard mappings independently checked.
- Safe test scope; identities/tenants/fixtures and proof of negative access, configuration and observed runtime at the actual layer.
- MFA/access review, encryption/keys, private/public exposure, quota/cost, audit logs/alerts, backup restoration and recovery as relevant.
- Evidence paths, tested source/build ref, target/environment, observed time, result and remaining limitations.

Service families to discover (include only those present; record missing/unknown coverage):
Hosting/serverless/VPS/containers; DNS/CDN/WAF/tunnels; DB/BaaS; Auth/OIDC; object/file storage; secrets/KMS; CI/CD/source registries; AI/gateways; payment; email/SMS; analytics/logging/monitoring; queues/jobs; backups/DR.

An API gateway's brand/model list is not proof of its upstream vendor identity, privacy policy or DPA. One provider PASS does not transfer to another. An inaccessible control plane is unverified, not an assumed secure default. Do not turn project discovery into unauthorized testing of unrelated owner accounts.
