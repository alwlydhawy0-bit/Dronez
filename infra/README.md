# Infrastructure

Empty at Milestone 0 by design — there is nothing flight-capable to deploy yet.

The rules that will govern everything placed here, from Zero-Trust v3.0-ULTRA §6.1:

- **All infrastructure is provisioned exclusively through version-controlled IaC.** Manual
  console changes to production are forbidden and, where technically enforceable, blocked at
  the IAM policy level.
- IaC is scanned for misconfiguration (`tfsec`, `checkov`) as a **pre-merge gate**.
- Kubernetes enforces Pod Security Standards at the `restricted` level via an admission
  controller. No workload gets privileged mode, host networking, or host PID/IPC namespaces
  without a signed exception.
- Containers run non-root (UID ≥ 10001) with a read-only root filesystem and all Linux
  capabilities dropped except those demonstrably required.
- Secrets are injected at runtime from Vault / AWS Secrets Manager. **Zero hardcoded keys in
  git**, enforced by GitLeaks/Trufflehog in pre-commit and pipeline gates.
- NetworkPolicies and security groups allow egress **only** to explicitly allow-listed
  endpoints. The sovereign NFZ feed will be one of them; it is reached through the egress
  proxy, not directly (§3.3).

```
terraform/   Cloud resources, database privileges, network policy
k8s/         Workload manifests and admission policy
```
