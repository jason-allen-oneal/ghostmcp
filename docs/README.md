# GhostMCP documentation

GhostMCP is a beta security automation server for authorized assessment workflows. These documents describe the hardened runtime in version `0.2.0`.

## Start here

- [Project overview and quick start](../README.md)
- [Configuration reference](CONFIGURATION.md)
- [Deployment guide](DEPLOYMENT.md)
- [Dashboard and scheduling](DASHBOARD.md)
- [Operations runbook](RUNBOOK.md)
- [Security operations](SECURITY-OPERATIONS.md)
- [Plugin development](PLUGINS.md)
- [Vulnerability reporting](../SECURITY.md)

## Operator model

GhostMCP assumes that the operator:

- Has written authorization for every target
- Defines CIDR, domain, port, and engagement scope before execution
- Reviews installed binaries and explicitly enables optional extension surfaces
- Protects transport tokens, credential keys, audit signing keys, and databases
- Runs the dashboard and scheduler as a single trusted control-plane process unless shared-state behavior has been tested

## Default posture

The shipped configuration is intentionally restrictive:

- Public targets are blocked by default
- Engagement context is required by default
- The global tool ceiling is `active`
- Raw wrappers and plugins are disabled
- Credential storage is disabled
- Remote transport without authentication is blocked
- Dashboard authentication is required

Use [`.env.example`](../.env.example) as the canonical configuration template. The documentation explains the settings, but the template reflects the exact supported environment-variable names.

## Documentation maintenance

When behavior changes, update the relevant guide in the same pull request. In particular, changes to defaults, authentication, scheduling, plugin loading, credential backends, audit fields, CLI entry points, or deployment paths should not be merged without documentation updates.
