# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security issue in Steiner, please report it responsibly.

**Preferred:** open a [GitHub Security Advisory](https://github.com/HT88-exe/steiner/security/advisories/new) (private disclosure).

**Alternative:** email **huzaifathak05@gmail.com** with:

- A description of the issue and its impact
- Steps to reproduce
- Affected version or commit

Please do not open a public GitHub issue for exploitable vulnerabilities.

## What to expect

- Acknowledgement within 72 hours
- A fix or mitigation plan within 14 days for confirmed issues
- Credit in the release notes if you would like it

## Scope

In scope:

- Authentication bypass on the MCP ingress or admin API
- Policy bypass (e.g. taint or allowlist enforcement failures)
- Secret leakage in audit logs or error responses
- Upstream credential exposure to downstream clients

Out of scope:

- Vulnerabilities in upstream MCP servers Steiner proxies to
- Attacks that require full compromise of the host running Steiner
- Social engineering of approval workflows
