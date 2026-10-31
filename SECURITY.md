# Security Policy

## Responsible use

Aegis-DAST sends security test traffic to web applications. **Only scan systems
you own or have explicit, written authorization to test.** Unauthorized scanning
may be illegal and is never condoned by this project.

Safeguards built into the tool:

- **Scope allowlist** — requests are only sent to hosts/prefixes you explicitly
  allow.
- **Authorization gate** — active (attack) checks require the
  `--i-have-authorization` flag.
- **Non-destructive checks** — built-in active checks use safe, marker-based
  probes and never attempt to modify or delete data.

## Reporting a vulnerability in Aegis-DAST

If you discover a security issue in Aegis-DAST itself, please open a
[GitHub Security Advisory](https://github.com/Upadhyay123a/aegis-dast/security/advisories/new)
or a private report rather than a public issue. We aim to acknowledge reports
within a few days.

## Supported versions

This project is pre-1.0; only the latest `main` is supported.
