# Security policy

SkillGuardrail processes intentionally hostile content and participates in an installation security boundary. We appreciate careful, private reports that help keep its users safe.

## Supported versions

Until the project reaches `1.0`, only the most recent release receives security fixes. Users should update before reporting an issue that affects an older build.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |
| Unreleased development branch | Best effort |

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** form in the repository's Security tab. This creates a private advisory visible only to the maintainers and invited collaborators.

If private vulnerability reporting is temporarily unavailable, contact the repository owner privately through the contact method listed on the [T-Zevin GitHub profile](https://github.com/T-Zevin). Do not open a public issue for an undisclosed vulnerability.

Include, where possible:

- the affected version, commit, operating system, and architecture;
- the smallest reproducible skill package or archive;
- the expected and observed verdict or installation behavior;
- whether exploitation requires user confirmation;
- impact, suggested severity, and any proposed mitigation;
- whether the report or sample must remain embargoed.

Never include real credentials, access tokens, private repositories, or another person's data. Replace secrets with clearly marked test values.

## Response targets

These are goals rather than contractual service levels:

- acknowledgement within 3 business days;
- initial triage within 7 business days;
- coordinated disclosure after a fix is available, normally within 90 days.

We will credit reporters who request attribution. We may ask to publish an advisory jointly after users have had a reasonable opportunity to update.

## Scope

Examples of in-scope issues include:

- execution of a skill-controlled command during `scan`, `install`, or `verify`;
- archive traversal, symlink escape, or writes outside the intended destination;
- SSRF, redirect-policy bypass, or credential forwarding during source retrieval;
- a policy bypass that allows a critical finding to be installed;
- fingerprint, external-receipt, package-manifest, or verification bypasses;
- terminal escape sequences or report injection with security impact;
- denial of service that bypasses documented size or resource limits.

A missed heuristic on its own may be a detection improvement rather than a product vulnerability. Please still report reliable evasions privately when publishing them first would put users at risk.

## Safe-harbor intent

Good-faith research performed against systems and data you own or are authorized to test is welcome. Avoid privacy violations, service disruption, persistence, and access to third-party data. Give us a reasonable opportunity to investigate before disclosure.

This statement does not authorize testing of GitHub, package registries, agent platforms, or other third-party services.
