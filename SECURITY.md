# Security Policy

## Project Scope

MoonCIDR Audit is an offline analysis library for ordered IPv4 and CIDR
allow/deny rules.

It helps identify potentially unsafe configurations, including:

- overly broad allow rules;
- shadowed or conflicting rules;
- global deny rules;
- duplicate rules;
- non-canonical CIDR input;
- risky special address ranges.

MoonCIDR Audit does not configure firewalls, enforce network traffic, access
cloud accounts, capture packets, or make network requests.

## Reporting a Security Issue

Please avoid publishing sensitive vulnerability details in a public issue.

When private vulnerability reporting is available for this repository, use the
GitHub security advisory reporting interface. Include:

- the affected version or commit;
- a minimal rule set that reproduces the problem;
- the observed audit result;
- the expected result;
- any possible security impact.

Remove real credentials, internal addresses, and confidential infrastructure
information from reproduction examples.

## Security Considerations

Audit results should be treated as review assistance rather than a replacement
for deployment testing or firewall validation.

Users should keep the following limitations in mind:

- rule evaluation depends on rule order;
- CIDR input may be normalized before analysis;
- the current implementation focuses on IPv4;
- imported Nginx and CSV rules are analyzed offline;
- provider-specific firewall behavior is outside the project scope.

## Supported Versions

Security fixes are applied to the latest version available on the main branch.
