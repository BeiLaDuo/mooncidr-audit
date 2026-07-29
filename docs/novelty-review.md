# Novelty Review

## Summary

MoonCIDR Audit is not a generic IP parser. Its project value is the ordered
CIDR rule audit layer: rule shadowing, overlapping decisions, dangerous wide
allows, global deny rules, special address scope checks, policy presets, and
human-readable reports.

## Search Notes

Before implementation, public MoonBit ecosystem references were checked at a
high level, including Mooncakes, the official MoonBit package documentation,
awesome-moonbit, and visible GitHub/Mooncakes networking-related packages.

Search terms used:

- `site:mooncakes.io cidr MoonBit`
- `site:mooncakes.io "CIDR" "MoonBit"`
- `site:github.com "MoonBit" "CIDR" "audit"`
- `site:github.com "moonbit" "cidr" "allow" "deny"`

Observed nearby areas:

- URL and address parsing utilities.
- Socket or networking examples.
- TLS or network fingerprinting utilities.
- Rate limiting and request handling libraries.
- General MoonBit package examples.

The distinctive scope of this project is:

- ordered allow/deny CIDR rules;
- audit findings for security and operations review;
- first-match decision explanation;
- CIDR normalization warnings;
- remediation hints;
- rule-set diff reports for CI review;
- CIDR deduplication and recursive sibling aggregation;
- coverage-hole analysis inside a target network;
- offline Nginx and CSV rule import with structured diagnostics;
- configurable deployment gates for automated review;
- report rendering for CI or review workflows.

No highly overlapping public MoonBit project was found during this check. This
is not a guarantee that no similar private or newly published project exists,
so the submission wording should be: "未发现与本项目功能高度重合的 MoonBit
公开生态项目。"

## Why It Is Different

Many network libraries answer whether an address is syntactically valid. This
project answers a higher-level review question: what will this ordered rule set
actually do, and which rules are risky or ineffective?

For example, this project can identify that:

```text
allow 10.0.0.0/8
deny 10.1.2.0/24
```

makes the second rule unreachable under first-match semantics. It can also show
that:

```text
allow 192.168.1.99/24
```

is non-canonical and is normalized to `192.168.1.0/24`.

## Intended Non-Goals

- Not a packet filter.
- Not a firewall frontend.
- Not an IPv6 implementation yet.
- Not a live cloud-provider or firewall management client.
- Not a replacement for production network policy engines.

The narrow boundary keeps the project practical for a hackathon while still
being reusable inside future MoonBit developer tools.
