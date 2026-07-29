# Project Instructions

This repository is the independent second MoonBit hackathon project.

## Identity

- Do not reuse identity information from any other project.
- Known GitHub account: `BeiLaDuo`.
- Confirmed participant name: `高本乾`.
- The Mooncakes package namespace is `beiladuo`; verify that the active
  Mooncakes login belongs to the second participant before publishing.
- Do not add the participant's email address or phone number to public
  repository files. Those values belong only in the official registration
  form unless the user explicitly requests otherwise.

## Validation

Before reporting the project as ready, run:

```powershell
moon info
moon fmt
moon check
moon build
moon test
moon package --list
```

After `moon fmt`, inspect generated public API files such as
`pkg.generated.mbti` when present.

## Scope

MoonCIDR Audit is an IPv4/CIDR rule audit library. Keep the core library
focused on parsing, normalization, first-match decisions, overlap and shadowing
analysis, offline rule import, CIDR aggregation, coverage analysis, policy
presets, deployment gates, and report output.

Avoid adding live network access, firewall control, packet capture, or
cloud-provider credentials to the core project.
