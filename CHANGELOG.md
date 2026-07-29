# Changelog

## 0.1.0

- Added IPv4 parser and dotted decimal rendering.
- Added CIDR parser, normalization, range containment, and overlap checks.
- Added ordered allow/deny rule parsing.
- Added rule decision and matching explanation helpers.
- Added audit findings for duplicates, shadowing, conflicts, wide allows,
  global deny rules, special address spaces, and non-canonical CIDR input.
- Added strict, gateway, and quiet audit policies.
- Added text, table, and JSON-like report rendering.
- Added address-range union and target coverage-hole analysis.
- Added CIDR deduplication, containment reduction, and recursive sibling
  aggregation.
- Added offline import reports for native rules, Nginx access directives, and
  CSV rule lists.
- Added configurable development, review, and release gates for CI workflows.
- Added main demo and two example scenarios.
- Added CI workflow and test coverage.
