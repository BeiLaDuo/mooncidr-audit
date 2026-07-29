///|
test "RuleSet parses lines and skips blanks" {
  let ruleset = RuleSet::from_lines([
    "", "# comment", "allow 10.0.0.0/8", "deny 10.1.2.0/24",
  ])
  inspect(ruleset.rules().length(), content="2")
  inspect(ruleset.parse_errors().length(), content="0")
  inspect(ruleset.rules()[0].id(), content="R1")
}

///|
test "RuleSet captures parse errors" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8", "drop nope"])
  inspect(ruleset.rules().length(), content="1")
  inspect(ruleset.parse_errors().length(), content="1")
  inspect(ruleset.audit().critical_count(), content="2")
}

///|
test "RuleSet decides first matching rule" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"])
  let decision = ruleset.decide(IPv4::parse("10.1.2.9").unwrap())
  inspect(decision.summary(), content="allow by R1 (10.0.0.0/8)")
}

///|
test "RuleSet returns no match decision" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let decision = ruleset.decide(IPv4::parse("8.8.8.8").unwrap())
  inspect(decision.matched(), content="false")
  inspect(decision.summary(), content="no matching rule")
}

///|
test "Audit detects shadowed opposite decision" {
  let report = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"]).audit()
  inspect(report.count_kind(ShadowedRule), content="1")
  inspect(report.critical_count() > 0, content="true")
}

///|
test "Audit detects duplicate rule" {
  let report = RuleSet::from_lines([
    "allow 192.168.1.0/24", "allow 192.168.1.0/24",
  ]).audit()
  inspect(report.count_kind(DuplicateRule), content="1")
  inspect(report.count_kind(ShadowedRule), content="1")
}

///|
test "Audit detects conflicting overlap" {
  let report = RuleSet::from_lines([
    "allow 192.168.0.0/23", "deny 192.168.1.0/24",
  ]).audit()
  inspect(report.count_kind(ShadowedRule), content="1")
  inspect(report.count_kind(ConflictingOverlap), content="0")
}

///|
test "Audit detects partial conflicting overlap" {
  let report = RuleSet::from_lines([
    "allow 192.168.0.0/23", "deny 192.168.1.128/25",
  ]).audit()
  inspect(report.count_kind(ShadowedRule), content="1")
}

///|
test "Audit detects redundant overlap for same action" {
  let report = RuleSet::from_lines(["allow 10.1.0.0/16", "allow 10.1.2.0/24"]).audit()
  inspect(report.count_kind(ShadowedRule), content="1")
}

///|
test "Audit detects global deny" {
  let report = RuleSet::from_lines(["deny 0.0.0.0/0"]).audit()
  inspect(report.count_kind(GlobalDeny), content="1")
  inspect(report.recommended_action(), content="fix_before_release")
}

///|
test "Audit detects too wide allow" {
  let report = RuleSet::from_lines(["allow 0.0.0.0/0"]).audit()
  inspect(report.count_kind(TooWideAllow), content="1")
  inspect(report.risk_level(), content="high")
}

///|
test "Audit detects non canonical CIDR" {
  let report = RuleSet::from_lines(["allow 192.168.1.99/24"]).audit()
  inspect(report.count_kind(NonCanonicalCidr), content="1")
}

///|
test "Audit policy strict flags slash 16 allow" {
  let ruleset = RuleSet::from_lines(["allow 172.16.0.0/16"])
  inspect(ruleset.audit().count_kind(TooWideAllow), content="0")
  inspect(
    ruleset.audit_with_policy(AuditPolicy::strict()).count_kind(TooWideAllow),
    content="1",
  )
}

///|
test "Audit policy quiet hides private range info" {
  let ruleset = RuleSet::from_lines(["allow 192.168.1.0/24"])
  inspect(ruleset.audit().count_kind(PrivateRange), content="1")
  inspect(
    ruleset.audit_with_policy(AuditPolicy::quiet()).count_kind(PrivateRange),
    content="0",
  )
}

///|
test "Audit report counts severities" {
  let report = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"]).audit()
  inspect(report.critical_count(), content="2")
  inspect(report.info_count(), content="2")
  inspect(report.warning_count(), content="0")
}
