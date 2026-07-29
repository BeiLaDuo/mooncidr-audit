///|
test "public API parses and audits rules" {
  let ruleset = @cidr-audit.parse_rules([
    "allow 10.0.0.0/8", "deny 10.1.2.0/24", "allow 192.168.1.99/24",
  ])
  let report = ruleset.audit()
  inspect(report.finding_count() >= 3, content="true")
  inspect(report.count_kind(@cidr-audit.ShadowedRule), content="1")
  inspect(report.count_kind(@cidr-audit.NonCanonicalCidr), content="1")
}

///|
test "public API answers address decision" {
  let ruleset = @cidr-audit.parse_rules([
    "deny 203.0.113.0/24", "allow 0.0.0.0/0",
  ])
  let ip = @cidr-audit.IPv4::parse("203.0.113.10").unwrap()
  inspect(ruleset.decide(ip).summary(), content="deny by R1 (203.0.113.0/24)")
}

///|
test "public API supports policy presets" {
  let ruleset = @cidr-audit.parse_rules(["allow 172.16.0.0/16"])
  let report = ruleset.audit_with_policy(@cidr-audit.AuditPolicy::strict())
  inspect(report.count_kind(@cidr-audit.TooWideAllow), content="1")
  inspect(report.text_report().contains("too_wide_allow"), content="true")
}
