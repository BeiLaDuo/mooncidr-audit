///|
test "coverage stats count actions and scopes" {
  let ruleset = RuleSet::from_lines([
    "allow 10.0.0.0/8", "deny 203.0.113.0/24", "deny 127.0.0.0/8",
  ])
  let stats = ruleset.coverage_stats()
  inspect(stats.total_rules(), content="3")
  inspect(stats.allow_rules(), content="1")
  inspect(stats.deny_rules(), content="2")
  inspect(stats.private_rules(), content="1")
  inspect(stats.public_rules(), content="1")
  inspect(stats.special_rules(), content="1")
}

///|
test "coverage stats tracks widest and narrowest prefix" {
  let stats = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.3/32"]).coverage_stats()
  inspect(stats.widest_prefix(), content="8")
  inspect(stats.narrowest_prefix(), content="32")
}

///|
test "coverage stats handles empty ruleset" {
  let stats = RuleSet::new([]).coverage_stats()
  inspect(
    stats.summary(),
    content="rules=0, allow=0, deny=0, private=0, public=0, special=0, widest=/0, narrowest=/0",
  )
}

///|
test "matching rules returns all hits" {
  let ruleset = RuleSet::from_lines([
    "allow 10.0.0.0/8", "deny 10.1.2.0/24", "allow 192.168.1.0/24",
  ])
  let matches = ruleset.matching_rules(IPv4::parse("10.1.2.5").unwrap())
  inspect(matches.length(), content="2")
  inspect(matches[0].id(), content="R1")
  inspect(matches[1].id(), content="R2")
}

///|
test "explain ip shows no match" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8"])
  inspect(
    ruleset
    .explain_ip(IPv4::parse("8.8.8.8").unwrap())
    .contains("decision: no matching rule"),
    content="true",
  )
}

///|
test "explain ip shows matching rule list" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"])
  let text = ruleset.explain_ip(IPv4::parse("10.1.2.8").unwrap())
  inspect(text.contains("allow by R1"), content="true")
  inspect(text.contains("R2: deny 10.1.2.0/24"), content="true")
}

///|
test "explain many reports invalid probes" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8"])
  inspect(
    ruleset.explain_many(["10.1.2.3", "bad"]).contains("invalid probe bad"),
    content="true",
  )
}

///|
test "first rule for block finds overlap" {
  let ruleset = RuleSet::from_lines(["deny 203.0.113.0/24", "allow 0.0.0.0/0"])
  let block = CidrBlock::parse("203.0.113.128/25").unwrap()
  inspect(ruleset.first_rule_for_block(block), content="R1 deny 203.0.113.0/24")
}

///|
test "inventory report lists rules" {
  let ruleset = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let report = ruleset.inventory_report()
  inspect(report.contains("MoonCIDR inventory"), content="true")
  inspect(report.contains("R1: allow 10.0.0.0/8"), content="true")
}
