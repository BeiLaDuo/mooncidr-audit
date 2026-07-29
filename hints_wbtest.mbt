///|
test "hints convert shadowed finding" {
  let report = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"]).audit()
  inspect(report.count_hint_kind(MoveSpecificRule), content="1")
}

///|
test "hints convert wide allow" {
  let report = RuleSet::from_lines(["allow 0.0.0.0/0"]).audit()
  inspect(report.count_hint_kind(TightenCidr), content="1")
}

///|
test "hints convert default deny" {
  let report = RuleSet::from_lines(["deny 0.0.0.0/0"]).audit()
  inspect(report.count_hint_kind(ConfirmDefaultPolicy), content="1")
}

///|
test "hints convert non canonical input" {
  let report = RuleSet::from_lines(["allow 192.168.1.99/24"]).audit()
  inspect(report.count_hint_kind(CanonicalizeInput), content="1")
}

///|
test "hints convert duplicate rule" {
  let report = RuleSet::from_lines(["allow 10.1.2.0/24", "allow 10.1.2.0/24"]).audit()
  inspect(report.count_hint_kind(RemoveDuplicate), content="1")
}

///|
test "hints convert special scope" {
  let report = RuleSet::from_lines(["deny 127.0.0.0/8"]).audit()
  inspect(report.count_hint_kind(ReviewSpecialScope), content="1")
}

///|
test "hints convert parse error" {
  let report = RuleSet::from_lines(["allow nope"]).audit()
  inspect(report.count_hint_kind(FixSyntax), content="1")
}

///|
test "hints convert overlap findings" {
  let report = RuleSet::from_lines([
    "allow 192.168.0.0/24", "allow 192.168.0.128/25",
  ]).audit()
  inspect(report.count_hint_kind(MoveSpecificRule), content="1")
}

///|
test "hint report includes summary" {
  let report = RuleSet::from_lines(["deny 0.0.0.0/0"]).audit()
  let text = report.hint_report()
  inspect(text.contains("MoonCIDR remediation hints"), content="true")
  inspect(text.contains("confirm_default_policy"), content="true")
}

///|
test "FixHint summary is stable" {
  let hint = FixHint::new(FixSyntax, Critical, "R1", "fix this")
  inspect(hint.summary(), content="[critical] fix_syntax R1: fix this")
}
