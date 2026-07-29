///|
test "GatePolicy validates negative thresholds" {
  match GatePolicy::new("invalid", -1, 0, 0) {
    Err(_) => ()
    Ok(_) => @test.fail("expected negative gate threshold to fail")
  }
}

///|
test "release gate passes clean report" {
  let rules = parse_rules(["allow 203.0.113.9/32 trusted host"])
  let result = rules
    .audit_with_policy(AuditPolicy::quiet())
    .evaluate_gate(GatePolicy::release())
  inspect(result.passed(), content="true")
  inspect(result.decision(), content="pass")
  inspect(result.reason_count(), content="0")
}

///|
test "release gate blocks critical finding" {
  let rules = parse_rules(["allow 0.0.0.0/0 public"])
  let result = rules.audit().evaluate_gate(GatePolicy::release())
  inspect(result.passed(), content="false")
  inspect(result.has_reason("critical_limit"), content="true")
  inspect(result.has_reason("risk_score_limit"), content="true")
}

///|
test "release gate blocks warning budget" {
  let rules = parse_rules(["allow 127.0.0.0/8 loopback"])
  let result = rules.audit().evaluate_gate(GatePolicy::release())
  inspect(result.has_reason("warning_limit"), content="true")
}

///|
test "gate reports parse errors separately" {
  let rules = parse_rules(["allow 10.0.0.0/8", "this is invalid"])
  let result = rules.audit().evaluate_gate(GatePolicy::development())
  inspect(result.has_reason("parse_errors"), content="true")
}

///|
test "custom gate can allow parse errors" {
  let policy = GatePolicy::new(
    "migration",
    10,
    10,
    100,
    allow_parse_errors=true,
  ).unwrap()
  let result = parse_rules(["bad rule"]).audit().evaluate_gate(policy)
  inspect(result.has_reason("parse_errors"), content="false")
}

///|
test "RuleSet evaluates audit and gate policies together" {
  let rules = parse_rules(["allow 10.0.0.0/16 internal"])
  let result = rules.evaluate_gate(
    AuditPolicy::quiet(),
    GatePolicy::development(),
  )
  inspect(result.policy().name(), content="development")
  inspect(result.decision(), content="pass")
}

///|
test "gate report explains blocking reasons" {
  let rules = parse_rules(["deny 0.0.0.0/0 fallback"])
  let result = rules.audit().evaluate_gate(GatePolicy::release())
  inspect(
    result.text_report(),
    content=(
      #|MoonCIDR deployment gate
      #|policy: release
      #|decision: fail
      #|risk_score: 10
      #|
      #|Blocking reasons:
      #|- critical_limit: actual=1, limit=0 (critical finding count exceeds policy)
      #|- risk_score_limit: actual=10, limit=9 (risk score exceeds policy)
      #|
    ),
  )
}
