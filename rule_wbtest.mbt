///|
test "RuleAction parser supports common aliases" {
  inspect(RuleAction::parse("allow").unwrap().label(), content="allow")
  inspect(RuleAction::parse("PERMIT").unwrap().label(), content="allow")
  inspect(RuleAction::parse("block").unwrap().label(), content="deny")
  inspect(RuleAction::parse("reject").unwrap().label(), content="deny")
}

///|
test "RuleAction parser rejects unknown action" {
  match RuleAction::parse("maybe") {
    Ok(_) => inspect("ok", content="err")
    Err(err) => inspect(err, content="unknown rule action: maybe")
  }
}

///|
test "Rule parser accepts action and CIDR" {
  let rule = Rule::parse("R1", "allow 192.168.1.0/24").unwrap()
  inspect(rule.id(), content="R1")
  inspect(rule.action().label(), content="allow")
  inspect(rule.block().to_string(), content="192.168.1.0/24")
}

///|
test "Rule parser accepts comment and note" {
  let rule = Rule::parse("R2", "deny 10.0.0.0/8 internal traffic # ignored").unwrap()
  inspect(rule.note(), content="internal traffic")
  inspect(rule.summary(), content="R2: deny 10.0.0.0/8 # internal traffic")
}

///|
test "Rule parser rejects incomplete line" {
  match Rule::parse("R3", "allow") {
    Ok(_) => inspect("ok", content="err")
    Err(err) =>
      inspect(
        err,
        content="rule line must contain an action and a CIDR block: allow",
      )
  }
}

///|
test "Rule remembers non canonical input" {
  let rule = Rule::parse("R4", "allow 192.168.1.99/24").unwrap()
  inspect(rule.source_block(), content="192.168.1.99/24")
  inspect(rule.block().to_string(), content="192.168.1.0/24")
  inspect(rule.is_canonical(), content="false")
}

///|
test "Rule matches IP" {
  let rule = Rule::parse("R5", "deny 203.0.113.0/24").unwrap()
  inspect(rule.matches(IPv4::parse("203.0.113.7").unwrap()), content="true")
  inspect(rule.matches(IPv4::parse("203.0.114.7").unwrap()), content="false")
}
