///|
fn demo_gateway_rules() -> @cidr.RuleSet {
  @cidr.parse_rules([
    "# ordered gateway ACL", "allow 10.0.0.0/8 internal network", "deny 10.1.2.0/24 blocked service subnet",
    "allow 192.168.1.99/24 office subnet with host bits", "deny 127.0.0.0/8 loopback should not appear in gateway ACL",
    "deny 0.0.0.0/0 final catch-all",
  ])
}

///|
fn print_probe(ruleset : @cidr.RuleSet, ip : String) -> Unit {
  match @cidr.IPv4::parse(ip) {
    Err(err) => println("probe error: \{err}")
    Ok(addr) => {
      let decision = ruleset.decide(addr)
      println("probe \{ip}: \{decision.summary()}")
    }
  }
}

///|
fn main {
  let ruleset = demo_gateway_rules()
  let report = ruleset.audit()
  println("MoonCIDR Audit demo")
  println("")
  println(ruleset.inventory_report())
  println(report.text_report())
  println("")
  println("Probe decisions:")
  print_probe(ruleset, "10.1.2.9")
  print_probe(ruleset, "192.168.1.22")
  print_probe(ruleset, "8.8.8.8")
  println("")
  println("Detailed explanation:")
  println(ruleset.explain_ip(@cidr.IPv4::parse("10.1.2.9").unwrap()))
  println("Deployment gate:")
  println(report.evaluate_gate(@cidr.GatePolicy::release()).text_report())
  println("Coverage holes:")
  println(
    ruleset.coverage_report(
      @cidr.Allow,
      @cidr.CidrBlock::parse("10.0.0.0/8").unwrap(),
    ),
  )
  println("CIDR aggregation:")
  println(
    @cidr.aggregate_cidr_strings([
      "203.0.113.0/25", "203.0.113.128/25", "203.0.113.9/32",
    ]).text_report(),
  )
  println("Nginx import:")
  println(
    @cidr.import_nginx_access([
      "allow 10.0.0.0/8;", "deny 10.1.2.0/24;", "deny all;",
    ]).text_report(),
  )
}
