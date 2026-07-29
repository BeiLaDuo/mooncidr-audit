///|
fn main {
  let ruleset = @cidr.parse_rules([
    "allow 10.0.0.0/8 corporate network", "deny 10.7.0.0/16 quarantined lab", "allow 10.7.1.0/24 temporary exception",
    "deny 0.0.0.0/0 default deny",
  ])
  println(ruleset.audit().text_report())
  println(ruleset.explain_many(["10.7.1.8", "10.8.1.8", "8.8.8.8"]))
}
