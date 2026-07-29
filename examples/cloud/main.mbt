///|
fn main {
  let ruleset = @cidr.parse_rules([
    "deny 203.0.113.0/24 blocked documentation network", "allow 203.0.113.128/25 overlapping exception",
    "allow 198.51.100.0/24 partner range", "allow 192.168.10.99/24 internal range written with host bits",
  ])
  let report = ruleset.audit_with_policy(@cidr.AuditPolicy::strict())
  println(report.text_report())
  println("JSON:")
  println(report.json_report())
}
