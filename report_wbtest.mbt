///|
test "text report includes important summary fields" {
  let report = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 10.1.2.0/24"]).audit()
  let text = report.text_report()
  inspect(text.contains("MoonCIDR Audit report"), content="true")
  inspect(text.contains("shadowed_rule"), content="true")
  inspect(text.contains("fix_before_release"), content="true")
}

///|
test "json report includes stable keys" {
  let report = RuleSet::from_lines(["deny 0.0.0.0/0"]).audit()
  let json = report.json_report()
  inspect(json.contains("\"risk_level\""), content="true")
  inspect(json.contains("\"global_deny\""), content="true")
}

///|
test "summary table has markdown header" {
  let report = RuleSet::from_lines(["deny 0.0.0.0/0"]).audit()
  inspect(
    report
    .summary_table()
    .contains("kind | severity | rule | related | message"),
    content="true",
  )
}

///|
test "json report escapes text" {
  let finding = Finding::new(
    ParseError,
    Critical,
    "R1",
    "bad \"quoted\" value\nnext",
  )
  let report : AuditReport = {
    rules: [],
    findings: [finding],
    parse_errors: [],
  }
  inspect(report.json_report().contains("\\\"quoted\\\""), content="true")
  inspect(report.json_report().contains("\\nnext"), content="true")
}
