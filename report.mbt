///|
/// Builds a compact human-readable audit report.
pub fn AuditReport::text_report(self : AuditReport) -> String {
  let mut output = "MoonCIDR Audit report\n"
  output = output + "rules: " + self.rules.length().to_string() + "\n"
  output = output + "findings: " + self.finding_count().to_string() + "\n"
  output = output +
    "risk: " +
    self.risk_level() +
    " (score=" +
    self.risk_score().to_string() +
    ")\n"
  output = output + "recommendation: " + self.recommended_action() + "\n"
  if self.findings.length() == 0 {
    output + "\nNo findings."
  } else {
    output = output + "\nFindings:\n"
    for finding in self.findings {
      output = output +
        "- [" +
        finding.severity().label() +
        "] " +
        finding.kind().label()
      if finding.rule_id() != "" {
        output = output + " " + finding.rule_id()
      }
      if finding.related_rule_id() != "" {
        output = output + " related=" + finding.related_rule_id()
      }
      output = output + ": " + finding.message() + "\n"
    }
    output
  }
}

///|
/// Builds a stable JSON-like report without external dependencies.
pub fn AuditReport::json_report(self : AuditReport) -> String {
  let mut output = "{"
  output = output + "\"rules\":" + self.rules.length().to_string() + ","
  output = output + "\"findings\":" + self.finding_count().to_string() + ","
  output = output + "\"risk_level\":\"" + escape_json(self.risk_level()) + "\","
  output = output + "\"risk_score\":" + self.risk_score().to_string() + ","
  output = output +
    "\"recommended_action\":\"" +
    escape_json(self.recommended_action()) +
    "\","
  output = output + "\"items\":["
  for index = 0; index < self.findings.length(); index = index + 1 {
    let finding = self.findings[index]
    if index > 0 {
      output = output + ","
    }
    output = output + "{"
    output = output +
      "\"kind\":\"" +
      escape_json(finding.kind().label()) +
      "\","
    output = output +
      "\"severity\":\"" +
      escape_json(finding.severity().label()) +
      "\","
    output = output + "\"rule\":\"" + escape_json(finding.rule_id()) + "\","
    output = output +
      "\"related\":\"" +
      escape_json(finding.related_rule_id()) +
      "\","
    output = output + "\"message\":\"" + escape_json(finding.message()) + "\""
    output = output + "}"
  }
  output + "]}"
}

///|
pub fn AuditReport::summary_table(self : AuditReport) -> String {
  let mut output = "kind | severity | rule | related | message\n"
  output = output + "--- | --- | --- | --- | ---\n"
  for finding in self.findings {
    output = output +
      finding.kind().label() +
      " | " +
      finding.severity().label() +
      " | " +
      finding.rule_id() +
      " | " +
      finding.related_rule_id() +
      " | " +
      finding.message() +
      "\n"
  }
  output
}

///|
fn escape_json(input : String) -> String {
  let chars = input.to_array()
  let output : Array[Char] = []
  for char in chars {
    if char == '"' {
      output.push('\\')
      output.push('"')
    } else if char == '\\' {
      output.push('\\')
      output.push('\\')
    } else if char == '\n' {
      output.push('\\')
      output.push('n')
    } else if char == '\r' {
      output.push('\\')
      output.push('r')
    } else if char == '\t' {
      output.push('\\')
      output.push('t')
    } else {
      output.push(char)
    }
  }
  String::from_array(output)
}
