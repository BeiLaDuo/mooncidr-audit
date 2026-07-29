///|
/// Thresholds used to decide whether a rule set may pass a CI or release gate.
pub struct GatePolicy {
  name : String
  max_critical : Int
  max_warning : Int
  max_risk_score : Int
  allow_parse_errors : Bool
} derive(Eq, Debug)

///|
pub fn GatePolicy::new(
  name : String,
  max_critical : Int,
  max_warning : Int,
  max_risk_score : Int,
  allow_parse_errors? : Bool = false,
) -> Result[GatePolicy, String] {
  guard trim_ascii(name) != "" else {
    return Err("gate policy name must not be empty")
  }
  guard max_critical >= 0 else {
    return Err("maximum critical finding count must not be negative")
  }
  guard max_warning >= 0 else {
    return Err("maximum warning finding count must not be negative")
  }
  guard max_risk_score >= 0 else {
    return Err("maximum risk score must not be negative")
  }
  Ok({ name, max_critical, max_warning, max_risk_score, allow_parse_errors })
}

///|
/// Strict release policy: no critical findings, warnings, or parse errors.
pub fn GatePolicy::release() -> GatePolicy {
  {
    name: "release",
    max_critical: 0,
    max_warning: 0,
    max_risk_score: 9,
    allow_parse_errors: false,
  }
}

///|
/// Review policy: allows a small warning budget but no critical findings.
pub fn GatePolicy::review() -> GatePolicy {
  {
    name: "review",
    max_critical: 0,
    max_warning: 5,
    max_risk_score: 29,
    allow_parse_errors: false,
  }
}

///|
/// Development policy: blocks only very risky reports and parse failures.
pub fn GatePolicy::development() -> GatePolicy {
  {
    name: "development",
    max_critical: 2,
    max_warning: 20,
    max_risk_score: 49,
    allow_parse_errors: false,
  }
}

///|
pub fn GatePolicy::name(self : GatePolicy) -> String {
  self.name
}

///|
pub fn GatePolicy::max_critical(self : GatePolicy) -> Int {
  self.max_critical
}

///|
pub fn GatePolicy::max_warning(self : GatePolicy) -> Int {
  self.max_warning
}

///|
pub fn GatePolicy::max_risk_score(self : GatePolicy) -> Int {
  self.max_risk_score
}

///|
pub fn GatePolicy::allow_parse_errors(self : GatePolicy) -> Bool {
  self.allow_parse_errors
}

///|
pub fn GatePolicy::summary(self : GatePolicy) -> String {
  let parse_error_mode = if self.allow_parse_errors {
    "allowed"
  } else {
    "blocked"
  }
  self.name +
  ": critical<=" +
  self.max_critical.to_string() +
  ", warning<=" +
  self.max_warning.to_string() +
  ", score<=" +
  self.max_risk_score.to_string() +
  ", parse_errors=" +
  parse_error_mode
}

///|
pub struct GateReason {
  code : String
  actual : Int
  limit : Int
  message : String
} derive(Eq, Debug)

///|
pub fn GateReason::new(
  code : String,
  actual : Int,
  limit : Int,
  message : String,
) -> GateReason {
  { code, actual, limit, message }
}

///|
pub fn GateReason::code(self : GateReason) -> String {
  self.code
}

///|
pub fn GateReason::actual(self : GateReason) -> Int {
  self.actual
}

///|
pub fn GateReason::limit(self : GateReason) -> Int {
  self.limit
}

///|
pub fn GateReason::message(self : GateReason) -> String {
  self.message
}

///|
pub fn GateReason::summary(self : GateReason) -> String {
  self.code +
  ": actual=" +
  self.actual.to_string() +
  ", limit=" +
  self.limit.to_string() +
  " (" +
  self.message +
  ")"
}

///|
pub struct GateResult {
  policy : GatePolicy
  passed : Bool
  risk_score : Int
  reasons : Array[GateReason]
} derive(Debug)

///|
pub fn GateResult::policy(self : GateResult) -> GatePolicy {
  self.policy
}

///|
pub fn GateResult::passed(self : GateResult) -> Bool {
  self.passed
}

///|
pub fn GateResult::decision(self : GateResult) -> String {
  if self.passed {
    "pass"
  } else {
    "fail"
  }
}

///|
pub fn GateResult::risk_score(self : GateResult) -> Int {
  self.risk_score
}

///|
pub fn GateResult::reasons(self : GateResult) -> Array[GateReason] {
  self.reasons
}

///|
pub fn GateResult::reason_count(self : GateResult) -> Int {
  self.reasons.length()
}

///|
pub fn GateResult::has_reason(self : GateResult, code : String) -> Bool {
  for reason in self.reasons {
    if reason.code() == code {
      return true
    }
  }
  false
}

///|
pub fn GateResult::text_report(self : GateResult) -> String {
  let mut output = "MoonCIDR deployment gate\n"
  output = output + "policy: " + self.policy.name() + "\n"
  output = output + "decision: " + self.decision() + "\n"
  output = output + "risk_score: " + self.risk_score.to_string() + "\n"
  if self.reasons.length() == 0 {
    output = output + "\nNo gate thresholds were exceeded.\n"
  } else {
    output = output + "\nBlocking reasons:\n"
    for reason in self.reasons {
      output = output + "- " + reason.summary() + "\n"
    }
  }
  output
}

///|
pub fn AuditReport::evaluate_gate(
  self : AuditReport,
  policy : GatePolicy,
) -> GateResult {
  let reasons : Array[GateReason] = []
  let critical = self.critical_count()
  let warning = self.warning_count()
  let score = self.risk_score()
  let parse_errors = self.parse_errors().length()
  if critical > policy.max_critical() {
    reasons.push(
      GateReason::new(
        "critical_limit",
        critical,
        policy.max_critical(),
        "critical finding count exceeds policy",
      ),
    )
  }
  if warning > policy.max_warning() {
    reasons.push(
      GateReason::new(
        "warning_limit",
        warning,
        policy.max_warning(),
        "warning finding count exceeds policy",
      ),
    )
  }
  if score > policy.max_risk_score() {
    reasons.push(
      GateReason::new(
        "risk_score_limit",
        score,
        policy.max_risk_score(),
        "risk score exceeds policy",
      ),
    )
  }
  if parse_errors > 0 && !policy.allow_parse_errors() {
    reasons.push(
      GateReason::new(
        "parse_errors", parse_errors, 0, "invalid rule input is not allowed",
      ),
    )
  }
  { policy, passed: reasons.length() == 0, risk_score: score, reasons }
}

///|
pub fn RuleSet::evaluate_gate(
  self : RuleSet,
  audit_policy : AuditPolicy,
  gate_policy : GatePolicy,
) -> GateResult {
  self.audit_with_policy(audit_policy).evaluate_gate(gate_policy)
}
