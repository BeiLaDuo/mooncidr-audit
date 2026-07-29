///|
/// Severity assigned to an audit finding.
pub(all) enum Severity {
  Info
  Warning
  Critical
} derive(Eq, Debug)

///|
pub fn Severity::label(self : Severity) -> String {
  match self {
    Info => "info"
    Warning => "warning"
    Critical => "critical"
  }
}

///|
pub fn Severity::score(self : Severity) -> Int {
  match self {
    Info => 1
    Warning => 4
    Critical => 10
  }
}

///|
/// Classifies why a rule deserves attention.
pub(all) enum FindingKind {
  DuplicateRule
  ShadowedRule
  ConflictingOverlap
  RedundantOverlap
  TooWideAllow
  GlobalDeny
  PrivateRange
  LoopbackRange
  LinkLocalRange
  MulticastRange
  NonCanonicalCidr
  ParseError
} derive(Eq, Debug)

///|
pub fn FindingKind::label(self : FindingKind) -> String {
  match self {
    DuplicateRule => "duplicate_rule"
    ShadowedRule => "shadowed_rule"
    ConflictingOverlap => "conflicting_overlap"
    RedundantOverlap => "redundant_overlap"
    TooWideAllow => "too_wide_allow"
    GlobalDeny => "global_deny"
    PrivateRange => "private_range"
    LoopbackRange => "loopback_range"
    LinkLocalRange => "link_local_range"
    MulticastRange => "multicast_range"
    NonCanonicalCidr => "non_canonical_cidr"
    ParseError => "parse_error"
  }
}

///|
pub struct Finding {
  kind : FindingKind
  severity : Severity
  rule_id : String
  related_rule_id : String
  message : String
} derive(Eq, Debug)

///|
pub fn Finding::new(
  kind : FindingKind,
  severity : Severity,
  rule_id : String,
  message : String,
  related_rule_id? : String = "",
) -> Finding {
  { kind, severity, rule_id, related_rule_id, message }
}

///|
pub fn Finding::kind(self : Finding) -> FindingKind {
  self.kind
}

///|
pub fn Finding::severity(self : Finding) -> Severity {
  self.severity
}

///|
pub fn Finding::rule_id(self : Finding) -> String {
  self.rule_id
}

///|
pub fn Finding::related_rule_id(self : Finding) -> String {
  self.related_rule_id
}

///|
pub fn Finding::message(self : Finding) -> String {
  self.message
}

///|
pub struct Decision {
  matched : Bool
  action : RuleAction
  rule_id : String
  block : String
} derive(Eq, Debug)

///|
pub fn Decision::matched(self : Decision) -> Bool {
  self.matched
}

///|
pub fn Decision::action(self : Decision) -> RuleAction {
  self.action
}

///|
pub fn Decision::rule_id(self : Decision) -> String {
  self.rule_id
}

///|
pub fn Decision::block(self : Decision) -> String {
  self.block
}

///|
pub fn Decision::summary(self : Decision) -> String {
  if self.matched {
    self.action.label() + " by " + self.rule_id + " (" + self.block + ")"
  } else {
    "no matching rule"
  }
}

///|
pub struct AuditReport {
  rules : Array[Rule]
  findings : Array[Finding]
  parse_errors : Array[String]
} derive(Debug)

///|
pub fn AuditReport::rules(self : AuditReport) -> Array[Rule] {
  self.rules
}

///|
pub fn AuditReport::findings(self : AuditReport) -> Array[Finding] {
  self.findings
}

///|
pub fn AuditReport::parse_errors(self : AuditReport) -> Array[String] {
  self.parse_errors
}

///|
pub fn AuditReport::finding_count(self : AuditReport) -> Int {
  self.findings.length()
}

///|
pub fn AuditReport::critical_count(self : AuditReport) -> Int {
  self.count_severity(Critical)
}

///|
pub fn AuditReport::warning_count(self : AuditReport) -> Int {
  self.count_severity(Warning)
}

///|
pub fn AuditReport::info_count(self : AuditReport) -> Int {
  self.count_severity(Info)
}

///|
pub fn AuditReport::count_kind(self : AuditReport, kind : FindingKind) -> Int {
  let mut count = 0
  for finding in self.findings {
    if finding.kind() == kind {
      count = count + 1
    }
  }
  count
}

///|
pub fn AuditReport::count_severity(
  self : AuditReport,
  severity : Severity,
) -> Int {
  let mut count = 0
  for finding in self.findings {
    if finding.severity() == severity {
      count = count + 1
    }
  }
  count
}

///|
pub fn AuditReport::risk_score(self : AuditReport) -> Int {
  let mut score = 0
  for finding in self.findings {
    score = score + finding.severity().score()
  }
  score + self.parse_errors.length() * 10
}

///|
pub fn AuditReport::risk_level(self : AuditReport) -> String {
  let score = self.risk_score()
  if self.critical_count() > 0 || score >= 30 {
    "high"
  } else if score >= 10 {
    "medium"
  } else if score > 0 {
    "low"
  } else {
    "clean"
  }
}

///|
pub fn AuditReport::recommended_action(self : AuditReport) -> String {
  if self.parse_errors.length() > 0 || self.critical_count() > 0 {
    "fix_before_release"
  } else if self.warning_count() > 0 {
    "review"
  } else {
    "accept"
  }
}

///|
pub struct RuleSet {
  rules : Array[Rule]
  parse_errors : Array[String]
} derive(Debug)

///|
pub fn RuleSet::new(rules : Array[Rule]) -> RuleSet {
  { rules, parse_errors: [] }
}

///|
pub fn RuleSet::from_lines(lines : Array[String]) -> RuleSet {
  let rules : Array[Rule] = []
  let errors : Array[String] = []
  for index = 0; index < lines.length(); index = index + 1 {
    let line = trim_ascii(lines[index])
    if line == "" || starts_with(line, "#") {
      continue
    }
    match Rule::parse("R" + (rules.length() + 1).to_string(), line) {
      Ok(rule) => rules.push(rule)
      Err(err) => errors.push("line " + (index + 1).to_string() + ": " + err)
    }
  }
  { rules, parse_errors: errors }
}

///|
pub fn RuleSet::rules(self : RuleSet) -> Array[Rule] {
  self.rules
}

///|
pub fn RuleSet::parse_errors(self : RuleSet) -> Array[String] {
  self.parse_errors
}

///|
pub fn RuleSet::decide(self : RuleSet, ip : IPv4) -> Decision {
  for rule in self.rules {
    if rule.matches(ip) {
      return {
        matched: true,
        action: rule.action(),
        rule_id: rule.id(),
        block: rule.block().to_string(),
      }
    }
  }
  { matched: false, action: Deny, rule_id: "", block: "" }
}

///|
pub fn RuleSet::audit(self : RuleSet) -> AuditReport {
  self.audit_with_policy(AuditPolicy::gateway())
}

///|
pub fn RuleSet::audit_with_policy(
  self : RuleSet,
  policy : AuditPolicy,
) -> AuditReport {
  let findings : Array[Finding] = []
  for index = 0; index < self.rules.length(); index = index + 1 {
    let rule = self.rules[index]
    analyze_single_rule(rule, policy, findings)
    for prev_index = 0; prev_index < index; prev_index = prev_index + 1 {
      analyze_pair(self.rules[prev_index], rule, policy, findings)
    }
  }
  for err in self.parse_errors {
    findings.push(Finding::new(ParseError, Critical, "", err))
  }
  { rules: self.rules, findings, parse_errors: self.parse_errors }
}

///|
pub fn audit_rules(rules : Array[Rule]) -> AuditReport {
  RuleSet::new(rules).audit()
}

///|
pub fn audit_rules_with_policy(
  rules : Array[Rule],
  policy : AuditPolicy,
) -> AuditReport {
  RuleSet::new(rules).audit_with_policy(policy)
}

///|
pub fn parse_rules(lines : Array[String]) -> RuleSet {
  RuleSet::from_lines(lines)
}

///|
fn analyze_single_rule(
  rule : Rule,
  policy : AuditPolicy,
  findings : Array[Finding],
) -> Unit {
  let block = rule.block()
  if policy.flag_non_canonical() && !rule.is_canonical() {
    findings.push(
      Finding::new(
        NonCanonicalCidr,
        Info,
        rule.id(),
        "input " +
        rule.source_block() +
        " was normalized to " +
        block.to_string(),
      ),
    )
  }
  if rule.action() == Allow && block.prefix() <= policy.wide_allow_prefix() {
    findings.push(
      Finding::new(
        TooWideAllow,
        Critical,
        rule.id(),
        "allow rule covers a very wide network: " + block.to_string(),
      ),
    )
  }
  if rule.action() == Deny && block.prefix() == 0 {
    findings.push(
      Finding::new(
        GlobalDeny,
        Critical,
        rule.id(),
        "deny rule blocks the entire IPv4 space",
      ),
    )
  }
  let scope = block.network().scope_label()
  if policy.flag_private() && scope == "private" {
    findings.push(
      Finding::new(
        PrivateRange,
        Info,
        rule.id(),
        "rule targets private address space: " + block.to_string(),
      ),
    )
  } else if policy.flag_special_ranges() && scope == "loopback" {
    findings.push(
      Finding::new(
        LoopbackRange,
        Warning,
        rule.id(),
        "rule targets loopback address space: " + block.to_string(),
      ),
    )
  } else if policy.flag_special_ranges() && scope == "link_local" {
    findings.push(
      Finding::new(
        LinkLocalRange,
        Warning,
        rule.id(),
        "rule targets link-local address space: " + block.to_string(),
      ),
    )
  } else if policy.flag_special_ranges() && scope == "multicast" {
    findings.push(
      Finding::new(
        MulticastRange,
        Warning,
        rule.id(),
        "rule targets multicast address space: " + block.to_string(),
      ),
    )
  }
}

///|
fn analyze_pair(
  previous : Rule,
  current : Rule,
  policy : AuditPolicy,
  findings : Array[Finding],
) -> Unit {
  if previous.block().equal_range(current.block()) {
    findings.push(
      Finding::new(
        DuplicateRule,
        Warning,
        current.id(),
        "rule duplicates earlier rule " +
        previous.id() +
        ": " +
        current.block().to_string(),
        related_rule_id=previous.id(),
      ),
    )
  }
  if previous.block().contains_block(current.block()) {
    findings.push(
      Finding::new(
        ShadowedRule,
        if previous.action() == current.action() {
          Warning
        } else {
          Critical
        },
        current.id(),
        "rule is already covered by earlier " +
        previous.action().label() +
        " rule " +
        previous.id(),
        related_rule_id=previous.id(),
      ),
    )
  } else if previous.block().overlaps(current.block()) {
    if previous.same_decision(current) && policy.flag_redundant_overlap() {
      findings.push(
        Finding::new(
          RedundantOverlap,
          Info,
          current.id(),
          "rule overlaps earlier same-action rule " + previous.id(),
          related_rule_id=previous.id(),
        ),
      )
    } else {
      findings.push(
        Finding::new(
          ConflictingOverlap,
          Critical,
          current.id(),
          "rule overlaps earlier opposite-action rule " + previous.id(),
          related_rule_id=previous.id(),
        ),
      )
    }
  }
}

///|
fn starts_with(input : String, prefix : String) -> Bool {
  let chars = input.to_array()
  let prefix_chars = prefix.to_array()
  if prefix_chars.length() > chars.length() {
    false
  } else {
    let mut ok = true
    for index = 0; index < prefix_chars.length(); index = index + 1 {
      if chars[index] != prefix_chars[index] {
        ok = false
      }
    }
    ok
  }
}
