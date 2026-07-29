///|
/// Category of remediation hint produced from audit findings.
pub(all) enum HintKind {
  MoveSpecificRule
  TightenCidr
  ConfirmDefaultPolicy
  CanonicalizeInput
  RemoveDuplicate
  ReviewSpecialScope
  FixSyntax
  ReviewOverlap
} derive(Eq, Debug)

///|
pub fn HintKind::label(self : HintKind) -> String {
  match self {
    MoveSpecificRule => "move_specific_rule"
    TightenCidr => "tighten_cidr"
    ConfirmDefaultPolicy => "confirm_default_policy"
    CanonicalizeInput => "canonicalize_input"
    RemoveDuplicate => "remove_duplicate"
    ReviewSpecialScope => "review_special_scope"
    FixSyntax => "fix_syntax"
    ReviewOverlap => "review_overlap"
  }
}

///|
pub struct FixHint {
  kind : HintKind
  severity : Severity
  rule_id : String
  text : String
} derive(Eq, Debug)

///|
pub fn FixHint::new(
  kind : HintKind,
  severity : Severity,
  rule_id : String,
  text : String,
) -> FixHint {
  { kind, severity, rule_id, text }
}

///|
pub fn FixHint::kind(self : FixHint) -> HintKind {
  self.kind
}

///|
pub fn FixHint::severity(self : FixHint) -> Severity {
  self.severity
}

///|
pub fn FixHint::rule_id(self : FixHint) -> String {
  self.rule_id
}

///|
pub fn FixHint::text(self : FixHint) -> String {
  self.text
}

///|
pub fn FixHint::summary(self : FixHint) -> String {
  "[" +
  self.severity.label() +
  "] " +
  self.kind.label() +
  " " +
  self.rule_id +
  ": " +
  self.text
}

///|
pub fn AuditReport::fix_hints(self : AuditReport) -> Array[FixHint] {
  let hints : Array[FixHint] = []
  for finding in self.findings() {
    hints.push(hint_from_finding(finding))
  }
  hints
}

///|
pub fn AuditReport::hint_report(self : AuditReport) -> String {
  let hints = self.fix_hints()
  let mut output = "MoonCIDR remediation hints\n"
  output = output + "hints: " + hints.length().to_string() + "\n"
  if hints.length() == 0 {
    output + "\nNo hints."
  } else {
    output = output + "\nHints:\n"
    for hint in hints {
      output = output + "- " + hint.summary() + "\n"
    }
    output
  }
}

///|
pub fn AuditReport::count_hint_kind(self : AuditReport, kind : HintKind) -> Int {
  let mut count = 0
  for hint in self.fix_hints() {
    if hint.kind() == kind {
      count = count + 1
    }
  }
  count
}

///|
fn hint_from_finding(finding : Finding) -> FixHint {
  match finding.kind() {
    ShadowedRule =>
      FixHint::new(
        MoveSpecificRule,
        finding.severity(),
        finding.rule_id(),
        "move the more specific rule before the broader rule, or remove it if the shadowing is intentional",
      )
    TooWideAllow =>
      FixHint::new(
        TightenCidr,
        finding.severity(),
        finding.rule_id(),
        "replace the broad allow range with the smallest CIDR blocks that are actually required",
      )
    GlobalDeny =>
      FixHint::new(
        ConfirmDefaultPolicy,
        finding.severity(),
        finding.rule_id(),
        "confirm this is the intended default policy and place it after all specific allow or deny rules",
      )
    NonCanonicalCidr =>
      FixHint::new(
        CanonicalizeInput,
        finding.severity(),
        finding.rule_id(),
        "rewrite the CIDR block using its normalized network address",
      )
    DuplicateRule =>
      FixHint::new(
        RemoveDuplicate,
        finding.severity(),
        finding.rule_id(),
        "remove the duplicated rule or merge its note into the original rule",
      )
    PrivateRange | LoopbackRange | LinkLocalRange | MulticastRange =>
      FixHint::new(
        ReviewSpecialScope,
        finding.severity(),
        finding.rule_id(),
        "review whether this address scope belongs in the current gateway or public-facing policy",
      )
    ParseError =>
      FixHint::new(
        FixSyntax,
        finding.severity(),
        finding.rule_id(),
        "fix the rule syntax before relying on audit results",
      )
    ConflictingOverlap | RedundantOverlap =>
      FixHint::new(
        ReviewOverlap,
        finding.severity(),
        finding.rule_id(),
        "review overlapping ranges and split or reorder rules to make intent explicit",
      )
  }
}
