///|
/// Type of change between two rule sets.
pub(all) enum RuleChangeKind {
  AddedRule
  RemovedRule
  ActionChanged
  NoteChanged
  UnchangedRule
} derive(Eq, Debug)

///|
pub fn RuleChangeKind::label(self : RuleChangeKind) -> String {
  match self {
    AddedRule => "added_rule"
    RemovedRule => "removed_rule"
    ActionChanged => "action_changed"
    NoteChanged => "note_changed"
    UnchangedRule => "unchanged_rule"
  }
}

///|
pub fn RuleChangeKind::is_risky(self : RuleChangeKind) -> Bool {
  match self {
    AddedRule | RemovedRule | ActionChanged => true
    NoteChanged | UnchangedRule => false
  }
}

///|
/// A change item matched by CIDR range.
pub struct RuleChange {
  kind : RuleChangeKind
  before_id : String
  after_id : String
  block : String
  message : String
} derive(Eq, Debug)

///|
pub fn RuleChange::new(
  kind : RuleChangeKind,
  before_id : String,
  after_id : String,
  block : String,
  message : String,
) -> RuleChange {
  { kind, before_id, after_id, block, message }
}

///|
pub fn RuleChange::kind(self : RuleChange) -> RuleChangeKind {
  self.kind
}

///|
pub fn RuleChange::before_id(self : RuleChange) -> String {
  self.before_id
}

///|
pub fn RuleChange::after_id(self : RuleChange) -> String {
  self.after_id
}

///|
pub fn RuleChange::block(self : RuleChange) -> String {
  self.block
}

///|
pub fn RuleChange::message(self : RuleChange) -> String {
  self.message
}

///|
pub fn RuleChange::summary(self : RuleChange) -> String {
  self.kind.label() + " " + self.block + ": " + self.message
}

///|
pub struct DiffReport {
  changes : Array[RuleChange]
} derive(Debug)

///|
pub fn DiffReport::changes(self : DiffReport) -> Array[RuleChange] {
  self.changes
}

///|
pub fn DiffReport::change_count(self : DiffReport) -> Int {
  self.changes.length()
}

///|
pub fn DiffReport::count_kind(self : DiffReport, kind : RuleChangeKind) -> Int {
  let mut count = 0
  for change in self.changes {
    if change.kind() == kind {
      count = count + 1
    }
  }
  count
}

///|
pub fn DiffReport::risky_count(self : DiffReport) -> Int {
  let mut count = 0
  for change in self.changes {
    if change.kind().is_risky() {
      count = count + 1
    }
  }
  count
}

///|
pub fn DiffReport::is_empty(self : DiffReport) -> Bool {
  self.changes.length() == 0
}

///|
pub fn DiffReport::risk_level(self : DiffReport) -> String {
  let risky = self.risky_count()
  if risky >= 3 {
    "high"
  } else if risky > 0 {
    "medium"
  } else if self.change_count() > 0 {
    "low"
  } else {
    "clean"
  }
}

///|
pub fn DiffReport::text_report(self : DiffReport) -> String {
  let mut output = "MoonCIDR diff report\n"
  output = output + "changes: " + self.change_count().to_string() + "\n"
  output = output + "risky_changes: " + self.risky_count().to_string() + "\n"
  output = output + "risk: " + self.risk_level() + "\n"
  if self.changes.length() == 0 {
    output + "\nNo rule changes."
  } else {
    output = output + "\nChanges:\n"
    for change in self.changes {
      output = output + "- " + change.summary() + "\n"
    }
    output
  }
}

///|
pub fn RuleSet::diff_from(self : RuleSet, previous : RuleSet) -> DiffReport {
  let changes : Array[RuleChange] = []
  for before in previous.rules() {
    match find_same_block(self.rules(), before.block()) {
      None =>
        changes.push(
          RuleChange::new(
            RemovedRule,
            before.id(),
            "",
            before.block().to_string(),
            "rule was removed: " + before.summary(),
          ),
        )
      Some(after) =>
        if before.action() != after.action() {
          changes.push(
            RuleChange::new(
              ActionChanged,
              before.id(),
              after.id(),
              before.block().to_string(),
              "action changed from " +
              before.action().label() +
              " to " +
              after.action().label(),
            ),
          )
        } else if before.note() != after.note() {
          changes.push(
            RuleChange::new(
              NoteChanged,
              before.id(),
              after.id(),
              before.block().to_string(),
              "note changed",
            ),
          )
        } else {
          changes.push(
            RuleChange::new(
              UnchangedRule,
              before.id(),
              after.id(),
              before.block().to_string(),
              "rule is unchanged",
            ),
          )
        }
    }
  }
  for after in self.rules() {
    match find_same_block(previous.rules(), after.block()) {
      None =>
        changes.push(
          RuleChange::new(
            AddedRule,
            "",
            after.id(),
            after.block().to_string(),
            "rule was added: " + after.summary(),
          ),
        )
      Some(_) => ()
    }
  }
  { changes, }
}

///|
pub fn diff_rule_sets(current : RuleSet, previous : RuleSet) -> DiffReport {
  current.diff_from(previous)
}

///|
fn find_same_block(rules : Array[Rule], block : CidrBlock) -> Rule? {
  for rule in rules {
    if rule.block().equal_range(block) {
      return Some(rule)
    }
  }
  None
}
