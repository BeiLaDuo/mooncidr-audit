///|
test "diff detects added rule" {
  let previous = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let current = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 203.0.113.0/24"])
  let diff = current.diff_from(previous)
  inspect(diff.count_kind(AddedRule), content="1")
  inspect(diff.risky_count(), content="1")
}

///|
test "diff detects removed rule" {
  let previous = RuleSet::from_lines(["allow 10.0.0.0/8", "deny 203.0.113.0/24"])
  let current = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let diff = current.diff_from(previous)
  inspect(diff.count_kind(RemovedRule), content="1")
  inspect(diff.risk_level(), content="medium")
}

///|
test "diff detects action change" {
  let previous = RuleSet::from_lines(["allow 203.0.113.0/24"])
  let current = RuleSet::from_lines(["deny 203.0.113.0/24"])
  let diff = diff_rule_sets(current, previous)
  inspect(diff.count_kind(ActionChanged), content="1")
  inspect(
    diff.changes()[0].message(),
    content="action changed from allow to deny",
  )
}

///|
test "diff detects note change" {
  let previous = RuleSet::from_lines(["allow 10.0.0.0/8 old"])
  let current = RuleSet::from_lines(["allow 10.0.0.0/8 new"])
  let diff = current.diff_from(previous)
  inspect(diff.count_kind(NoteChanged), content="1")
  inspect(diff.risky_count(), content="0")
}

///|
test "diff records unchanged rule" {
  let previous = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let current = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let diff = current.diff_from(previous)
  inspect(diff.count_kind(UnchangedRule), content="1")
  inspect(diff.risk_level(), content="low")
}

///|
test "diff empty current reports removal" {
  let previous = RuleSet::from_lines(["deny 0.0.0.0/0"])
  let current = RuleSet::new([])
  let diff = current.diff_from(previous)
  inspect(diff.change_count(), content="1")
  inspect(diff.changes()[0].block(), content="0.0.0.0/0")
}

///|
test "diff text report includes summary" {
  let previous = RuleSet::from_lines(["allow 10.0.0.0/8"])
  let current = RuleSet::from_lines(["deny 10.0.0.0/8"])
  let text = current.diff_from(previous).text_report()
  inspect(text.contains("MoonCIDR diff report"), content="true")
  inspect(text.contains("action_changed"), content="true")
}

///|
test "RuleChange kind labels are stable" {
  inspect(AddedRule.label(), content="added_rule")
  inspect(RemovedRule.label(), content="removed_rule")
  inspect(ActionChanged.label(), content="action_changed")
  inspect(NoteChanged.label(), content="note_changed")
  inspect(UnchangedRule.label(), content="unchanged_rule")
}
