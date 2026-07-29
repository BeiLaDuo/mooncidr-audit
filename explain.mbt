///|
/// Aggregate facts about a rule set.
pub struct CoverageStats {
  total_rules : Int
  allow_rules : Int
  deny_rules : Int
  private_rules : Int
  public_rules : Int
  special_rules : Int
  widest_prefix : Int
  narrowest_prefix : Int
} derive(Eq, Debug)

///|
pub fn CoverageStats::total_rules(self : CoverageStats) -> Int {
  self.total_rules
}

///|
pub fn CoverageStats::allow_rules(self : CoverageStats) -> Int {
  self.allow_rules
}

///|
pub fn CoverageStats::deny_rules(self : CoverageStats) -> Int {
  self.deny_rules
}

///|
pub fn CoverageStats::private_rules(self : CoverageStats) -> Int {
  self.private_rules
}

///|
pub fn CoverageStats::public_rules(self : CoverageStats) -> Int {
  self.public_rules
}

///|
pub fn CoverageStats::special_rules(self : CoverageStats) -> Int {
  self.special_rules
}

///|
pub fn CoverageStats::widest_prefix(self : CoverageStats) -> Int {
  self.widest_prefix
}

///|
pub fn CoverageStats::narrowest_prefix(self : CoverageStats) -> Int {
  self.narrowest_prefix
}

///|
pub fn CoverageStats::summary(self : CoverageStats) -> String {
  "rules=" +
  self.total_rules.to_string() +
  ", allow=" +
  self.allow_rules.to_string() +
  ", deny=" +
  self.deny_rules.to_string() +
  ", private=" +
  self.private_rules.to_string() +
  ", public=" +
  self.public_rules.to_string() +
  ", special=" +
  self.special_rules.to_string() +
  ", widest=/" +
  self.widest_prefix.to_string() +
  ", narrowest=/" +
  self.narrowest_prefix.to_string()
}

///|
pub fn RuleSet::coverage_stats(self : RuleSet) -> CoverageStats {
  let mut allow_rules = 0
  let mut deny_rules = 0
  let mut private_rules = 0
  let mut public_rules = 0
  let mut special_rules = 0
  let mut widest_prefix = 32
  let mut narrowest_prefix = 0
  if self.rules.length() == 0 {
    widest_prefix = 0
    narrowest_prefix = 0
  }
  for rule in self.rules {
    if rule.action() == Allow {
      allow_rules = allow_rules + 1
    } else {
      deny_rules = deny_rules + 1
    }
    let scope = rule.block().network().scope_label()
    if scope == "private" {
      private_rules = private_rules + 1
    } else if scope == "public" {
      public_rules = public_rules + 1
    } else {
      special_rules = special_rules + 1
    }
    if rule.block().prefix() < widest_prefix {
      widest_prefix = rule.block().prefix()
    }
    if rule.block().prefix() > narrowest_prefix {
      narrowest_prefix = rule.block().prefix()
    }
  }
  {
    total_rules: self.rules.length(),
    allow_rules,
    deny_rules,
    private_rules,
    public_rules,
    special_rules,
    widest_prefix,
    narrowest_prefix,
  }
}

///|
pub fn RuleSet::matching_rules(self : RuleSet, ip : IPv4) -> Array[Rule] {
  let matched : Array[Rule] = []
  for rule in self.rules {
    if rule.matches(ip) {
      matched.push(rule)
    }
  }
  matched
}

///|
pub fn RuleSet::explain_ip(self : RuleSet, ip : IPv4) -> String {
  let matched = self.matching_rules(ip)
  let mut output = "IP " + ip.to_dotted() + " scope=" + ip.scope_label() + "\n"
  if matched.length() == 0 {
    output = output + "decision: no matching rule\n"
  } else {
    output = output + "decision: " + self.decide(ip).summary() + "\n"
    output = output + "matching rules:\n"
    for rule in matched {
      output = output + "- " + rule.summary() + "\n"
    }
  }
  output
}

///|
pub fn RuleSet::explain_many(self : RuleSet, probes : Array[String]) -> String {
  let mut output = ""
  for probe in probes {
    match IPv4::parse(probe) {
      Ok(ip) => output = output + self.explain_ip(ip) + "\n"
      Err(err) => output = output + "invalid probe " + probe + ": " + err + "\n"
    }
  }
  output
}

///|
pub fn RuleSet::first_rule_for_block(
  self : RuleSet,
  block : CidrBlock,
) -> String {
  for rule in self.rules {
    if rule.block().overlaps(block) {
      return rule.id() +
        " " +
        rule.action().label() +
        " " +
        rule.block().to_string()
    }
  }
  "no overlapping rule"
}

///|
pub fn RuleSet::inventory_report(self : RuleSet) -> String {
  let stats = self.coverage_stats()
  let mut output = "MoonCIDR inventory\n"
  output = output + stats.summary() + "\n"
  output = output + "rules:\n"
  for rule in self.rules {
    output = output + "- " + rule.summary() + "\n"
  }
  output
}
