///|
/// Action taken when a CIDR rule matches.
pub(all) enum RuleAction {
  Allow
  Deny
} derive(Eq, Debug)

///|
pub fn RuleAction::label(self : RuleAction) -> String {
  match self {
    Allow => "allow"
    Deny => "deny"
  }
}

///|
pub fn RuleAction::parse(input : String) -> Result[RuleAction, String] {
  let text = lower_ascii(trim_ascii(input))
  match text {
    "allow" | "permit" | "accept" => Ok(Allow)
    "deny" | "block" | "reject" => Ok(Deny)
    _ => Err("unknown rule action: " + input)
  }
}

///|
/// A single ordered firewall, proxy, or gateway rule.
pub struct Rule {
  id : String
  action : RuleAction
  block : CidrBlock
  source_block : String
  note : String
} derive(Eq, Debug)

///|
pub fn Rule::new(
  id : String,
  action : RuleAction,
  block : CidrBlock,
  source_block? : String = block.to_string(),
  note? : String = "",
) -> Rule {
  { id, action, block, source_block, note }
}

///|
pub fn Rule::id(self : Rule) -> String {
  self.id
}

///|
pub fn Rule::action(self : Rule) -> RuleAction {
  self.action
}

///|
pub fn Rule::block(self : Rule) -> CidrBlock {
  self.block
}

///|
pub fn Rule::source_block(self : Rule) -> String {
  self.source_block
}

///|
pub fn Rule::is_canonical(self : Rule) -> Bool {
  self.source_block == self.block.to_string()
}

///|
pub fn Rule::note(self : Rule) -> String {
  self.note
}

///|
pub fn Rule::matches(self : Rule, ip : IPv4) -> Bool {
  self.block.contains_ip(ip)
}

///|
pub fn Rule::same_decision(self : Rule, other : Rule) -> Bool {
  self.action == other.action
}

///|
pub fn Rule::summary(self : Rule) -> String {
  if self.note == "" {
    self.id + ": " + self.action.label() + " " + self.block.to_string()
  } else {
    self.id +
    ": " +
    self.action.label() +
    " " +
    self.block.to_string() +
    " # " +
    self.note
  }
}

///|
pub fn Rule::parse(id : String, line : String) -> Result[Rule, String] {
  let clean = strip_comment(line)
  let tokens = split_ascii_words(clean)
  guard tokens.length() >= 2 else {
    return Err("rule line must contain an action and a CIDR block: " + line)
  }
  match RuleAction::parse(tokens[0]) {
    Err(err) => Err(err)
    Ok(action) =>
      match CidrBlock::parse(tokens[1]) {
        Err(err) => Err(err)
        Ok(block) => {
          let mut note = ""
          if tokens.length() > 2 {
            note = join_words(tokens[2:])
          }
          Ok(Rule::new(id, action, block, source_block=tokens[1], note~))
        }
      }
  }
}

///|
fn strip_comment(line : String) -> String {
  let chars = line.to_array()
  let mut end = chars.length()
  for index = 0; index < chars.length(); index = index + 1 {
    if chars[index] == '#' {
      end = index
      break
    }
  }
  trim_ascii(String::from_array(chars[0:end]))
}

///|
fn split_ascii_words(input : String) -> Array[String] {
  let chars = input.to_array()
  let words : Array[String] = []
  let mut start = -1
  for index = 0; index < chars.length(); index = index + 1 {
    if is_ascii_space(chars[index]) {
      if start != -1 {
        words.push(String::from_array(chars[start:index]))
        start = -1
      }
    } else if start == -1 {
      start = index
    }
  }
  if start != -1 {
    words.push(String::from_array(chars[start:]))
  }
  words
}

///|
fn join_words(words : ArrayView[String]) -> String {
  let mut output = ""
  for index = 0; index < words.length(); index = index + 1 {
    if index > 0 {
      output = output + " "
    }
    output = output + words[index]
  }
  output
}

///|
fn lower_ascii(input : String) -> String {
  let chars = input.to_array()
  let output : Array[Char] = []
  for char in chars {
    let code = char.to_int()
    if code >= 'A' && code <= 'Z' {
      output.push((code + 32).unsafe_to_char())
    } else {
      output.push(char)
    }
  }
  String::from_array(output)
}
