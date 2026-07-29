///|
/// Input syntax understood by the configuration import layer.
pub(all) enum ImportFormat {
  PlainRules
  NginxAccess
  CsvRules
} derive(Eq, Debug)

///|
pub fn ImportFormat::label(self : ImportFormat) -> String {
  match self {
    PlainRules => "plain"
    NginxAccess => "nginx_access"
    CsvRules => "csv"
  }
}

///|
pub(all) enum ImportIssueLevel {
  ImportWarning
  ImportError
} derive(Eq, Debug)

///|
pub fn ImportIssueLevel::label(self : ImportIssueLevel) -> String {
  match self {
    ImportWarning => "warning"
    ImportError => "error"
  }
}

///|
pub struct ImportIssue {
  line : Int
  level : ImportIssueLevel
  code : String
  message : String
  input : String
} derive(Eq, Debug)

///|
pub fn ImportIssue::new(
  line : Int,
  level : ImportIssueLevel,
  code : String,
  message : String,
  input : String,
) -> ImportIssue {
  { line, level, code, message, input }
}

///|
pub fn ImportIssue::line(self : ImportIssue) -> Int {
  self.line
}

///|
pub fn ImportIssue::level(self : ImportIssue) -> ImportIssueLevel {
  self.level
}

///|
pub fn ImportIssue::code(self : ImportIssue) -> String {
  self.code
}

///|
pub fn ImportIssue::message(self : ImportIssue) -> String {
  self.message
}

///|
pub fn ImportIssue::input(self : ImportIssue) -> String {
  self.input
}

///|
pub fn ImportIssue::summary(self : ImportIssue) -> String {
  "[" +
  self.level.label() +
  "] line " +
  self.line.to_string() +
  " " +
  self.code +
  ": " +
  self.message
}

///|
pub struct ImportReport {
  format : ImportFormat
  source_count : Int
  rules : Array[Rule]
  issues : Array[ImportIssue]
} derive(Debug)

///|
pub fn ImportReport::format(self : ImportReport) -> ImportFormat {
  self.format
}

///|
pub fn ImportReport::source_count(self : ImportReport) -> Int {
  self.source_count
}

///|
pub fn ImportReport::rules(self : ImportReport) -> Array[Rule] {
  self.rules
}

///|
pub fn ImportReport::issues(self : ImportReport) -> Array[ImportIssue] {
  self.issues
}

///|
pub fn ImportReport::accepted_count(self : ImportReport) -> Int {
  self.rules.length()
}

///|
pub fn ImportReport::error_count(self : ImportReport) -> Int {
  let mut count = 0
  for issue in self.issues {
    if issue.level() == ImportError {
      count = count + 1
    }
  }
  count
}

///|
pub fn ImportReport::warning_count(self : ImportReport) -> Int {
  let mut count = 0
  for issue in self.issues {
    if issue.level() == ImportWarning {
      count = count + 1
    }
  }
  count
}

///|
pub fn ImportReport::is_clean(self : ImportReport) -> Bool {
  self.issues.length() == 0
}

///|
pub fn ImportReport::can_audit(self : ImportReport) -> Bool {
  self.rules.length() > 0
}

///|
pub fn ImportReport::to_ruleset(self : ImportReport) -> RuleSet {
  RuleSet::new(self.rules)
}

///|
pub fn ImportReport::summary(self : ImportReport) -> String {
  "format=" +
  self.format.label() +
  ", source_lines=" +
  self.source_count.to_string() +
  ", accepted=" +
  self.accepted_count().to_string() +
  ", warnings=" +
  self.warning_count().to_string() +
  ", errors=" +
  self.error_count().to_string()
}

///|
pub fn ImportReport::text_report(self : ImportReport) -> String {
  let mut output = "MoonCIDR import report\n"
  output = output + self.summary() + "\n"
  if self.rules.length() > 0 {
    output = output + "\nImported rules:\n"
    for rule in self.rules {
      output = output + "- " + rule.summary() + "\n"
    }
  }
  if self.issues.length() > 0 {
    output = output + "\nImport issues:\n"
    for issue in self.issues {
      output = output + "- " + issue.summary() + "\n"
    }
  }
  output
}

///|
/// Imports the native compact syntax: `allow 10.0.0.0/8 note`.
pub fn import_plain_rules(lines : Array[String]) -> ImportReport {
  let rules : Array[Rule] = []
  let issues : Array[ImportIssue] = []
  for index = 0; index < lines.length(); index = index + 1 {
    let text = trim_ascii(lines[index])
    if text == "" || starts_with(text, "#") {
      continue
    }
    let id = "R" + (rules.length() + 1).to_string()
    match Rule::parse(id, text) {
      Ok(rule) => rules.push(rule)
      Err(error) =>
        issues.push(
          ImportIssue::new(
            index + 1,
            ImportError,
            "invalid_rule",
            error,
            lines[index],
          ),
        )
    }
  }
  { format: PlainRules, source_count: lines.length(), rules, issues }
}

///|
/// Imports Nginx access directives such as `allow 10.0.0.0/8;`.
///
/// `deny all;` and `allow all;` are converted to `0.0.0.0/0`. Other Nginx
/// directives are rejected so accidental input from an unrelated section is
/// visible to the caller.
pub fn import_nginx_access(lines : Array[String]) -> ImportReport {
  let rules : Array[Rule] = []
  let issues : Array[ImportIssue] = []
  for index = 0; index < lines.length(); index = index + 1 {
    let original = lines[index]
    let without_comment = strip_comment(original)
    let text = trim_ascii(without_comment)
    if text == "" {
      continue
    }
    if !ends_with(text, ";") {
      issues.push(
        ImportIssue::new(
          index + 1,
          ImportError,
          "missing_semicolon",
          "Nginx access directive must end with a semicolon",
          original,
        ),
      )
      continue
    }
    let directive = trim_ascii(remove_last_char(text))
    let words = split_ascii_words(directive)
    if words.length() != 2 {
      issues.push(
        ImportIssue::new(
          index + 1,
          ImportError,
          "invalid_directive",
          "expected exactly an allow or deny directive and one address",
          original,
        ),
      )
      continue
    }
    let action_text = lower_ascii(words[0])
    if action_text != "allow" && action_text != "deny" {
      issues.push(
        ImportIssue::new(
          index + 1,
          ImportError,
          "unsupported_directive",
          "only Nginx allow and deny directives are supported",
          original,
        ),
      )
      continue
    }
    let block_text = if lower_ascii(words[1]) == "all" {
      "0.0.0.0/0"
    } else {
      words[1]
    }
    let native_line = action_text + " " + block_text + " imported from nginx"
    match Rule::parse("R" + (rules.length() + 1).to_string(), native_line) {
      Ok(rule) => rules.push(rule)
      Err(error) =>
        issues.push(
          ImportIssue::new(
            index + 1,
            ImportError,
            "invalid_address",
            error,
            original,
          ),
        )
    }
  }
  { format: NginxAccess, source_count: lines.length(), rules, issues }
}

///|
/// Imports rows in `action,cidr,note` form.
///
/// A header row is optional. Quoted fields, embedded commas, and doubled quote
/// escapes are supported. Extra columns are folded into the note and reported
/// as a warning so information is not silently discarded.
pub fn import_csv_rules(lines : Array[String]) -> ImportReport {
  let rules : Array[Rule] = []
  let issues : Array[ImportIssue] = []
  let mut header_seen = false
  for index = 0; index < lines.length(); index = index + 1 {
    let original = lines[index]
    if trim_ascii(original) == "" {
      continue
    }
    match parse_csv_row(original) {
      Err(error) =>
        issues.push(
          ImportIssue::new(
            index + 1,
            ImportError,
            "invalid_csv",
            error,
            original,
          ),
        )
      Ok(fields) => {
        if !header_seen && is_csv_header(fields) {
          header_seen = true
          continue
        }
        guard fields.length() >= 2 else {
          issues.push(
            ImportIssue::new(
              index + 1,
              ImportError,
              "missing_column",
              "CSV row must contain at least action and CIDR columns",
              original,
            ),
          )
          continue
        }
        let note = csv_note(fields)
        if fields.length() > 3 {
          issues.push(
            ImportIssue::new(
              index + 1,
              ImportWarning,
              "extra_columns",
              "extra CSV columns were appended to the note",
              original,
            ),
          )
        }
        let note_suffix = if note == "" { "" } else { " " + note }
        let native_line = trim_ascii(fields[0]) +
          " " +
          trim_ascii(fields[1]) +
          note_suffix
        match Rule::parse("R" + (rules.length() + 1).to_string(), native_line) {
          Ok(rule) => rules.push(rule)
          Err(error) =>
            issues.push(
              ImportIssue::new(
                index + 1,
                ImportError,
                "invalid_rule",
                error,
                original,
              ),
            )
        }
      }
    }
  }
  { format: CsvRules, source_count: lines.length(), rules, issues }
}

///|
fn parse_csv_row(input : String) -> Result[Array[String], String] {
  let fields : Array[String] = []
  let current : Array[Char] = []
  let chars = input.to_array()
  let mut quoted = false
  let mut index = 0
  while index < chars.length() {
    let char = chars[index]
    if char == '"' {
      if quoted && index + 1 < chars.length() && chars[index + 1] == '"' {
        current.push('"')
        index = index + 2
        continue
      }
      quoted = !quoted
    } else if char == ',' && !quoted {
      fields.push(trim_ascii(String::from_array(current)))
      current.clear()
    } else {
      current.push(char)
    }
    index = index + 1
  }
  guard !quoted else { return Err("CSV row contains an unclosed quote") }
  fields.push(trim_ascii(String::from_array(current)))
  Ok(fields)
}

///|
fn is_csv_header(fields : Array[String]) -> Bool {
  fields.length() >= 2 &&
  lower_ascii(trim_ascii(fields[0])) == "action" &&
  (
    lower_ascii(trim_ascii(fields[1])) == "cidr" ||
    lower_ascii(trim_ascii(fields[1])) == "network"
  )
}

///|
fn csv_note(fields : Array[String]) -> String {
  if fields.length() < 3 {
    return ""
  }
  let mut note = trim_ascii(fields[2])
  for index = 3; index < fields.length(); index = index + 1 {
    if note != "" {
      note = note + ", "
    }
    note = note + trim_ascii(fields[index])
  }
  note
}

///|
fn ends_with(input : String, suffix : String) -> Bool {
  let chars = input.to_array()
  let suffix_chars = suffix.to_array()
  if suffix_chars.length() > chars.length() {
    return false
  }
  let offset = chars.length() - suffix_chars.length()
  for index = 0; index < suffix_chars.length(); index = index + 1 {
    if chars[offset + index] != suffix_chars[index] {
      return false
    }
  }
  true
}

///|
fn remove_last_char(input : String) -> String {
  let chars = input.to_array()
  if chars.length() == 0 {
    ""
  } else {
    String::from_array(chars[0:chars.length() - 1])
  }
}
