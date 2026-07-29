///|
/// A closed IPv4 address interval.
///
/// `source_count` records how many original intervals contributed to this
/// range after union operations. It is useful when explaining why a range was
/// produced, but does not change equality or containment semantics.
pub struct AddressRange {
  first : IPv4
  last : IPv4
  source_count : Int
} derive(Eq, Debug)

///|
pub fn AddressRange::new(
  first : IPv4,
  last : IPv4,
  source_count? : Int = 1,
) -> Result[AddressRange, String] {
  guard first.value() <= last.value() else {
    return Err(
      "address range starts after it ends: " +
      first.to_dotted() +
      "-" +
      last.to_dotted(),
    )
  }
  guard source_count > 0 else {
    return Err("address range source count must be positive")
  }
  Ok({ first, last, source_count })
}

///|
pub fn AddressRange::from_block(block : CidrBlock) -> AddressRange {
  { first: block.network(), last: block.broadcast(), source_count: 1 }
}

///|
pub fn AddressRange::first(self : AddressRange) -> IPv4 {
  self.first
}

///|
pub fn AddressRange::last(self : AddressRange) -> IPv4 {
  self.last
}

///|
pub fn AddressRange::source_count(self : AddressRange) -> Int {
  self.source_count
}

///|
pub fn AddressRange::contains_ip(self : AddressRange, ip : IPv4) -> Bool {
  ip.value() >= self.first.value() && ip.value() <= self.last.value()
}

///|
pub fn AddressRange::contains_range(
  self : AddressRange,
  other : AddressRange,
) -> Bool {
  self.contains_ip(other.first()) && self.contains_ip(other.last())
}

///|
pub fn AddressRange::overlaps(
  self : AddressRange,
  other : AddressRange,
) -> Bool {
  self.first.value() <= other.last.value() &&
  other.first.value() <= self.last.value()
}

///|
pub fn AddressRange::touches(self : AddressRange, other : AddressRange) -> Bool {
  if self.overlaps(other) {
    true
  } else if self.last.value() != 0xffffffffU &&
    self.last.value() + 1U == other.first.value() {
    true
  } else {
    other.last.value() != 0xffffffffU &&
    other.last.value() + 1U == self.first.value()
  }
}

///|
pub fn AddressRange::merge(
  self : AddressRange,
  other : AddressRange,
) -> Result[AddressRange, String] {
  guard self.touches(other) else {
    return Err(
      "address ranges are disjoint: " +
      self.to_string() +
      " and " +
      other.to_string(),
    )
  }
  let first = if self.first.value() <= other.first.value() {
    self.first
  } else {
    other.first
  }
  let last = if self.last.value() >= other.last.value() {
    self.last
  } else {
    other.last
  }
  Ok({ first, last, source_count: self.source_count + other.source_count })
}

///|
pub fn AddressRange::address_count_label(self : AddressRange) -> String {
  if self.first.value() == 0U && self.last.value() == 0xffffffffU {
    "4294967296"
  } else {
    (self.last.value() - self.first.value() + 1U).to_string()
  }
}

///|
pub fn AddressRange::to_string(self : AddressRange) -> String {
  if self.first == self.last {
    self.first.to_dotted()
  } else {
    self.first.to_dotted() + "-" + self.last.to_dotted()
  }
}

///|
pub fn AddressRange::summary(self : AddressRange) -> String {
  self.to_string() +
  " addresses=" +
  self.address_count_label() +
  " sources=" +
  self.source_count.to_string()
}

///|
/// Converts CIDR blocks into a sorted, non-overlapping union of address ranges.
pub fn ranges_from_blocks(blocks : Array[CidrBlock]) -> Array[AddressRange] {
  let ranges : Array[AddressRange] = []
  for block in blocks {
    ranges.push(AddressRange::from_block(block))
  }
  merge_address_ranges(ranges)
}

///|
/// Sorts and merges overlapping or adjacent address ranges.
pub fn merge_address_ranges(input : Array[AddressRange]) -> Array[AddressRange] {
  let sorted = copy_ranges(input)
  sort_ranges(sorted)
  let output : Array[AddressRange] = []
  for candidate in sorted {
    if output.length() == 0 {
      output.push(candidate)
    } else {
      let last_index = output.length() - 1
      let current = output[last_index]
      if current.touches(candidate) {
        match current.merge(candidate) {
          Ok(merged) => output[last_index] = merged
          Err(_) => output.push(candidate)
        }
      } else {
        output.push(candidate)
      }
    }
  }
  output
}

///|
/// Returns the union of all rule blocks with the requested action.
///
/// This is a structural view. Ordered first-match behavior is intentionally
/// handled separately by `RuleSet::decide`.
pub fn RuleSet::coverage_ranges(
  self : RuleSet,
  action : RuleAction,
) -> Array[AddressRange] {
  let blocks : Array[CidrBlock] = []
  for rule in self.rules() {
    if rule.action() == action {
      blocks.push(rule.block())
    }
  }
  ranges_from_blocks(blocks)
}

///|
/// Clips address ranges to a target CIDR and returns a merged union.
pub fn clip_ranges_to_block(
  target : CidrBlock,
  coverage : Array[AddressRange],
) -> Array[AddressRange] {
  let clipped : Array[AddressRange] = []
  let target_range = AddressRange::from_block(target)
  for item in merge_address_ranges(coverage) {
    if item.overlaps(target_range) {
      let first = if item.first().value() < target_range.first().value() {
        target_range.first()
      } else {
        item.first()
      }
      let last = if item.last().value() > target_range.last().value() {
        target_range.last()
      } else {
        item.last()
      }
      match AddressRange::new(first, last, source_count=item.source_count()) {
        Ok(value) => clipped.push(value)
        Err(_) => ()
      }
    }
  }
  merge_address_ranges(clipped)
}

///|
/// Finds holes inside `target` that are not covered by any supplied range.
pub fn uncovered_ranges(
  target : CidrBlock,
  coverage : Array[AddressRange],
) -> Array[AddressRange] {
  let clipped = clip_ranges_to_block(target, coverage)
  let target_range = AddressRange::from_block(target)
  let holes : Array[AddressRange] = []
  let mut cursor = target_range.first().value()
  let mut finished = false
  for item in clipped {
    if !finished && cursor < item.first().value() {
      match
        AddressRange::new(
          IPv4::new(cursor),
          IPv4::new(item.first().value() - 1U),
        ) {
        Ok(hole) => holes.push(hole)
        Err(_) => ()
      }
    }
    if !finished && item.last().value() == 0xffffffffU {
      finished = true
    } else if !finished && item.last().value() >= cursor {
      cursor = item.last().value() + 1U
    }
  }
  if !finished && cursor <= target_range.last().value() {
    match AddressRange::new(IPv4::new(cursor), target_range.last()) {
      Ok(hole) => holes.push(hole)
      Err(_) => ()
    }
  }
  holes
}

///|
pub fn RuleSet::coverage_report(
  self : RuleSet,
  action : RuleAction,
  target : CidrBlock,
) -> String {
  let all_coverage = self.coverage_ranges(action)
  let coverage = clip_ranges_to_block(target, all_coverage)
  let holes = uncovered_ranges(target, all_coverage)
  let mut output = "MoonCIDR coverage report\n"
  output = output + "action: " + action.label() + "\n"
  output = output + "target: " + target.to_string() + "\n"
  output = output + "merged_ranges: " + coverage.length().to_string() + "\n"
  output = output + "uncovered_ranges: " + holes.length().to_string() + "\n"
  if coverage.length() > 0 {
    output = output + "\nCoverage:\n"
    for item in coverage {
      output = output + "- " + item.summary() + "\n"
    }
  }
  if holes.length() > 0 {
    output = output + "\nHoles inside target:\n"
    for hole in holes {
      output = output + "- " + hole.summary() + "\n"
    }
  }
  output
}

///|
fn copy_ranges(input : Array[AddressRange]) -> Array[AddressRange] {
  let output : Array[AddressRange] = []
  for item in input {
    output.push(item)
  }
  output
}

///|
fn sort_ranges(ranges : Array[AddressRange]) -> Unit {
  for index = 0; index < ranges.length(); index = index + 1 {
    let mut smallest = index
    for candidate = index + 1
        candidate < ranges.length()
        candidate = candidate + 1 {
      if range_before(ranges[candidate], ranges[smallest]) {
        smallest = candidate
      }
    }
    if smallest != index {
      let saved = ranges[index]
      ranges[index] = ranges[smallest]
      ranges[smallest] = saved
    }
  }
}

///|
fn range_before(left : AddressRange, right : AddressRange) -> Bool {
  if left.first().value() < right.first().value() {
    true
  } else {
    left.first().value() == right.first().value() &&
    left.last().value() < right.last().value()
  }
}
