///|
/// Result of normalizing, deduplicating, and aggregating CIDR blocks.
pub struct AggregationReport {
  input_count : Int
  valid_count : Int
  duplicate_count : Int
  contained_count : Int
  merged_pair_count : Int
  blocks : Array[CidrBlock]
  errors : Array[String]
} derive(Debug)

///|
pub fn AggregationReport::input_count(self : AggregationReport) -> Int {
  self.input_count
}

///|
pub fn AggregationReport::valid_count(self : AggregationReport) -> Int {
  self.valid_count
}

///|
pub fn AggregationReport::duplicate_count(self : AggregationReport) -> Int {
  self.duplicate_count
}

///|
pub fn AggregationReport::contained_count(self : AggregationReport) -> Int {
  self.contained_count
}

///|
pub fn AggregationReport::merged_pair_count(self : AggregationReport) -> Int {
  self.merged_pair_count
}

///|
pub fn AggregationReport::blocks(self : AggregationReport) -> Array[CidrBlock] {
  self.blocks
}

///|
pub fn AggregationReport::errors(self : AggregationReport) -> Array[String] {
  self.errors
}

///|
pub fn AggregationReport::output_count(self : AggregationReport) -> Int {
  self.blocks.length()
}

///|
pub fn AggregationReport::changed(self : AggregationReport) -> Bool {
  self.duplicate_count > 0 ||
  self.contained_count > 0 ||
  self.merged_pair_count > 0
}

///|
pub fn AggregationReport::reduction_count(self : AggregationReport) -> Int {
  self.valid_count - self.output_count()
}

///|
pub fn AggregationReport::summary(self : AggregationReport) -> String {
  "input=" +
  self.input_count.to_string() +
  ", valid=" +
  self.valid_count.to_string() +
  ", output=" +
  self.output_count().to_string() +
  ", duplicates=" +
  self.duplicate_count.to_string() +
  ", contained=" +
  self.contained_count.to_string() +
  ", merged_pairs=" +
  self.merged_pair_count.to_string() +
  ", errors=" +
  self.errors.length().to_string()
}

///|
pub fn AggregationReport::text_report(self : AggregationReport) -> String {
  let mut output = "MoonCIDR aggregation report\n"
  output = output + self.summary() + "\n"
  if self.blocks.length() > 0 {
    output = output + "\nAggregated blocks:\n"
    for block in self.blocks {
      output = output + "- " + block.to_string() + "\n"
    }
  }
  if self.errors.length() > 0 {
    output = output + "\nInvalid inputs:\n"
    for error in self.errors {
      output = output + "- " + error + "\n"
    }
  }
  output
}

///|
/// Parses and aggregates a list of CIDR strings.
///
/// Invalid entries are preserved in `errors` rather than aborting the whole
/// operation, making the API suitable for configuration linting.
pub fn aggregate_cidr_strings(inputs : Array[String]) -> AggregationReport {
  let blocks : Array[CidrBlock] = []
  let errors : Array[String] = []
  for index = 0; index < inputs.length(); index = index + 1 {
    match CidrBlock::parse(inputs[index]) {
      Ok(block) => blocks.push(block)
      Err(error) =>
        errors.push(
          "item " +
          (index + 1).to_string() +
          " (" +
          inputs[index] +
          "): " +
          error,
        )
    }
  }
  aggregate_blocks_with_metadata(inputs.length(), blocks, errors)
}

///|
/// Aggregates already parsed CIDR blocks.
pub fn aggregate_blocks(blocks : Array[CidrBlock]) -> AggregationReport {
  aggregate_blocks_with_metadata(blocks.length(), blocks, [])
}

///|
fn aggregate_blocks_with_metadata(
  input_count : Int,
  input_blocks : Array[CidrBlock],
  errors : Array[String],
) -> AggregationReport {
  let sorted = copy_blocks(input_blocks)
  sort_blocks(sorted)
  let unique : Array[CidrBlock] = []
  let mut duplicate_count = 0
  for block in sorted {
    if contains_equal_block(unique, block) {
      duplicate_count = duplicate_count + 1
    } else {
      unique.push(block)
    }
  }
  let reduced : Array[CidrBlock] = []
  let mut contained_count = 0
  for candidate in unique {
    if is_contained_by_any(reduced, candidate) {
      contained_count = contained_count + 1
    } else {
      remove_blocks_contained_by(reduced, candidate)
      reduced.push(candidate)
      sort_blocks(reduced)
    }
  }
  let (aggregated, merged_pair_count) = merge_sibling_blocks(reduced)
  sort_blocks(aggregated)
  {
    input_count,
    valid_count: input_blocks.length(),
    duplicate_count,
    contained_count,
    merged_pair_count,
    blocks: aggregated,
    errors,
  }
}

///|
fn merge_sibling_blocks(input : Array[CidrBlock]) -> (Array[CidrBlock], Int) {
  let mut current = copy_blocks(input)
  let mut merged_count = 0
  let mut keep_merging = true
  while keep_merging {
    keep_merging = false
    let mut left_index = -1
    let mut right_index = -1
    let mut parent = CidrBlock::new_unchecked(IPv4::new(0U), 0)
    for left = 0; left < current.length(); left = left + 1 {
      if left_index != -1 {
        break
      }
      for right = left + 1; right < current.length(); right = right + 1 {
        match sibling_parent(current[left], current[right]) {
          Some(value) => {
            left_index = left
            right_index = right
            parent = value
            break
          }
          None => ()
        }
      }
    }
    if left_index != -1 {
      let next : Array[CidrBlock] = []
      for index = 0; index < current.length(); index = index + 1 {
        if index != left_index && index != right_index {
          next.push(current[index])
        }
      }
      next.push(parent)
      current = remove_contained_blocks(next)
      merged_count = merged_count + 1
      keep_merging = true
    }
  }
  (current, merged_count)
}

///|
fn sibling_parent(left : CidrBlock, right : CidrBlock) -> CidrBlock? {
  if left.prefix() == 0 || left.prefix() != right.prefix() {
    return None
  }
  let parent_prefix = left.prefix() - 1
  let left_parent = CidrBlock::new_unchecked(left.network(), parent_prefix)
  let right_parent = CidrBlock::new_unchecked(right.network(), parent_prefix)
  if left_parent == right_parent && left != right {
    Some(left_parent)
  } else {
    None
  }
}

///|
fn remove_contained_blocks(input : Array[CidrBlock]) -> Array[CidrBlock] {
  let sorted = copy_blocks(input)
  sort_blocks(sorted)
  let output : Array[CidrBlock] = []
  for candidate in sorted {
    if !is_contained_by_any(output, candidate) {
      output.push(candidate)
    }
  }
  output
}

///|
fn is_contained_by_any(
  blocks : Array[CidrBlock],
  candidate : CidrBlock,
) -> Bool {
  for existing in blocks {
    if existing.contains_block(candidate) {
      return true
    }
  }
  false
}

///|
fn remove_blocks_contained_by(
  blocks : Array[CidrBlock],
  parent : CidrBlock,
) -> Unit {
  let kept : Array[CidrBlock] = []
  for existing in blocks {
    if !parent.contains_block(existing) {
      kept.push(existing)
    }
  }
  blocks.clear()
  for existing in kept {
    blocks.push(existing)
  }
}

///|
fn contains_equal_block(
  blocks : Array[CidrBlock],
  candidate : CidrBlock,
) -> Bool {
  for block in blocks {
    if block == candidate {
      return true
    }
  }
  false
}

///|
fn copy_blocks(input : Array[CidrBlock]) -> Array[CidrBlock] {
  let output : Array[CidrBlock] = []
  for block in input {
    output.push(block)
  }
  output
}

///|
fn sort_blocks(blocks : Array[CidrBlock]) -> Unit {
  for index = 0; index < blocks.length(); index = index + 1 {
    let mut smallest = index
    for candidate = index + 1
        candidate < blocks.length()
        candidate = candidate + 1 {
      if block_before(blocks[candidate], blocks[smallest]) {
        smallest = candidate
      }
    }
    if smallest != index {
      let saved = blocks[index]
      blocks[index] = blocks[smallest]
      blocks[smallest] = saved
    }
  }
}

///|
fn block_before(left : CidrBlock, right : CidrBlock) -> Bool {
  if left.network().value() < right.network().value() {
    true
  } else {
    left.network().value() == right.network().value() &&
    left.prefix() < right.prefix()
  }
}
