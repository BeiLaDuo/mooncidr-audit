///|
test "aggregate CIDR strings rejects invalid input without aborting" {
  let report = aggregate_cidr_strings([
    "10.0.0.0/24", "not-a-network", "192.168.0.0/16",
  ])
  inspect(report.input_count(), content="3")
  inspect(report.valid_count(), content="2")
  inspect(report.errors().length(), content="1")
  inspect(report.output_count(), content="2")
}

///|
test "aggregate removes duplicate normalized blocks" {
  let report = aggregate_cidr_strings([
    "10.0.0.1/24", "10.0.0.0/24", "10.0.0.99/24",
  ])
  inspect(report.valid_count(), content="3")
  inspect(report.duplicate_count(), content="2")
  inspect(report.blocks().length(), content="1")
  inspect(report.blocks()[0].to_string(), content="10.0.0.0/24")
}

///|
test "aggregate removes blocks contained by parent" {
  let report = aggregate_cidr_strings([
    "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25",
  ])
  inspect(report.contained_count(), content="2")
  inspect(report.output_count(), content="1")
  inspect(report.blocks()[0].to_string(), content="10.1.0.0/16")
}

///|
test "aggregate merges sibling slash 25 networks" {
  let report = aggregate_cidr_strings(["192.0.2.0/25", "192.0.2.128/25"])
  inspect(report.merged_pair_count(), content="1")
  inspect(report.output_count(), content="1")
  inspect(report.blocks()[0].to_string(), content="192.0.2.0/24")
}

///|
test "aggregate recursively merges four sibling networks" {
  let report = aggregate_cidr_strings([
    "198.51.100.0/26", "198.51.100.64/26", "198.51.100.128/26", "198.51.100.192/26",
  ])
  inspect(report.merged_pair_count(), content="3")
  inspect(report.output_count(), content="1")
  inspect(report.blocks()[0].to_string(), content="198.51.100.0/24")
}

///|
test "aggregate does not merge non-sibling blocks" {
  let report = aggregate_cidr_strings(["10.0.0.0/25", "10.0.1.128/25"])
  inspect(report.merged_pair_count(), content="0")
  inspect(report.output_count(), content="2")
}

///|
test "aggregate reports reduction and changed state" {
  let report = aggregate_cidr_strings([
    "10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/25",
  ])
  inspect(report.changed(), content="true")
  inspect(report.reduction_count(), content="2")
  inspect(
    report.summary(),
    content="input=3, valid=3, output=1, duplicates=1, contained=0, " +
      "merged_pairs=1, errors=0",
  )
}

///|
test "aggregate blocks accepts parsed input" {
  let report = aggregate_blocks([
    CidrBlock::parse("203.0.113.0/25").unwrap(),
    CidrBlock::parse("203.0.113.128/25").unwrap(),
  ])
  inspect(report.errors().length(), content="0")
  inspect(report.blocks()[0].to_string(), content="203.0.113.0/24")
}

///|
test "aggregation report renders invalid and valid sections" {
  let report = aggregate_cidr_strings([
    "192.0.2.0/25", "192.0.2.128/25", "broken",
  ])
  inspect(
    report.text_report(),
    content=(
      #|MoonCIDR aggregation report
      #|input=3, valid=2, output=1, duplicates=0, contained=0, merged_pairs=1, errors=1
      #|
      #|Aggregated blocks:
      #|- 192.0.2.0/24
      #|
      #|Invalid inputs:
      #|- item 3 (broken): IPv4 address contains an invalid character: broken
      #|
    ),
  )
}
