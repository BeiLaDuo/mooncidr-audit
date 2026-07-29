///|
test "AddressRange validates order" {
  let high = IPv4::parse("10.0.0.2").unwrap()
  let low = IPv4::parse("10.0.0.1").unwrap()
  match AddressRange::new(high, low) {
    Err(_) => ()
    Ok(_) => @test.fail("expected reversed address range to fail")
  }
}

///|
test "AddressRange reports a single address" {
  let ip = IPv4::parse("192.0.2.9").unwrap()
  let item = AddressRange::new(ip, ip).unwrap()
  inspect(item.to_string(), content="192.0.2.9")
  inspect(item.address_count_label(), content="1")
}

///|
test "AddressRange merges adjacent intervals" {
  let left = AddressRange::new(
    IPv4::parse("10.0.0.0").unwrap(),
    IPv4::parse("10.0.0.127").unwrap(),
  ).unwrap()
  let right = AddressRange::new(
    IPv4::parse("10.0.0.128").unwrap(),
    IPv4::parse("10.0.0.255").unwrap(),
  ).unwrap()
  let merged = left.merge(right).unwrap()
  inspect(merged.to_string(), content="10.0.0.0-10.0.0.255")
  inspect(merged.source_count(), content="2")
  inspect(merged.address_count_label(), content="256")
}

///|
test "AddressRange rejects disjoint merge" {
  let left = AddressRange::from_block(CidrBlock::parse("10.0.0.0/25").unwrap())
  let right = AddressRange::from_block(CidrBlock::parse("10.0.1.0/25").unwrap())
  match left.merge(right) {
    Err(_) => ()
    Ok(_) => @test.fail("expected disjoint address ranges to fail")
  }
}

///|
test "merge address ranges sorts and unions input" {
  let ranges = [
    AddressRange::from_block(CidrBlock::parse("10.0.1.0/24").unwrap()),
    AddressRange::from_block(CidrBlock::parse("10.0.0.128/25").unwrap()),
    AddressRange::from_block(CidrBlock::parse("10.0.0.0/24").unwrap()),
  ]
  let merged = merge_address_ranges(ranges)
  inspect(merged.length(), content="1")
  inspect(merged[0].to_string(), content="10.0.0.0-10.0.1.255")
  inspect(merged[0].source_count(), content="3")
}

///|
test "ranges from blocks keeps separated networks" {
  let blocks = [
    CidrBlock::parse("192.0.2.0/24").unwrap(),
    CidrBlock::parse("198.51.100.0/24").unwrap(),
  ]
  let ranges = ranges_from_blocks(blocks)
  inspect(ranges.length(), content="2")
  inspect(ranges[0].first().to_dotted(), content="192.0.2.0")
}

///|
test "uncovered ranges finds internal holes" {
  let target = CidrBlock::parse("10.0.0.0/24").unwrap()
  let coverage = ranges_from_blocks([
    CidrBlock::parse("10.0.0.0/26").unwrap(),
    CidrBlock::parse("10.0.0.128/26").unwrap(),
  ])
  let holes = uncovered_ranges(target, coverage)
  inspect(holes.length(), content="2")
  inspect(holes[0].to_string(), content="10.0.0.64-10.0.0.127")
  inspect(holes[1].to_string(), content="10.0.0.192-10.0.0.255")
}

///|
test "uncovered ranges handles total coverage" {
  let target = CidrBlock::parse("0.0.0.0/0").unwrap()
  let coverage = ranges_from_blocks([target])
  inspect(uncovered_ranges(target, coverage).length(), content="0")
}

///|
test "uncovered ranges clips outside coverage" {
  let target = CidrBlock::parse("10.0.0.0/24").unwrap()
  let coverage = ranges_from_blocks([
    CidrBlock::parse("0.0.0.0/8").unwrap(),
    CidrBlock::parse("10.0.0.64/26").unwrap(),
    CidrBlock::parse("192.168.0.0/16").unwrap(),
  ])
  let holes = uncovered_ranges(target, coverage)
  inspect(holes.length(), content="2")
  inspect(holes[0].to_string(), content="10.0.0.0-10.0.0.63")
}

///|
test "clip ranges excludes networks outside target" {
  let target = CidrBlock::parse("10.0.0.0/24").unwrap()
  let coverage = ranges_from_blocks([
    CidrBlock::parse("10.0.0.0/25").unwrap(),
    CidrBlock::parse("192.168.0.0/16").unwrap(),
  ])
  let clipped = clip_ranges_to_block(target, coverage)
  inspect(clipped.length(), content="1")
  inspect(clipped[0].to_string(), content="10.0.0.0-10.0.0.127")
}

///|
test "RuleSet coverage ranges filters by action" {
  let rules = parse_rules([
    "allow 10.0.0.0/25 first", "allow 10.0.0.128/25 second", "deny 192.0.2.0/24 blocked",
  ])
  let allow = rules.coverage_ranges(Allow)
  let deny = rules.coverage_ranges(Deny)
  inspect(allow.length(), content="1")
  inspect(allow[0].address_count_label(), content="256")
  inspect(deny.length(), content="1")
  inspect(deny[0].first().to_dotted(), content="192.0.2.0")
}

///|
test "coverage report includes holes and action" {
  let rules = parse_rules(["allow 10.0.0.0/25 internal"])
  let report = rules.coverage_report(
    Allow,
    CidrBlock::parse("10.0.0.0/24").unwrap(),
  )
  inspect(
    report,
    content=(
      #|MoonCIDR coverage report
      #|action: allow
      #|target: 10.0.0.0/24
      #|merged_ranges: 1
      #|uncovered_ranges: 1
      #|
      #|Coverage:
      #|- 10.0.0.0-10.0.0.127 addresses=128 sources=1
      #|
      #|Holes inside target:
      #|- 10.0.0.128-10.0.0.255 addresses=128 sources=1
      #|
    ),
  )
}
