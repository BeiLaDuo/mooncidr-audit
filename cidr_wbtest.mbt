///|
test "CIDR parser normalizes host bits" {
  let block = CidrBlock::parse("192.168.1.99/24").unwrap()
  inspect(block.to_string(), content="192.168.1.0/24")
  inspect(block.broadcast().to_dotted(), content="192.168.1.255")
}

///|
test "CIDR parser accepts bare address as slash 32" {
  let block = CidrBlock::parse("8.8.8.8").unwrap()
  inspect(block.to_string(), content="8.8.8.8/32")
}

///|
test "CIDR parser rejects invalid prefix" {
  match CidrBlock::parse("10.0.0.0/33") {
    Ok(_) => inspect("ok", content="err")
    Err(err) => inspect(err, content="CIDR prefix must be between 0 and 32")
  }
}

///|
test "CIDR parser rejects empty prefix" {
  match CidrBlock::parse("10.0.0.0/") {
    Ok(_) => inspect("ok", content="err")
    Err(err) => inspect(err, content="empty CIDR prefix")
  }
}

///|
test "CIDR contains IP" {
  let block = CidrBlock::parse("10.1.0.0/16").unwrap()
  inspect(block.contains_ip(IPv4::parse("10.1.5.5").unwrap()), content="true")
  inspect(block.contains_ip(IPv4::parse("10.2.5.5").unwrap()), content="false")
}

///|
test "CIDR contains another block" {
  let outer = CidrBlock::parse("10.0.0.0/8").unwrap()
  let inner = CidrBlock::parse("10.1.2.0/24").unwrap()
  let outside = CidrBlock::parse("11.1.2.0/24").unwrap()
  inspect(outer.contains_block(inner), content="true")
  inspect(outer.contains_block(outside), content="false")
}

///|
test "CIDR detects overlap" {
  let left = CidrBlock::parse("192.168.0.0/23").unwrap()
  let right = CidrBlock::parse("192.168.1.0/24").unwrap()
  let other = CidrBlock::parse("192.168.4.0/24").unwrap()
  inspect(left.overlaps(right), content="true")
  inspect(left.overlaps(other), content="false")
}

///|
test "CIDR labels size" {
  inspect(
    CidrBlock::parse("0.0.0.0/0").unwrap().size_label(),
    content="all_ipv4",
  )
  inspect(
    CidrBlock::parse("10.0.0.0/8").unwrap().size_label(),
    content="very_wide",
  )
  inspect(CidrBlock::parse("10.1.0.0/16").unwrap().size_label(), content="wide")
  inspect(
    CidrBlock::parse("10.1.2.0/24").unwrap().size_label(),
    content="medium",
  )
  inspect(
    CidrBlock::parse("10.1.2.3/32").unwrap().size_label(),
    content="narrow",
  )
}

///|
test "CIDR raw parser sees host bits" {
  inspect(CidrBlock::has_host_bits("10.1.2.3/24"), content="true")
  inspect(CidrBlock::has_host_bits("10.1.2.0/24"), content="false")
}
