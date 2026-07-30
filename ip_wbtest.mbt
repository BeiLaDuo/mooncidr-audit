///|
test "IPv4 parser accepts ordinary address" {
  match IPv4::parse("192.168.1.10") {
    Ok(ip) => {
      inspect(ip.to_dotted(), content="192.168.1.10")
      inspect(ip.scope_label(), content="private")
    }
    Err(err) => inspect(err, content="unexpected")
  }
}

///|
test "IPv4 parser trims whitespace" {
  match IPv4::parse("  8.8.8.8\t") {
    Ok(ip) => inspect(ip.to_dotted(), content="8.8.8.8")
    Err(err) => inspect(err, content="unexpected")
  }
}

///|
test "IPv4 parser rejects empty address" {
  match IPv4::parse("") {
    Ok(_) => inspect("ok", content="err")
    Err(err) => inspect(err, content="empty IPv4 address")
  }
}

///|
test "IPv4 parser rejects missing octet" {
  match IPv4::parse("10..0.1") {
    Ok(_) => inspect("ok", content="err")
    Err(err) =>
      inspect(err, content="IPv4 dot is not preceded by an octet: 10..0.1")
  }
}

///|
test "IPv4 parser rejects high octet" {
  match IPv4::parse("10.0.300.1") {
    Ok(_) => inspect("ok", content="err")
    Err(err) =>
      inspect(err, content="IPv4 octet is greater than 255: 10.0.300.1")
  }
}

///|
test "IPv4 parser rejects too few octets" {
  match IPv4::parse("10.0.1") {
    Ok(_) => inspect("ok", content="err")
    Err(err) =>
      inspect(err, content="IPv4 address must contain four octets: 10.0.1")
  }
}

///|
test "IPv4 parser rejects too many dots" {
  match IPv4::parse("1.2.3.4.5") {
    Ok(_) => inspect("ok", content="err")
    Err(err) =>
      inspect(err, content="IPv4 address has too many dots: 1.2.3.4.5")
  }
}

///|
test "IPv4 parser rejects trailing dot" {
  match IPv4::parse("1.2.3.") {
    Ok(_) => inspect("ok", content="err")
    Err(err) => inspect(err, content="IPv4 address ends after a dot: 1.2.3.")
  }
}

///|
test "IPv4 recognizes private ranges" {
  inspect(IPv4::parse("10.1.2.3").unwrap().is_private(), content="true")
  inspect(IPv4::parse("172.16.1.1").unwrap().is_private(), content="true")
  inspect(IPv4::parse("192.168.1.1").unwrap().is_private(), content="true")
  inspect(IPv4::parse("172.15.1.1").unwrap().is_private(), content="false")
}

///|
test "IPv4 recognizes special scopes" {
  inspect(IPv4::parse("127.0.0.1").unwrap().scope_label(), content="loopback")
  inspect(
    IPv4::parse("169.254.1.1").unwrap().scope_label(),
    content="link_local",
  )
  inspect(IPv4::parse("224.0.0.1").unwrap().scope_label(), content="multicast")
  inspect(IPv4::parse("0.0.0.0").unwrap().scope_label(), content="unspecified")
  inspect(
    IPv4::parse("255.255.255.255").unwrap().scope_label(),
    content="limited_broadcast",
  )
}

///|
test "IPv4 round trips unsigned maximum" {
  let ip = IPv4::parse("255.255.255.255").unwrap()
  inspect(ip.to_dotted(), content="255.255.255.255")
  inspect(ip.value(), content="4294967295")
}

///|
test "IPv4 identifies public addresses" {
  inspect(IPv4::parse("8.8.8.8").unwrap().is_public(), content="true")
  inspect(IPv4::parse("1.1.1.1").unwrap().is_public(), content="true")
  inspect(IPv4::parse("192.168.1.1").unwrap().is_public(), content="false")
  inspect(IPv4::parse("127.0.0.1").unwrap().is_public(), content="false")
  inspect(IPv4::parse("224.0.0.1").unwrap().is_public(), content="false")
}
