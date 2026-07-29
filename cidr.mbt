///|
/// A normalized IPv4 CIDR block.
pub struct CidrBlock {
  network : IPv4
  prefix : Int
} derive(Eq, Debug)

///|
pub fn CidrBlock::new_unchecked(network : IPv4, prefix : Int) -> CidrBlock {
  { network: IPv4::new(network.value() & prefix_mask(prefix)), prefix }
}

///|
pub fn CidrBlock::new(
  address : IPv4,
  prefix : Int,
) -> Result[CidrBlock, String] {
  guard prefix >= 0 && prefix <= 32 else {
    return Err("CIDR prefix must be between 0 and 32")
  }
  Ok(CidrBlock::new_unchecked(address, prefix))
}

///|
pub fn CidrBlock::parse(input : String) -> Result[CidrBlock, String] {
  let text = trim_ascii(input)
  let chars = text.to_array()
  guard chars.length() > 0 else { return Err("empty CIDR block") }
  let mut slash = -1
  for index = 0; index < chars.length(); index = index + 1 {
    if chars[index] == '/' {
      guard slash == -1 else {
        return Err("CIDR block contains more than one slash: " + input)
      }
      slash = index
    }
  }
  if slash == -1 {
    match IPv4::parse(text) {
      Ok(ip) => CidrBlock::new(ip, 32)
      Err(err) => Err(err)
    }
  } else {
    let ip_text = String::from_array(chars[0:slash])
    let prefix_text = String::from_array(chars[slash + 1:])
    match IPv4::parse(ip_text) {
      Err(err) => Err(err)
      Ok(ip) =>
        match parse_prefix(prefix_text) {
          Err(err) => Err(err)
          Ok(prefix) => CidrBlock::new(ip, prefix)
        }
    }
  }
}

///|
pub fn CidrBlock::network(self : CidrBlock) -> IPv4 {
  self.network
}

///|
pub fn CidrBlock::prefix(self : CidrBlock) -> Int {
  self.prefix
}

///|
pub fn CidrBlock::broadcast(self : CidrBlock) -> IPv4 {
  IPv4::new(self.network.value() | host_mask(self.prefix))
}

///|
pub fn CidrBlock::contains_ip(self : CidrBlock, ip : IPv4) -> Bool {
  ip.value() >= self.network.value() && ip.value() <= self.broadcast().value()
}

///|
pub fn CidrBlock::contains_block(self : CidrBlock, other : CidrBlock) -> Bool {
  self.contains_ip(other.network()) && self.contains_ip(other.broadcast())
}

///|
pub fn CidrBlock::overlaps(self : CidrBlock, other : CidrBlock) -> Bool {
  self.network.value() <= other.broadcast().value() &&
  other.network().value() <= self.broadcast().value()
}

///|
pub fn CidrBlock::equal_range(self : CidrBlock, other : CidrBlock) -> Bool {
  self.network.value() == other.network().value() &&
  self.broadcast().value() == other.broadcast().value()
}

///|
pub fn CidrBlock::has_host_bits(input : String) -> Bool {
  match CidrBlock::parse_raw(input) {
    Ok((ip, prefix)) => ip.value() != (ip.value() & prefix_mask(prefix))
    Err(_) => false
  }
}

///|
pub fn CidrBlock::parse_raw(input : String) -> Result[(IPv4, Int), String] {
  let text = trim_ascii(input)
  let chars = text.to_array()
  let mut slash = -1
  for index = 0; index < chars.length(); index = index + 1 {
    if chars[index] == '/' {
      slash = index
    }
  }
  if slash == -1 {
    match IPv4::parse(text) {
      Ok(ip) => Ok((ip, 32))
      Err(err) => Err(err)
    }
  } else {
    match IPv4::parse(String::from_array(chars[0:slash])) {
      Err(err) => Err(err)
      Ok(ip) =>
        match parse_prefix(String::from_array(chars[slash + 1:])) {
          Ok(prefix) => Ok((ip, prefix))
          Err(err) => Err(err)
        }
    }
  }
}

///|
pub fn CidrBlock::to_string(self : CidrBlock) -> String {
  self.network.to_dotted() + "/" + self.prefix.to_string()
}

///|
pub fn CidrBlock::size_label(self : CidrBlock) -> String {
  if self.prefix == 0 {
    "all_ipv4"
  } else if self.prefix <= 8 {
    "very_wide"
  } else if self.prefix <= 16 {
    "wide"
  } else if self.prefix <= 24 {
    "medium"
  } else {
    "narrow"
  }
}

///|
fn parse_prefix(input : String) -> Result[Int, String] {
  let text = trim_ascii(input)
  let chars = text.to_array()
  guard chars.length() > 0 else { return Err("empty CIDR prefix") }
  let mut value = 0
  for char in chars {
    guard is_ascii_digit(char) else {
      return Err("CIDR prefix contains an invalid character: " + input)
    }
    value = value * 10 + digit_value(char)
    guard value <= 32 else {
      return Err("CIDR prefix must be between 0 and 32")
    }
  }
  Ok(value)
}

///|
fn prefix_mask(prefix : Int) -> UInt {
  if prefix == 0 {
    0U
  } else {
    0xffffffffU << (32 - prefix)
  }
}

///|
fn host_mask(prefix : Int) -> UInt {
  if prefix == 32 {
    0U
  } else {
    0xffffffffU >> prefix
  }
}
