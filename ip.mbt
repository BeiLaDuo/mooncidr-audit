///|
/// A parsed IPv4 address stored as an unsigned 32-bit integer.
pub struct IPv4 {
  value : UInt
} derive(Eq, Debug)

///|
pub fn IPv4::new(value : UInt) -> IPv4 {
  { value, }
}

///|
pub fn IPv4::value(self : IPv4) -> UInt {
  self.value
}

///|
pub fn IPv4::parse(input : String) -> Result[IPv4, String] {
  let text = trim_ascii(input)
  let chars = text.to_array()
  guard chars.length() > 0 else { return Err("empty IPv4 address") }
  let octets : Array[Int] = []
  let mut current = 0
  let mut digits = 0
  let mut dots = 0
  for char in chars {
    if is_ascii_digit(char) {
      current = current * 10 + digit_value(char)
      digits = digits + 1
      guard digits <= 3 else {
        return Err("IPv4 octet has too many digits: " + input)
      }
      guard current <= 255 else {
        return Err("IPv4 octet is greater than 255: " + input)
      }
    } else if char == '.' {
      guard digits > 0 else {
        return Err("IPv4 dot is not preceded by an octet: " + input)
      }
      octets.push(current)
      current = 0
      digits = 0
      dots = dots + 1
      guard dots <= 3 else {
        return Err("IPv4 address has too many dots: " + input)
      }
    } else {
      return Err("IPv4 address contains an invalid character: " + input)
    }
  }
  guard digits > 0 else {
    return Err("IPv4 address ends after a dot: " + input)
  }
  octets.push(current)
  guard octets.length() == 4 else {
    return Err("IPv4 address must contain four octets: " + input)
  }
  let value = (octets[0].reinterpret_as_uint() << 24) |
    (octets[1].reinterpret_as_uint() << 16) |
    (octets[2].reinterpret_as_uint() << 8) |
    octets[3].reinterpret_as_uint()
  Ok(IPv4::new(value))
}

///|
pub fn IPv4::to_dotted(self : IPv4) -> String {
  let a = ((self.value >> 24) & 255U).reinterpret_as_int()
  let b = ((self.value >> 16) & 255U).reinterpret_as_int()
  let c = ((self.value >> 8) & 255U).reinterpret_as_int()
  let d = (self.value & 255U).reinterpret_as_int()
  "\{a}.\{b}.\{c}.\{d}"
}

///|
pub fn IPv4::is_private(self : IPv4) -> Bool {
  CidrBlock::new_unchecked(IPv4::new(0x0a000000U), 8).contains_ip(self) ||
  CidrBlock::new_unchecked(IPv4::new(0xac100000U), 12).contains_ip(self) ||
  CidrBlock::new_unchecked(IPv4::new(0xc0a80000U), 16).contains_ip(self)
}

///|
pub fn IPv4::is_loopback(self : IPv4) -> Bool {
  CidrBlock::new_unchecked(IPv4::new(0x7f000000U), 8).contains_ip(self)
}

///|
pub fn IPv4::is_link_local(self : IPv4) -> Bool {
  CidrBlock::new_unchecked(IPv4::new(0xa9fe0000U), 16).contains_ip(self)
}

///|
pub fn IPv4::is_multicast(self : IPv4) -> Bool {
  CidrBlock::new_unchecked(IPv4::new(0xe0000000U), 4).contains_ip(self)
}

///|
pub fn IPv4::is_unspecified(self : IPv4) -> Bool {
  self.value == 0U
}

///|
pub fn IPv4::is_limited_broadcast(self : IPv4) -> Bool {
  self.value == 0xffffffffU
}

///|
/// Returns true when the address is not one of the private or special scopes
/// currently recognized by this package.
pub fn IPv4::is_public(self : IPv4) -> Bool {
  !self.is_unspecified() &&
  !self.is_limited_broadcast() &&
  !self.is_loopback() &&
  !self.is_private() &&
  !self.is_link_local() &&
  !self.is_multicast()
}

///|
pub fn IPv4::scope_label(self : IPv4) -> String {
  if self.is_unspecified() {
    "unspecified"
  } else if self.is_limited_broadcast() {
    "limited_broadcast"
  } else if self.is_loopback() {
    "loopback"
  } else if self.is_private() {
    "private"
  } else if self.is_link_local() {
    "link_local"
  } else if self.is_multicast() {
    "multicast"
  } else {
    "public"
  }
}

///|
fn is_ascii_digit(char : Char) -> Bool {
  let code = char.to_int()
  code >= '0' && code <= '9'
}

///|
fn digit_value(char : Char) -> Int {
  char.to_int() - '0'
}

///|
fn is_ascii_space(char : Char) -> Bool {
  char == ' ' || char == '\t' || char == '\r' || char == '\n'
}

///|
fn trim_ascii(input : String) -> String {
  let chars = input.to_array()
  let mut start = 0
  let mut end = chars.length()
  while start < end && is_ascii_space(chars[start]) {
    start = start + 1
  }
  while end > start && is_ascii_space(chars[end - 1]) {
    end = end - 1
  }
  String::from_array(chars[start:end])
}
