///|
/// Controls how noisy or strict CIDR audits should be.
pub struct AuditPolicy {
  wide_allow_prefix : Int
  flag_private : Bool
  flag_special_ranges : Bool
  flag_non_canonical : Bool
  flag_redundant_overlap : Bool
} derive(Eq, Debug)

///|
pub fn AuditPolicy::strict() -> AuditPolicy {
  {
    wide_allow_prefix: 16,
    flag_private: true,
    flag_special_ranges: true,
    flag_non_canonical: true,
    flag_redundant_overlap: true,
  }
}

///|
pub fn AuditPolicy::gateway() -> AuditPolicy {
  {
    wide_allow_prefix: 8,
    flag_private: true,
    flag_special_ranges: true,
    flag_non_canonical: true,
    flag_redundant_overlap: true,
  }
}

///|
pub fn AuditPolicy::quiet() -> AuditPolicy {
  {
    wide_allow_prefix: 0,
    flag_private: false,
    flag_special_ranges: true,
    flag_non_canonical: true,
    flag_redundant_overlap: false,
  }
}

///|
pub fn AuditPolicy::wide_allow_prefix(self : AuditPolicy) -> Int {
  self.wide_allow_prefix
}

///|
pub fn AuditPolicy::flag_private(self : AuditPolicy) -> Bool {
  self.flag_private
}

///|
pub fn AuditPolicy::flag_special_ranges(self : AuditPolicy) -> Bool {
  self.flag_special_ranges
}

///|
pub fn AuditPolicy::flag_non_canonical(self : AuditPolicy) -> Bool {
  self.flag_non_canonical
}

///|
pub fn AuditPolicy::flag_redundant_overlap(self : AuditPolicy) -> Bool {
  self.flag_redundant_overlap
}
