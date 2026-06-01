//! User (UID/GID) namespace value object — the write-once `uid_map`/`gid_map`
//! parser/validator, the setgroups gate, and inside↔outside id translation.
//!
//! Every rule here is from `user_namespaces(7)` (see design §4.1, §4.3):
//! - a map is at most 5 lines, each `inside outside length`;
//! - a map is write-once (a second write fails `EPERM`);
//! - an unmapped id reads back as the overflow id 65534;
//! - an unprivileged process may write only a single-id self-map
//!   (`length == 1`, `outside == euid`);
//! - the setgroups gate: an unprivileged process must write `"deny"` to
//!   `setgroups` before it may write `gid_map`; after `gid_map` is written,
//!   `setgroups` is locked read-only `"deny"`.
//!
//! The pure logic is decoupled from the dispatcher: writers return
//! `Result<(), i64>` where the error is the *positive* Linux errno number
//! (`errno(2)`), which the `/proc` write path converts into the guest-visible
//! `write(2)` return.

use super::{NsId, OVERFLOW_ID};

/// `EPERM` (`errno(2)`). Write-once violation, setgroups gate, unprivileged
/// over-broad map.
pub const EPERM: i64 = 1;
/// `EINVAL` (`errno(2)`). Malformed map / setgroups value.
pub const EINVAL: i64 = 22;

/// A single `uid_map`/`gid_map` line: ids `[inside, inside+length)` inside the
/// namespace map to `[outside, outside+length)` in the parent namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMapEntry {
    pub inside: u32,
    pub outside: u32,
    pub length: u32,
}

impl IdMapEntry {
    /// `true` if `id` falls in this entry's inside range.
    fn contains_inside(&self, id: u32) -> bool {
        // length > 0 is guaranteed by the parser; use u64 to avoid overflow.
        let lo = u64::from(self.inside);
        let hi = lo + u64::from(self.length);
        (lo..hi).contains(&u64::from(id))
    }

    /// `true` if `id` falls in this entry's outside range.
    fn contains_outside(&self, id: u32) -> bool {
        let lo = u64::from(self.outside);
        let hi = lo + u64::from(self.length);
        (lo..hi).contains(&u64::from(id))
    }
}

/// Why a `uid_map`/`gid_map` write was rejected. All map to `EINVAL` per
/// `user_namespaces(7)` ("the file ... was not formatted correctly").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdMapError {
    /// More than the documented 5 lines.
    TooManyLines,
    /// A `length` field of 0 (an empty range is meaningless).
    ZeroLength,
    /// Two lines whose inside *or* outside ranges overlap.
    Overlap,
    /// `inside+length` or `outside+length` exceeds `u32::MAX`.
    RangeOverflow,
    /// Non-numeric token, wrong token count, or no lines at all.
    Malformed,
}

impl IdMapError {
    /// The positive Linux errno this maps to.
    pub fn errno(self) -> i64 {
        EINVAL
    }
}

/// The documented maximum number of lines in a single map (`user_namespaces(7)`).
pub const MAX_ID_MAP_LINES: usize = 5;

/// A parsed `uid_map` or `gid_map`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IdMap {
    entries: Vec<IdMapEntry>,
}

impl IdMap {
    /// The identity map (`0 0 4294967295`) — the initial/default namespace's
    /// map, matching observed `docker run` (design §1.2).
    pub fn identity() -> Self {
        Self {
            entries: vec![IdMapEntry {
                inside: 0,
                outside: 0,
                length: u32::MAX,
            }],
        }
    }

    /// `true` if this is exactly the identity map.
    pub fn is_identity(&self) -> bool {
        matches!(
            self.entries.as_slice(),
            [IdMapEntry {
                inside: 0,
                outside: 0,
                length: u32::MAX,
            }]
        )
    }

    /// The parsed entries.
    pub fn entries(&self) -> &[IdMapEntry] {
        &self.entries
    }

    /// Parse the text written to `/proc/[pid]/uid_map`: up to 5 whitespace-
    /// separated `inside outside length` triples. Enforces the
    /// `user_namespaces(7)` structural rules (≤5 lines, non-zero length, no
    /// overlapping inside/outside ranges, no arithmetic overflow).
    pub fn parse(input: &str) -> Result<Self, IdMapError> {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.is_empty() || !tokens.len().is_multiple_of(3) {
            return Err(IdMapError::Malformed);
        }
        let line_count = tokens.len() / 3;
        if line_count > MAX_ID_MAP_LINES {
            return Err(IdMapError::TooManyLines);
        }
        let mut entries = Vec::with_capacity(line_count);
        for chunk in tokens.chunks_exact(3) {
            let inside: u32 = chunk[0].parse().map_err(|_| IdMapError::Malformed)?;
            let outside: u32 = chunk[1].parse().map_err(|_| IdMapError::Malformed)?;
            let length: u32 = chunk[2].parse().map_err(|_| IdMapError::Malformed)?;
            if length == 0 {
                return Err(IdMapError::ZeroLength);
            }
            // Reject ranges that would wrap past u32::MAX (e.g. inside=10,
            // length=u32::MAX). The identity map (inside=0, length=u32::MAX) is
            // the one legal range that touches the top: 0 + 2^32-1 fits in u64
            // and the half-open interval [0, 2^32-1) is valid.
            if u64::from(inside) + u64::from(length) > u64::from(u32::MAX)
                || u64::from(outside) + u64::from(length) > u64::from(u32::MAX)
            {
                // Allow the exact identity extent length == u32::MAX with base 0.
                let is_full = length == u32::MAX && inside == 0 && outside == 0;
                if !is_full {
                    return Err(IdMapError::RangeOverflow);
                }
            }
            entries.push(IdMapEntry {
                inside,
                outside,
                length,
            });
        }
        // No two entries' inside ranges (or outside ranges) may overlap.
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if ranges_overlap(
                    entries[i].inside,
                    entries[i].length,
                    entries[j].inside,
                    entries[j].length,
                ) || ranges_overlap(
                    entries[i].outside,
                    entries[i].length,
                    entries[j].outside,
                    entries[j].length,
                ) {
                    return Err(IdMapError::Overlap);
                }
            }
        }
        Ok(Self { entries })
    }

    /// Render the map exactly as the Linux kernel prints it: each line is three
    /// width-10 right-justified columns separated by single spaces, newline-
    /// terminated (`%10u %10u %10u\n`). The identity line is
    /// `"         0          0 4294967295\n"` — must match `docker run`
    /// byte-for-byte so the conformance diff passes (design §1.2).
    pub fn render(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&format!(
                "{:>10} {:>10} {:>10}\n",
                e.inside, e.outside, e.length
            ));
        }
        out
    }

    /// Translate an in-namespace id to its parent-namespace id, or the overflow
    /// id 65534 if unmapped (`user_namespaces(7)`).
    pub fn inside_to_outside(&self, id: u32) -> u32 {
        for e in &self.entries {
            if e.contains_inside(id) {
                // Safe: id - inside < length, and outside + (that) < 2^32 by the
                // RangeOverflow check at parse time.
                return e.outside.wrapping_add(id - e.inside);
            }
        }
        OVERFLOW_ID
    }

    /// Translate a parent-namespace id to its in-namespace id, or 65534 if
    /// unmapped.
    pub fn outside_to_inside(&self, id: u32) -> u32 {
        for e in &self.entries {
            if e.contains_outside(id) {
                return e.inside.wrapping_add(id - e.outside);
            }
        }
        OVERFLOW_ID
    }
}

/// Half-open `[a, a+alen)` and `[b, b+blen)` intersect. `u64` math so the
/// identity extent (`alen == u32::MAX`) does not wrap.
fn ranges_overlap(a: u32, alen: u32, b: u32, blen: u32) -> bool {
    let a0 = u64::from(a);
    let a1 = a0 + u64::from(alen);
    let b0 = u64::from(b);
    let b1 = b0 + u64::from(blen);
    a0 < b1 && b0 < a1
}

/// A user namespace: a write-once `uid_map`/`gid_map` pair plus the setgroups
/// gate. The initial namespace is identity-mapped; a freshly created namespace
/// starts with empty maps (every id is overflow until a map is written).
#[derive(Clone, Debug)]
pub struct UserNs {
    pub id: NsId,
    pub parent: Option<NsId>,
    /// `None` until written. The initial ns is `Some(identity)`.
    pub uid_map: Option<IdMap>,
    pub gid_map: Option<IdMap>,
    /// Whether `setgroups(2)` is permitted. Starts `true`; an unprivileged
    /// process writes `"deny"` (false) before `gid_map`.
    pub setgroups_allowed: bool,
    /// Once `gid_map` is written, `setgroups` is locked read-only.
    pub setgroups_locked: bool,
}

impl UserNs {
    /// The initial/default namespace: identity maps, `setgroups=allow`. Matches
    /// observed default `docker run` and carrick's "guest is root" behavior so
    /// the common case is unchanged (design §1.2, §4.2).
    pub fn initial(id: NsId) -> Self {
        Self {
            id,
            parent: None,
            uid_map: Some(IdMap::identity()),
            gid_map: Some(IdMap::identity()),
            setgroups_allowed: true,
            setgroups_locked: false,
        }
    }

    /// A freshly created namespace (`unshare(CLONE_NEWUSER)` / launch
    /// placement): empty maps, `setgroups=allow`, not locked. The creator gets
    /// full capabilities in it (handled by the caller — design §4.1).
    pub fn fresh(id: NsId, parent: NsId) -> Self {
        Self {
            id,
            parent: Some(parent),
            uid_map: None,
            gid_map: None,
            setgroups_allowed: true,
            setgroups_locked: false,
        }
    }

    /// Text for `cat /proc/[pid]/uid_map` (empty if no map written yet).
    pub fn uid_map_text(&self) -> String {
        self.uid_map.as_ref().map(IdMap::render).unwrap_or_default()
    }

    /// Text for `cat /proc/[pid]/gid_map`.
    pub fn gid_map_text(&self) -> String {
        self.gid_map.as_ref().map(IdMap::render).unwrap_or_default()
    }

    /// Text for `cat /proc/[pid]/setgroups` — `"allow\n"` or `"deny\n"`.
    pub fn setgroups_text(&self) -> &'static str {
        if self.setgroups_allowed {
            "allow\n"
        } else {
            "deny\n"
        }
    }

    /// Write `/proc/[pid]/setgroups`. Value must be `"allow"` or `"deny"`
    /// (trailing whitespace ignored). Fails `EPERM` once the gate is locked
    /// (after `gid_map` is written). (Design §4.3 rule 4.)
    pub fn write_setgroups(&mut self, value: &str) -> Result<(), i64> {
        if self.setgroups_locked {
            return Err(EPERM);
        }
        match value.trim() {
            "allow" => self.setgroups_allowed = true,
            "deny" => self.setgroups_allowed = false,
            _ => return Err(EINVAL),
        }
        Ok(())
    }

    /// Write `/proc/[pid]/uid_map`. Write-once (`EPERM` on a second write).
    /// Unprivileged writers may map only a single id whose `outside` equals
    /// their effective uid in the parent ns, `length == 1` (design §4.3 rules
    /// 1, 2).
    pub fn write_uid_map(
        &mut self,
        text: &str,
        privileged: bool,
        euid_outside: u32,
    ) -> Result<(), i64> {
        if self.uid_map.is_some() {
            return Err(EPERM);
        }
        let map = IdMap::parse(text).map_err(IdMapError::errno)?;
        if !privileged {
            check_unprivileged_single_id(&map, euid_outside)?;
        }
        self.uid_map = Some(map);
        Ok(())
    }

    /// Write `/proc/[pid]/gid_map`. Like `uid_map` plus the setgroups gate: an
    /// unprivileged process must have written `"deny"` to `setgroups` first
    /// (else `EPERM`). On success `setgroups` becomes locked (design §4.3 rule
    /// 3, §4.1).
    pub fn write_gid_map(
        &mut self,
        text: &str,
        privileged: bool,
        egid_outside: u32,
    ) -> Result<(), i64> {
        if self.gid_map.is_some() {
            return Err(EPERM);
        }
        // The setgroups gate: unprivileged + setgroups still "allow" → EPERM.
        if !privileged && self.setgroups_allowed {
            return Err(EPERM);
        }
        let map = IdMap::parse(text).map_err(IdMapError::errno)?;
        if !privileged {
            check_unprivileged_single_id(&map, egid_outside)?;
        }
        self.gid_map = Some(map);
        // After gid_map is written, setgroups is locked read-only (and a
        // gid_map implies setgroups is effectively settled).
        self.setgroups_locked = true;
        Ok(())
    }
}

/// The unprivileged single-id rule: exactly one line, `length == 1`, `outside
/// == the writer's effective id in the parent ns`. Otherwise `EPERM`.
fn check_unprivileged_single_id(map: &IdMap, expected_outside: u32) -> Result<(), i64> {
    match map.entries() {
        [e] if e.length == 1 && e.outside == expected_outside => Ok(()),
        _ => Err(EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_renders_like_docker() {
        // Must match `cat /proc/self/uid_map` in a default container exactly.
        assert_eq!(
            IdMap::identity().render(),
            "         0          0 4294967295\n"
        );
    }

    #[test]
    fn identity_predicate() {
        assert!(IdMap::identity().is_identity());
        assert!(!IdMap::parse("0 1000 1").unwrap().is_identity());
    }

    #[test]
    fn parse_single_and_multi_line() {
        let m = IdMap::parse("0 1000 1").unwrap();
        assert_eq!(
            m.entries(),
            &[IdMapEntry {
                inside: 0,
                outside: 1000,
                length: 1
            }]
        );
        let m = IdMap::parse("0 1000 10\n10 2000 5").unwrap();
        assert_eq!(m.entries().len(), 2);
    }

    #[test]
    fn parse_rejects_too_many_lines() {
        let six = "0 0 1\n1 1 1\n2 2 1\n3 3 1\n4 4 1\n5 5 1";
        assert_eq!(IdMap::parse(six), Err(IdMapError::TooManyLines));
    }

    #[test]
    fn parse_rejects_zero_length() {
        assert_eq!(IdMap::parse("0 0 0"), Err(IdMapError::ZeroLength));
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(IdMap::parse(""), Err(IdMapError::Malformed));
        assert_eq!(IdMap::parse("0 0"), Err(IdMapError::Malformed));
        assert_eq!(IdMap::parse("a b c"), Err(IdMapError::Malformed));
        assert_eq!(IdMap::parse("0 0 1 5"), Err(IdMapError::Malformed));
    }

    #[test]
    fn parse_rejects_overlapping_inside() {
        // inside [0,10) and [5,15) overlap.
        assert_eq!(IdMap::parse("0 100 10\n5 200 10"), Err(IdMapError::Overlap));
    }

    #[test]
    fn parse_rejects_overlapping_outside() {
        // outside [100,110) and [105,115) overlap.
        assert_eq!(
            IdMap::parse("0 100 10\n50 105 10"),
            Err(IdMapError::Overlap)
        );
    }

    #[test]
    fn parse_rejects_range_overflow() {
        // inside 10 + length u32::MAX wraps.
        let s = format!("10 0 {}", u32::MAX);
        assert_eq!(IdMap::parse(&s), Err(IdMapError::RangeOverflow));
    }

    #[test]
    fn parse_accepts_identity_full_extent() {
        let s = format!("0 0 {}", u32::MAX);
        assert!(IdMap::parse(&s).unwrap().is_identity());
    }

    #[test]
    fn translate_inside_outside_and_overflow() {
        let m = IdMap::parse("0 1000 10").unwrap();
        assert_eq!(m.inside_to_outside(0), 1000);
        assert_eq!(m.inside_to_outside(9), 1009);
        assert_eq!(m.inside_to_outside(10), OVERFLOW_ID); // out of range
        assert_eq!(m.outside_to_inside(1000), 0);
        assert_eq!(m.outside_to_inside(1009), 9);
        assert_eq!(m.outside_to_inside(999), OVERFLOW_ID);
    }

    #[test]
    fn identity_translates_one_to_one() {
        let m = IdMap::identity();
        assert_eq!(m.inside_to_outside(0), 0);
        assert_eq!(m.inside_to_outside(1000), 1000);
        assert_eq!(m.outside_to_inside(4242), 4242);
    }

    #[test]
    fn initial_ns_is_identity() {
        let ns = UserNs::initial(INITIAL_USER_NS_FOR_TEST);
        assert!(ns.uid_map.as_ref().unwrap().is_identity());
        assert!(ns.gid_map.as_ref().unwrap().is_identity());
        assert_eq!(ns.setgroups_text(), "allow\n");
    }
    const INITIAL_USER_NS_FOR_TEST: NsId = 1;

    #[test]
    fn fresh_ns_has_empty_maps() {
        let ns = UserNs::fresh(2, 1);
        assert!(ns.uid_map.is_none());
        assert_eq!(ns.uid_map_text(), "");
        assert_eq!(ns.gid_map_text(), "");
        assert_eq!(ns.setgroups_text(), "allow\n");
    }

    #[test]
    fn uid_map_is_write_once() {
        let mut ns = UserNs::fresh(2, 1);
        assert_eq!(ns.write_uid_map("0 0 100", true, 0), Ok(()));
        // second write → EPERM
        assert_eq!(ns.write_uid_map("0 0 50", true, 0), Err(EPERM));
    }

    #[test]
    fn gid_map_before_deny_is_eperm_for_unprivileged() {
        let mut ns = UserNs::fresh(2, 1);
        // unprivileged, setgroups still "allow" → gid_map write fails the gate.
        assert_eq!(ns.write_gid_map("0 1000 1", false, 1000), Err(EPERM));
        // write "deny" first, then the single-id gid_map succeeds.
        assert_eq!(ns.write_setgroups("deny"), Ok(()));
        assert_eq!(ns.write_gid_map("0 1000 1", false, 1000), Ok(()));
        // setgroups now locked.
        assert_eq!(ns.write_setgroups("allow"), Err(EPERM));
        assert_eq!(ns.setgroups_text(), "deny\n");
    }

    #[test]
    fn unprivileged_single_id_rule() {
        let mut ns = UserNs::fresh(2, 1);
        // outside must equal the writer's euid (1000), length 1.
        assert_eq!(ns.write_uid_map("0 1000 1", false, 1000), Ok(()));

        let mut ns2 = UserNs::fresh(3, 1);
        // wrong outside → EPERM
        assert_eq!(ns2.write_uid_map("0 999 1", false, 1000), Err(EPERM));

        let mut ns3 = UserNs::fresh(4, 1);
        // length > 1 → EPERM for unprivileged
        assert_eq!(ns3.write_uid_map("0 1000 5", false, 1000), Err(EPERM));

        let mut ns4 = UserNs::fresh(5, 1);
        // multiple lines → EPERM for unprivileged
        assert_eq!(
            ns4.write_uid_map("0 1000 1\n1 1001 1", false, 1000),
            Err(EPERM)
        );
    }

    #[test]
    fn privileged_can_write_arbitrary_map() {
        let mut ns = UserNs::fresh(2, 1);
        assert_eq!(ns.write_uid_map("0 0 65536", true, 0), Ok(()));
        assert_eq!(ns.uid_map_text(), "         0          0      65536\n");
    }

    #[test]
    fn setgroups_write_validates_value() {
        let mut ns = UserNs::fresh(2, 1);
        assert_eq!(ns.write_setgroups("garbage"), Err(EINVAL));
        assert_eq!(ns.write_setgroups("deny\n"), Ok(()));
        assert_eq!(ns.setgroups_text(), "deny\n");
        assert_eq!(ns.write_setgroups("allow"), Ok(()));
        assert_eq!(ns.setgroups_text(), "allow\n");
    }

    #[test]
    fn malformed_map_write_is_einval() {
        let mut ns = UserNs::fresh(2, 1);
        assert_eq!(ns.write_uid_map("not a map", true, 0), Err(EINVAL));
    }
}
