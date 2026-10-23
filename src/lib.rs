//! Decision core for `php2shell-remediate`: is an observed PHP point release
//! exposed to CVE-2026-109618 / CVE-2026-109619 ("php2shell"), and if so, which
//! vendor point release closes it, and what remediation that implies. Pure — no
//! DB, no network — so every branch is testable without a probe ever running.
//!
//! Fixed versions per the 2026-10-21 advisory: 8.5.12, 8.4.27, 8.3.36, 8.2.35.
//! 7.4, 8.0, 8.1 are end-of-life and got source-only backports, not a vendor
//! binary release; this tool reports that branch separately rather than
//! inventing a fixed version number for it. Any branch not named by the
//! advisory is reported as unknown, never guessed into Patched or Exposed.

use std::fmt;

/// A parsed `major.minor.patch` PHP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhpVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse a PHP version out of a raw string — a bare `8.2.35`, an
/// `X-Powered-By` value like `PHP/8.2.35`, or a distro build string with a
/// suffix after the patch level (`8.1.29-1+ubuntu20.04.1+deb.sury.org+1`).
///
/// # Errors
/// Returns `Err` if fewer than three dot-separated numeric components can be
/// read from the start of the (optionally `PHP/`-prefixed) string.
pub fn parse_php_version(raw: &str) -> Result<PhpVersion, String> {
    let s = raw.strip_prefix("PHP/").unwrap_or(raw);
    let mut parts = s.split('.');
    let major = next_numeric_component(&mut parts, raw)?;
    let minor = next_numeric_component(&mut parts, raw)?;
    let patch_raw = parts
        .next()
        .ok_or_else(|| format!("{raw:?} does not have a patch component"))?;
    // The patch component may trail into a distro suffix after the first
    // non-digit byte (`35-1+ubuntu...`); take the leading digits only.
    let patch_digits: String = patch_raw.chars().take_while(char::is_ascii_digit).collect();
    if patch_digits.is_empty() {
        return Err(format!("{raw:?} has no numeric patch component"));
    }
    let patch = patch_digits
        .parse()
        .map_err(|_| format!("{raw:?} patch component does not fit u32"))?;
    // Reject a fourth numeric component sitting right after the patch digits
    // (`v8.2.35.1.2`) — that is not a three-component version.
    if patch_raw[patch_digits.len()..].starts_with('.') {
        return Err(format!("{raw:?} has more than three numeric components"));
    }
    Ok(PhpVersion {
        major,
        minor,
        patch,
    })
}

fn next_numeric_component<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    raw: &str,
) -> Result<u32, String> {
    parts
        .next()
        .ok_or_else(|| format!("{raw:?} is missing a version component"))?
        .parse()
        .map_err(|_| format!("{raw:?} has a non-numeric version component"))
}

/// What CVE-2026-109618/CVE-2026-109619 exposure classification says about one
/// observed [`PhpVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Below the fixed point release on its branch.
    Exposed { fixed_in: PhpVersion },
    /// At or above the fixed point release on its branch.
    Patched,
    /// 7.4 / 8.0 / 8.1 — end-of-life; the vendor shipped a source-only
    /// backport, not a point release this tool can name as "fixed_in".
    EolBranchSourceBackportOnly,
    /// A branch the 2026-10-21 advisory does not name. Never asserted as
    /// Patched or Exposed — an unnamed branch is unverified, not safe.
    UnknownBranch,
}

/// The vendor-fixed patch level for each branch the advisory names.
const FIXED_PATCH_BY_BRANCH: [(u32, u32, u32); 4] =
    [(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)];

/// The end-of-life branches named in the advisory as source-backport-only.
const EOL_BRANCHES: [(u32, u32); 3] = [(7, 4), (8, 0), (8, 1)];

/// Classify `observed` against the 2026-10-21 php2shell advisory.
#[must_use]
pub fn classify_exposure(observed: &PhpVersion) -> Exposure {
    for &(major, minor, patch) in &FIXED_PATCH_BY_BRANCH {
        if observed.major == major && observed.minor == minor {
            return if observed.patch >= patch {
                Exposure::Patched
            } else {
                Exposure::Exposed {
                    fixed_in: PhpVersion {
                        major,
                        minor,
                        patch,
                    },
                }
            };
        }
    }
    for &(major, minor) in &EOL_BRANCHES {
        if observed.major == major && observed.minor == minor {
            return Exposure::EolBranchSourceBackportOnly;
        }
    }
    Exposure::UnknownBranch
}

/// What a sandbox re-verification probe observed after planting a benign
/// throwing-class marker session (`poc|O:7:"Closure":0:{}`) and firing one
/// `PHP_SESSION_UPLOAD_PROGRESS` request against the patched sandbox clone.
///
/// The marker is deliberately benign. `Closure` is on PHP's unserialize-deny
/// list, so it instantiates no object and runs no destructor: a vulnerable
/// target betrays itself merely by *attempting* the pre-RINIT unserialize (the
/// "Unserialization of 'Closure' is not allowed" fatal raised from request
/// startup, with no active file), while a patched target never reaches that
/// code path. A remediation check must not carry a harmful payload onto a
/// client's sandbox; a safe signal is all an attestation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSignals {
    /// The target attempted the pre-RINIT unserialize of the planted session
    /// object — observed as the `Closure` unserialize-denied fatal coupled with
    /// a "PHP Request Startup" / "Failed to decode session object" marker, which
    /// together place the attempt before any user code (`[no active file]:0`).
    pub pre_rinit_unserialize_attempted: bool,
    /// The planted session file was read by the request (consumed: deleted or
    /// truncated), proving the handler actually processed it rather than the
    /// front end buffering the body away before PHP ever saw it.
    pub session_consumed: bool,
}

/// The verdict of a sandbox re-verification probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The pre-RINIT unserialize was still attempted: the sink the advisory
    /// closes is reachable. The patch did not take, or was applied to the wrong
    /// interpreter.
    StillVulnerable,
    /// The handler read the planted session yet made no pre-RINIT unserialize
    /// attempt — the patched behavior (`in_rfc1867_update` restricting pre-RINIT
    /// decoding to `__PHP_Incomplete_Class`). Safe to attest.
    Remediated,
    /// The planted session was never read, so vulnerable and patched cannot be
    /// told apart (front-end request buffering, wrong session path, or a worker
    /// that did not pick up the request). Never attested as remediated.
    Inconclusive,
}

/// Interpret a sandbox probe's observations into a [`ProbeVerdict`]. Pure — the
/// network-facing probe fills [`ProbeSignals`]; this is the testable decision.
#[must_use]
pub fn interpret_probe(signals: &ProbeSignals) -> ProbeVerdict {
    if signals.pre_rinit_unserialize_attempted {
        // An attempt is only observable if the session was read, so this
        // dominates `session_consumed`.
        ProbeVerdict::StillVulnerable
    } else if signals.session_consumed {
        ProbeVerdict::Remediated
    } else {
        ProbeVerdict::Inconclusive
    }
}

/// Whether the platform's package repository currently offers a binary build
/// at or above the fixed point release for the exposed branch. For example, a
/// FreeBSD site pinned to the `quarterly` package branch may see only the
/// vulnerable point release while `latest` already carries the fix, so this is
/// a property of the configured repository, not of the branch alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageRepoFix {
    /// The repo has a build at or above the fixed point release: upgrade in place.
    Available,
    /// The repo has no fixed build: the fix must be built from source.
    Absent,
}

/// What the remediation step must actually do to close the exposure. The
/// network/shell-facing apply layer executes this; the mapping itself is pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemediationPlan {
    /// Upgrade to the vendor binary point release from the package repo.
    UpgradeToPointRelease { fixed_in: PhpVersion },
    /// No fixed binary in the repo: rebuild this point release from source
    /// (ports or vanilla source) at the fixed version, then install it.
    BuildFromSource { fixed_in: PhpVersion },
    /// EOL branch (7.4 / 8.0 / 8.1): only a source-only backport exists; rebuild
    /// from the backported source. There is no vendor point release to name.
    BuildFromSourceBackport,
    /// Already patched, or a branch the advisory does not name — nothing to
    /// apply. An unknown branch is surfaced for a human, never auto-patched.
    NoActionNeeded,
}

/// Decide the remediation plan for an [`Exposure`] given what the platform's
/// package repo offers. Pure — the apply layer carries it out.
#[must_use]
pub fn plan_remediation(exposure: Exposure, repo: PackageRepoFix) -> RemediationPlan {
    match exposure {
        Exposure::Exposed { fixed_in } => match repo {
            PackageRepoFix::Available => RemediationPlan::UpgradeToPointRelease { fixed_in },
            PackageRepoFix::Absent => RemediationPlan::BuildFromSource { fixed_in },
        },
        Exposure::EolBranchSourceBackportOnly => RemediationPlan::BuildFromSourceBackport,
        Exposure::Patched | Exposure::UnknownBranch => RemediationPlan::NoActionNeeded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trips_through_parse() {
        let v = parse_php_version("8.2.35").unwrap();
        assert_eq!(v.to_string(), "8.2.35");
    }
}
