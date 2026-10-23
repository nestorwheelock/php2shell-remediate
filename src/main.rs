//! php2shell-remediate — exposure classification and remediation planning for
//! CVE-2026-109618 / CVE-2026-109619 ("php2shell").
//!
//!   php2shell-remediate classify <php-version-string>
//!
//! Exit: 0 patched · 1 exposed, EOL, or unknown-branch · 2 bad input.
//!
//! `classify` takes an already-observed version string (e.g. captured from an
//! `X-Powered-By` header or `php -v`) and reports exposure. A live HTTP probe
//! that fetches that header itself is intentionally out of scope for this
//! release: the decision core here is pure and testable without a network.

use clap::{Parser, Subcommand};
use tools_php2shell_remediate::{classify_exposure, parse_php_version, Exposure};

#[derive(Parser)]
#[command(
    name = "php2shell-remediate",
    version,
    about = "CVE-2026-109618/CVE-2026-109619 (php2shell) PHP exposure classifier and remediation planner",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Classify an already-observed PHP version string against the 2026-10-21 advisory.
    Classify {
        /// The version string, as read from `X-Powered-By` or a shell `php -v`.
        version: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Classify { version } => std::process::exit(run_classify(&version)),
    }
}

fn run_classify(raw: &str) -> i32 {
    let parsed = match parse_php_version(raw) {
        Ok(v) => v,
        Err(e) => {
            println!("BAD INPUT {raw:?} — {e}");
            return 2;
        }
    };
    match classify_exposure(&parsed) {
        Exposure::Patched => {
            println!("PATCHED {parsed}");
            0
        }
        Exposure::Exposed { fixed_in } => {
            println!("EXPOSED {parsed} — fixed in {fixed_in}");
            1
        }
        Exposure::EolNoVendorFix => {
            println!("EOL-BRANCH {parsed} — end-of-life, no vendor fix; migrate to a supported branch");
            1
        }
        Exposure::UnknownBranch => {
            println!("UNKNOWN-BRANCH {parsed} — not named by the 2026-10-21 advisory");
            1
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
