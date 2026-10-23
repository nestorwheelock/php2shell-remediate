use tools_php2shell_remediate::{
    classify_exposure, interpret_probe, parse_php_version, plan_remediation, Exposure,
    PackageRepoFix, PhpVersion, ProbeSignals, ProbeVerdict, RemediationPlan,
};

#[test]
fn versions_below_the_fix_are_exposed_with_the_fixed_version_named() {
    let cases = [
        ("8.5.11", "8.5.12"),
        ("8.4.26", "8.4.27"),
        ("8.3.35", "8.3.36"),
        ("8.2.34", "8.2.35"),
        ("8.2.0", "8.2.35"),
    ];
    for (observed, fixed) in cases {
        let v = parse_php_version(observed).unwrap();
        match classify_exposure(&v) {
            Exposure::Exposed { fixed_in } => {
                assert_eq!(fixed_in.to_string(), fixed, "observed {observed}");
            }
            other => panic!("{observed}: expected Exposed, got {other:?}"),
        }
    }
}

#[test]
fn the_fixed_version_itself_and_anything_newer_on_the_branch_is_patched() {
    for observed in ["8.5.12", "8.5.13", "8.4.27", "8.3.36", "8.2.35", "8.2.99"] {
        let v = parse_php_version(observed).unwrap();
        assert_eq!(
            classify_exposure(&v),
            Exposure::Patched,
            "observed {observed}"
        );
    }
}

#[test]
fn eol_branches_have_no_tracked_binary_fix_and_are_named_separately_from_exposed() {
    // 7.4, 8.0, 8.1 only got source-only backports per the advisory; this tool
    // does not report a binary fixed version for them.
    for observed in ["7.4.33", "8.0.30", "8.1.29"] {
        let v = parse_php_version(observed).unwrap();
        assert_eq!(
            classify_exposure(&v),
            Exposure::EolBranchSourceBackportOnly,
            "observed {observed}"
        );
    }
}

#[test]
fn a_branch_outside_the_advisory_table_is_unknown_not_guessed() {
    // Never assert Patched or Exposed for a branch this tool was not told about.
    for observed in ["9.0.0", "8.6.0", "7.3.0"] {
        let v = parse_php_version(observed).unwrap();
        assert_eq!(
            classify_exposure(&v),
            Exposure::UnknownBranch,
            "observed {observed}"
        );
    }
}

#[test]
fn version_parsing_accepts_the_shapes_a_real_probe_will_see_and_rejects_junk() {
    assert!(parse_php_version("8.2.35").is_ok());
    // An X-Powered-By header value, not a bare version.
    assert_eq!(
        parse_php_version("PHP/8.2.35").unwrap().to_string(),
        "8.2.35"
    );
    // Distro suffix after the patch level.
    assert_eq!(
        parse_php_version("8.1.29-1+ubuntu20.04.1+deb.sury.org+1")
            .unwrap()
            .to_string(),
        "8.1.29"
    );
    for junk in ["", "php", "8.2", "8.x.1", "v8.2.35.1.2"] {
        assert!(
            parse_php_version(junk).is_err(),
            "expected rejection of {junk:?}"
        );
    }
}

#[test]
fn an_exposed_branch_with_a_repo_fix_upgrades_in_place() {
    let exposure = classify_exposure(&parse_php_version("8.4.26").unwrap());
    assert_eq!(
        plan_remediation(exposure, PackageRepoFix::Available),
        RemediationPlan::UpgradeToPointRelease {
            fixed_in: PhpVersion { major: 8, minor: 4, patch: 27 }
        }
    );
}

#[test]
fn an_exposed_branch_with_no_repo_fix_builds_from_source() {
    // A site pinned to a package branch that has not yet received the fixed
    // build: the only path is a source build of the fixed point release.
    let exposure = classify_exposure(&parse_php_version("8.4.26").unwrap());
    assert_eq!(
        plan_remediation(exposure, PackageRepoFix::Absent),
        RemediationPlan::BuildFromSource {
            fixed_in: PhpVersion { major: 8, minor: 4, patch: 27 }
        }
    );
}

#[test]
fn an_eol_branch_builds_from_the_source_backport() {
    let exposure = classify_exposure(&parse_php_version("8.1.29").unwrap());
    // The repo state is irrelevant for an EOL branch: there is no point release.
    for repo in [PackageRepoFix::Available, PackageRepoFix::Absent] {
        assert_eq!(
            plan_remediation(exposure, repo),
            RemediationPlan::BuildFromSourceBackport
        );
    }
}

#[test]
fn a_patched_or_unknown_branch_needs_no_remediation() {
    for observed in ["8.4.27", "9.0.0"] {
        let exposure = classify_exposure(&parse_php_version(observed).unwrap());
        assert_eq!(
            plan_remediation(exposure, PackageRepoFix::Absent),
            RemediationPlan::NoActionNeeded,
            "observed {observed}"
        );
    }
}

#[test]
fn a_still_attempted_pre_rinit_unserialize_is_vulnerable() {
    let signals = ProbeSignals {
        pre_rinit_unserialize_attempted: true,
        session_consumed: true,
    };
    assert_eq!(interpret_probe(&signals), ProbeVerdict::StillVulnerable);
}

#[test]
fn a_read_session_with_no_attempt_is_remediated() {
    let signals = ProbeSignals {
        pre_rinit_unserialize_attempted: false,
        session_consumed: true,
    };
    assert_eq!(interpret_probe(&signals), ProbeVerdict::Remediated);
}

#[test]
fn a_session_the_handler_never_read_is_inconclusive_not_remediated() {
    // Front-end buffering (or a wrong session path) can hide the body from PHP.
    // Absence of the attempt must never be read as proof of a fix.
    let signals = ProbeSignals {
        pre_rinit_unserialize_attempted: false,
        session_consumed: false,
    };
    assert_eq!(interpret_probe(&signals), ProbeVerdict::Inconclusive);
    assert_ne!(interpret_probe(&signals), ProbeVerdict::Remediated);
}
