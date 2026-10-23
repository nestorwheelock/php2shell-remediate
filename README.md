# php2shell-remediate

A small, dependency-light Rust tool that classifies a PHP point release against
the **CVE-2026-109618 / CVE-2026-109619 ("php2shell")** advisory of 2026-10-21
and reports what remediation the result implies. No exploit code, no payload —
a pure decision core that answers "is this version exposed, and what closes it?"

---

## Need this remediated? Hire the author.

**Nestor Wheelock — South City Computer** is available **commercially and
professionally** to remediate affected servers and to advise on
CVE-2026-109618 / CVE-2026-109619 exposure across a PHP estate: assessment,
patching, sandbox-first verification, and attestation that the flaw is actually
closed.

- **Get in touch:** [southcitycomputer.com](https://southcitycomputer.com) ·
  [@nestorwheelock on GitHub](https://github.com/nestorwheelock)
- Engagements: one-off remediation, estate-wide rollout, retained advisory, or
  a second opinion on an in-progress response.

If your servers run PHP and you are not certain they are clear of this advisory,
that uncertainty is exactly what this service resolves.

---

## Navigation

- [What this is](#php2shell-remediate)
- [Fixed versions](#fixed-versions)
- [Usage](#usage)
- [Library API](#library)
- [Build from source](#build)
- [Downloads](#downloads)
- **Documents**
  - [Methodology — how this was reconstructed, verified, patched, re-verified](docs/METHODOLOGY.md)
  - [Legal and lawful-use disclaimer](docs/DISCLAIMER.md)
  - [Manual (man page source)](docs/php2shell-remediate.1)
- [License](#license)

---

## Fixed versions

| Branch | Fixed in |
|--------|----------|
| 8.5    | 8.5.12   |
| 8.4    | 8.4.27   |
| 8.3    | 8.3.36   |
| 8.2    | 8.2.35   |

7.4 / 8.0 / 8.1 are end-of-life and received source-only backports rather than a
vendor binary point release; the tool reports those separately rather than
naming a fixed version it cannot vouch for. A branch the advisory does not name
is reported as `UNKNOWN-BRANCH`, never guessed into patched or exposed.

## Usage

```
php2shell-remediate classify <php-version-string>
```

The version string may be a bare `8.2.35`, an `X-Powered-By` value like
`PHP/8.2.35`, or a distro build string (`8.1.29-1+deb.sury.org+1`).

Exit codes: `0` patched · `1` exposed, EOL, or unknown-branch · `2` bad input.

```
$ php2shell-remediate classify PHP/8.4.26
EXPOSED 8.4.26 — fixed in 8.4.27
$ php2shell-remediate classify 8.4.27
PATCHED 8.4.27
```

## Library

The crate also exposes the decision functions for embedding:

- `parse_php_version` — tolerant version parsing from real-world strings.
- `classify_exposure` — version → `Exposure`.
- `plan_remediation` — `Exposure` + package-repo availability → `RemediationPlan`
  (`UpgradeToPointRelease`, `BuildFromSource`, `BuildFromSourceBackport`,
  `NoActionNeeded`). On platforms whose package branch lags the fix (e.g. a
  FreeBSD site on `quarterly` while `latest` already carries it), the plan is a
  source build.
- `interpret_probe` — turns the observations of a **benign** sandbox
  re-verification probe into a `ProbeVerdict` (`StillVulnerable`, `Remediated`,
  `Inconclusive`). A session the handler never read is `Inconclusive`, never
  reported as remediated.

## Build

```
cargo build --release
cargo test
```

## Downloads

Prebuilt binaries are published on the releases page: a Windows `.exe`, a
statically linked Linux binary (`x86_64-unknown-linux-musl`, runs on any x86_64
Linux), and a FreeBSD package (`FreeBSD:15:amd64`). Each release ships a
`SHA256SUMS` file — verify before running.

## License

Code: BSD-2-Clause. See [LICENSE](LICENSE). Accompanying written articles and
research prose are **All Rights Reserved** and are not covered by the code
license.
