# Background, history, and references

This document situates CVE-2026-109618 / CVE-2026-109619 ("php2shell") in the
documented history of the PHP mechanisms it abuses, answers the question of
whether any part of it is a regression of a previously fixed bug, and collects
the memory-safety literature the epilogue draws on. Every factual statement is
linked to a source. Where the only available sources are third-party databases
or vendor blogs rather than an official PHP advisory, that is noted.

## The 2026 advisory, as reported

The flaw is reported as two linked issues disclosed 2026-10-21, fixed in PHP
8.2.35, 8.3.36, 8.4.27, and 8.5.12; end-of-life branches receive no vendor
release.

- The mechanism, per Mend's database: PHP aborts a request on an out-of-memory
  error with `longjmp()`; if an allocation fails while request memory is
  reachable but not yet fully initialized, request shutdown later reads that
  invalid state, which can lead to a heap use-after-free and remote code
  execution. An unauthenticated attacker can force the out-of-memory condition
  through multipart request parsing; Apache mod_php is exploitable before
  application code runs, and FPM is also susceptible.
  — [Mend: CVE-2026-109618](https://www.mend.io/vulnerability-database/CVE-2026-109618/)
- CrowdStrike's analysis names the canonical instance as
  `_zend_hash_str_add_or_update_i()` in `Zend/zend_hash.c` — the helper behind
  every string-keyed array insert — which increments element counters and takes
  a pointer to the new bucket *before* allocating the key copy, so a failed
  allocation can leave a bucket holding stale heap data.
  — [CrowdStrike: PHP2Shell](https://crowdstrike.com/en-us/blog/crowdstrike-protects-customers-from-php-rce-zero-days)
- Distribution tracking (status varies by branch):
  [Amazon Linux ALAS — CVE-2026-109618](https://explore.alas.aws.amazon.com/CVE-2026-109618.html)

> These three are third-party sources, not PHP's own security advisory. The
> exact change should be confirmed against the upstream `php-src` fix commit
> before relying on specifics.

## Is any part of this a regression?

Short answer: **no clean fix-then-regression.** More precisely, the two halves
have different histories — one a long-known hazard that was never comprehensively
fixed, the other a vector that was fixed and kept resurfacing.

### Part A — bailout from an unsafe point (the state-corruption half)

The danger of `zend_bailout()` (a `longjmp`) firing while the engine holds
half-initialized or locked state is **not new in 2026**. It is documented across
the PHP bug tracker going back more than fifteen years:

- **2008 — bug #46025:** a `zend_bailout` during `HANDLE_BLOCK_INTERRUPTIONS`
  corrupted APC's shared-memory segment and deadlocked its mutex. The reporter
  proposed deferring the `longjmp`.
  — [PHP bug #46025](https://bugs.php.net/bug.php?id=46025)
- **bug #59281:** closed **Won't fix**, with the maintainer position that the
  real fix belonged in APC (wrap critical sections in `zend_try`/`zend_catch`),
  not in the engine.
  — [PHP bug #59281](https://bugs.php.net/bug.php?id=59281)
- **bug #16820:** a timeout `longjmp` that skips lock release, hanging the
  process — the same "bail out of an unsafe point and leave state wrong" shape.
  — [PHP bug #16820](https://bugs.php.net/bug.php?id=16820)

So Part A is best described not as a regression but as a **recurring, long-known
hazard that was repeatedly deferred to consumers** of the engine rather than
fixed generally. CVE-2026-109618's "avoid state corruption via bailout" change
is, on this reading, the first general engine-level fix of a hazard flagged as
early as 2008. (To settle this definitively, bisect `php-src` history around the
OOM/bailout path and `Zend/zend_hash.c`; these tracker entries establish the
hazard was known, not that a specific prior fix regressed.)

### Part B — upload_progress as an injection vector (the delivery half)

The delivery side *does* have a fix history, and it is a story of incomplete
closure rather than a single regression:

- **2015 — bug #71101:** with `session.upload_progress` enabled, an attacker can
  choose the key under which upload-progress data is stored in `$_SESSION`; the
  data then passes through whatever `session.serialize_handler` is configured.
  — [PHP bug #71101](https://bugs.php.net/bug.php?id=71101)
- **2016 — bug #72681 / CVE-2016-7125:** the session deserializer was confirmed
  to let user input reach `unserialize()`, permitting injection of **objects**,
  not just strings. Fixed in PHP 5.6.25 / 7.0.10.
  — [PHP bug #72681](https://bugs.php.net/72681) ·
  [CVE-2016-7125](https://cvefeed.io/vuln/detail/CVE-2016-7125)
- **Adjacent deserializer fixes of the same era:** CVE-2016-7124 (bypassing
  `__wakeup()` when deserializing an unexpected object)
  — [CVE-2016-7124 (Debian tracker)](https://security-tracker.debian.org/tracker/CVE-2016-7124);
  CVE-2015-6835 (use-after-free via repeated `php_var_unserialize`)
  — [CVE-2015-6835](https://cvefeed.io/vuln/detail/CVE-2015-6835);
  CVE-2015-4602 (`__PHP_Incomplete_Class` type confusion)
  — [CVE-2015-4602 (Rapid7)](https://www.rapid7.com/db/vulnerabilities/php-cve-2015-4602/).
- **2021 — Exploit-DB 50156:** a working chain on PHP 7.3.15 using
  `PHP_SESSION_UPLOAD_PROGRESS` plus a local file inclusion, showing the
  upload-progress path remained reachable well after the 2016 fix.
  — [Exploit-DB 50156](https://exploit-db.com/exploits/50156)

So the upload_progress vector was fixed for the specific "attacker chooses the
key" issue in 2016, yet the feature remained a usable delivery path for years.
The 2026 flaw reuses this well-worn path as the delivery for the Part A state
corruption.

### Bottom line

The novelty of php2shell is not a new vector — the delivery is a decade-old,
repeatedly-documented path, and the bailout hazard is older still. What is new
is their **combination into a pre-authentication, pre-application-code remote
code execution**, and the first general engine-level fix of the bailout hazard.

This matters for how the flaw is talked about. It was **not a novel defect
conjured by some super-intelligent tool**; it is a recombination of behavior
that PHP's own bug tracker and CVE record have described since 2008. Anyone with
the public fix commit and this history could reconstruct it — which is the whole
point of the disclosure argument elsewhere in this project. Reconstruction took
patience and a lab, not magic.

## Epilogue — this will keep happening, and why that argues for Rust

The engine-level half of this flaw is a memory-safety failure: a `longjmp`
leaving reachable-but-invalid heap state that is read later as a use-after-free.
It is precisely the class of defect the following publications argue should be
designed out by moving to memory-safe languages.

- **White House ONCD, "Back to the Building Blocks: A Path Toward Secure and
  Measurable Software" (2024-02-26)** — manufacturers can prevent entire classes
  of vulnerabilities by adopting memory-safe languages; C/C++ are common in
  critical software yet not memory safe.
  — [ONCD press release / technical report (archived)](https://bidenwhitehouse.archives.gov/oncd/briefing-room/2024/02/26/press-release-technical-report)
- **CISA/NSA/FBI + allied agencies, "The Case for Memory Safe Roadmaps"
  (2023-12-06)** — memory-safety defects are the most prevalent disclosed
  vulnerability class; makers should publish roadmaps to transition to
  memory-safe languages.
  — [CISA announcement](https://cisa.gov/news-events/alerts/2023/12/06/cisa-releases-joint-guide-software-manufacturers-case-memory-safe-roadmaps) ·
  [PDF (media.defense.gov)](https://media.defense.gov/2023/Dec/06/2003352724/-1/-1/0/THE-CASE-FOR-MEMORY-SAFE-ROADMAPS-TLP-CLEAR.PDF) ·
  [NSA press release](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3608324/us-and-international-partners-issue-recommendations-to-secure-software-products)
- **CISA/FBI/CCCS, "Exploring Memory Safety in Critical Open Source Projects"
  (2024-06)** — a baseline measuring memory-safety risk in selected open-source
  software; a large share of the code studied is in memory-unsafe languages.
  — [ACSC: Exploring Memory Safety in Critical Open Source Projects](https://www.cyber.gov.au/about-us/view-all-content/publications/exploring-memory-safety-in-critical-open-source-projects)
- The NSA list of memory-safe languages cited by these publications includes
  C#, Go, Java, Python, Rust, and Swift.

> Several of these government pages are archived historical material; check the
> agencies' current pages before citing them as present policy.

### Why I build this in Rust — and why you might want me to

php2shell is not the last remote-code-execution bug PHP will ship. The vector is
a decade old, the hazard older, and the pattern — a memory-unsafe engine
executing untrusted input — guarantees more of the same. Treating each one as a
surprise is a losing game.

I write remediation and verification tooling in **Rust** on purpose: a tool that
tells you whether you are exposed, and that your fix held, must not itself carry
the class of defect it is checking for. This classifier cannot have the
use-after-free it reports on. That is the language choice working for you, not
incidental.

I can and do work in PHP when the job calls for it — I would simply rather not
live there. If you run a PHP estate, the useful question is not "are we clear of
this one bug" but "who keeps us ahead of the next one." That is the work I take
on commercially: assessment, remediation, verification, and building the Rust
tooling that makes the next round routine instead of an emergency.

- **Get in touch:** [southcitycomputer.com](https://southcitycomputer.com) ·
  [@nestorwheelock on GitHub](https://github.com/nestorwheelock) — South City
  Computer.
