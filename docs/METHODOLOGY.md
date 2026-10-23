# Methodology: how this was reconstructed, verified, patched, and re-verified

This document records the process behind `php2shell-remediate` end to end: the
isolated lab, the reconstruction of the flaw from public material, the
philosophy of proving the flaw is reachable *before* trusting any fix, the patch, and
the re-verification. The point is not only the result but the method — so the
work is repeatable by anyone, and so the reasoning is auditable rather than
asserted.

## A note on terminology

When this document describes the science, the techniques, our discovery, and
our implementation, it uses neutral computer-science terms: *reachability*
(can attacker-controlled input reach a given code path under a given
configuration), *reproduction*, *triggering a code path*, *deserialization of
untrusted input*. These do not presuppose intent or outcome.

Loaded terms such as "exploit" appear only where this document reports how
*others* frame the matter — the advisory, the public write-ups, the disclosure
debate. Those are quotations of a framing, not our description of our own
process.

## 1. Start from doubt, not from the advisory

An advisory tells you a flaw exists and gives it a severity. It does not tell
you whether *your* configuration is exploitable, or what actually has to be
true for exploitation to succeed. The governing philosophy here is: **prove the
reachability yourself, in a disposable copy, before you trust that a patch
closed anything.** "Is it even true?" is the first question, asked of the flaw
and later asked again of the fix.

Concretely that means two reproductions, not one:
1. Reproduce the exposed behavior on a known-vulnerable build, so you know the
   signal of a *live* flaw.
2. Reproduce the same test against the patched build, so the fix is verified by
   the disappearance of that signal — not by a version number alone.

## 2. The lab: a jailed, disposable, snapshot-cloned host

The reproduction never touches a production system and never touches the
workstation. It runs in a FreeBSD jail, which gives process, filesystem, and
network isolation cheaply:

- A base WordPress jail is kept as a template.
- A vulnerable test host is produced by `zfs snapshot` of the template dataset
  followed by `zfs clone`, so the test jail is a copy-on-write fork that can be
  thrown away and recreated in seconds. Nothing done inside it can escape to the
  template or to other jails.
- Each test jail gets its own address on the lab segment and its own
  `nullfs`-mounted service tree, so several PHP point releases can run side by
  side (e.g. one jail on the vulnerable branch, one on the fixed branch).
- Every configuration change inside a jail is backed up before the edit and
  restored afterward, so the jail's state is always a known quantity.

The disposability matters for the philosophy: because the host is a clone, you
can take it to a genuinely broken state to confirm the flaw, then discard it.

## 3. Reconstructing the mechanism from public material

The reproduction detail was not published; it had to be rebuilt from what
was public:

- The vendor's **fix commit** — a public diff — which telegraphs the mechanism
  by showing exactly what state corruption the patch now prevents.
- The advisory's named fixed versions and affected branches.
- Independent public write-ups of the flaw's shape.

Reading the fix in reverse is the core technique: the patch shows which code
path was unsafe, which tells you what input reaches it and under what
conditions. This is the step that an embargo on reproduction detail does *not*
actually deny to a capable analyst — the patch itself is the specification — it
only slows the defender who needs it to verify remediation.

## 4. Proving the flaw is real (and bounded)

Reproduction is not "run an exploit and get a shell." It is mapping the
*conditions* under which the flaw is reachable, because those conditions are
exactly what a defender must check:

- which configuration settings have to be in their vulnerable state;
- whether the front end streams or buffers request bodies (this alone can
  decide reachability);
- what observable signal distinguishes a live flaw from a closed one.

Every test is run with a **positive control** (the expected-failure case run
alongside the expected-success case) and with error output visible, never
discarded. A result that cannot be reproduced with its control is treated as
unproven, not as a finding. This discipline is what lets the later
re-verification mean something.

## 5. A benign signal, not a weapon, for verification

The re-verification step uses a deliberately harmless marker rather than a
harmful input. The flaw class is exercised with an input that a vulnerable
build will *attempt* to process and visibly reject, while a patched build never
processes at all. No command runs, no object's destructor fires, nothing is
written. A remediation check must be safe to run against a system you care
about; proving the door is locked should not require kicking it in.

`php2shell-remediate`'s `interpret_probe` encodes the verdict logic for this
signal, including the honest third state: if the test could not even be
delivered (for example the front end buffered it away), the result is
`Inconclusive` — **never** reported as remediated. Absence of a positive is not
proof of a fix.

## 6. Apply the patch

Remediation is chosen by `plan_remediation` from the observed exposure and what
the platform's package channel actually offers:

- If the package repository already carries a build at or above the fixed point
  release, upgrade in place.
- If the configured channel lags (a real case observed on FreeBSD, where a
  stability package branch still served the vulnerable release while the
  rolling branch already carried the fix), either move to the channel that has
  the fix or build the fixed release from source.
- End-of-life branches that received only a source backport are rebuilt from
  that source; the tool refuses to name a binary "fixed version" it cannot
  stand behind.

The patch is applied to the **sandbox clone first**, never to production
directly, so a bad patch run cannot take a live site down.

## 7. Re-verify, then attest

After patching the clone, step 5 is repeated. The fix is accepted only when the
live-flaw signal is gone *and* the test was actually delivered (not
`Inconclusive`). Only then is the result recorded as a remediation attestation,
and only then is the patch promoted from the sandbox clone to the production
site.

## The shape of the loop

    doubt -> reproduce the live flaw (disposable clone, positive control)
          -> map the conditions
          -> patch the clone
          -> re-verify with a benign signal
          -> attest
          -> promote to production

Nothing in this loop trusts a version string on its own, and nothing is
asserted that was not reproduced with its control. That is the whole method.
