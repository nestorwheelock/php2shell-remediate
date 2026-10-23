# Legal and testing disclaimer

This is a plain statement of how and where the research behind
`php2shell-remediate` was conducted. It is not legal advice; any binding or
jurisdiction-specific wording is the author's counsel's call.

## WARNING — READ THIS FIRST

**This material is for educational purposes only.**

- **Run it only against systems you own or are explicitly authorized in writing
  to test.**
- **Do not break the law.** Accessing, probing, or modifying a computer system
  without authorization is a crime in most jurisdictions.
- **Benevolent intent is not a defense.** "I was only helping" / "I was fixing
  it" does not make unauthorized access lawful. An intrusion meant to secure
  someone else's system is still an intrusion, and can still be prosecuted. If
  it is not your system and you do not have authorization, do not touch it —
  report it instead.

If you are not certain the system is yours and the activity is lawful, stop.

## Scope of the work

All testing, reproduction, and security research described in this project
and its accompanying write-ups was performed by the author, on computer systems
**owned and operated by the author**, as part of legitimate security research
and the remediation of the author's own infrastructure.

- **Self-owned equipment only.** No system belonging to any other person or
  organization was accessed, scanned, probed, or tested at any point.
- **Isolated, non-internet-accessible lab.** The vulnerable hosts were FreeBSD
  jails on the author's own hardware, running on an isolated lab network
  segment. They were not reachable from the public internet and were not
  exposed to any third party. The vulnerable builds existed only inside
  disposable, copy-on-write clones created for the test and destroyed
  afterward.
- **No live or third-party targets.** Nothing in this work was directed at a
  production system, a customer system, or any host the author does not own.
  The flaw's behavior was reproduced solely to establish ground truth for
  the author's own remediation and verification process.

## Purpose

The purpose of this work is defensive: to determine whether a given PHP point
release is genuinely exposed to CVE-2026-109618 / CVE-2026-109619, to remediate
the author's own affected systems, and to verify — not assume — that the
remediation closed the flaw. The process it documents is deliberately
repeatable: **test, verify, patch, test again, verify again.**

## The tool and the published example

- The `php2shell-remediate` program contains **no exploit code and no payload**.
  It classifies a version string and reports remediation. It performs no network
  access and executes no external process.
- Any proof-of-concept published alongside this project demonstrates the
  technique using a **benevolent** action (self-remediation of the flaw it rode
  in on), not a weaponized payload. It is published to advance understanding and
  defense, not to enable misuse.

## Responsible use

This material is provided for lawful security research, defense, and the
remediation of systems the reader is authorized to administer. Using these
techniques against systems you do not own or do not have explicit written
authorization to test may be illegal in your jurisdiction. The reader is
responsible for ensuring their own conduct is lawful.

## No warranty

The software is provided under the BSD-2-Clause license, "as is" and without
warranty of any kind. See [../LICENSE](../LICENSE). The author and contributors
accept no liability for any use of this software or these techniques.
