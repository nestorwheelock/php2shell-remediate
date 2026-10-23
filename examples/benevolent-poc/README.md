# Benevolent proof-of-concept: an intrusion that closes its own door

This example demonstrates the central idea of the accompanying article: the same
reachable code path that an attacker would use to run a payload can instead
carry a **remediation**. Here the deserialization reached through PHP's
`session.upload_progress` handler delivers an object whose only effect is to
write a per-directory `.user.ini` that **disables the vulnerable feature**. The
demonstration secures the very door it came through.

**The useful part: you can test whether your system is exposed by *securing* it,
in the same step, before a vendor patch is even applied.** The demonstration is
at once the test — it reaches the destructor only if the flaw is live — and a
mitigation — it leaves the vulnerable feature disabled. A negative result means
nothing happened; a positive result means the exposure is now smaller than it
was a moment ago. That is a check you can safely run on a system you care about.

It runs code through the flaw, so it is a real demonstration of reachability —
but the action is harmless by construction: it writes one protective
configuration line and nothing else.

## WARNING — READ THIS FIRST

**For educational use, against your own lab only.**

- Run it only against a system you own and operate. The driver refuses to run
  without the `--i-own-this-system` flag and targets only `127.0.0.1`; the gadget
  refuses to act unless you have placed an authorization sentinel file,
  `.benevolent-poc-authorized`, in the trigger directory. On any system without
  that file the gadget does nothing at all, even if the deserialization path is
  reached. (A loopback-address check was tried first and rejected: inside a jail
  or behind a proxy, `127.0.0.1` is remapped, so an address check is brittle.)
- **Benevolent intent is not a legal defense.** Reaching into a system you do
  not own — even to fix it — is unauthorized access and can be prosecuted. If it
  is not yours, report it; do not touch it. See [../../docs/DISCLAIMER.md](../../docs/DISCLAIMER.md).

## What it shows (and the lab it assumes)

The reproduction lab is the two-context setup described in
[../../docs/METHODOLOGY.md](../../docs/METHODOLOGY.md):

- An **upload** directory whose `.user.ini` pins
  `session.serialize_handler = php_serialize`, with a script that does **not**
  call `session_start()`. A `PHP_SESSION_UPLOAD_PROGRESS` request writes the
  progress entry — carrying a `|` inside the uploaded filename — into the
  session file under the `php_serialize` handler.
- A **trigger** directory whose `.user.ini` pins
  `session.serialize_handler = php` and whose script calls `session_start()`.
  Reading the same session file under the `php` handler splits at the first `|`
  and deserializes the right-hand side, instantiating the named object and
  running its destructor.

In a real application the destructor-bearing class is an existing application
gadget. Here it is `UploadProgressContainment`, whose destructor performs the
remediation.

## Files

- `benevolent-upload.php` — the upload-context endpoint (no `session_start()`).
- `benevolent-trigger.php` — the trigger-context endpoint; defines the
  benevolent gadget and calls `session_start()`.
- `fire-benevolent.php` — the driver: plants the payload via one
  `PHP_SESSION_UPLOAD_PROGRESS` request, then reads the trigger endpoint.

## Preconditions

- `session.use_strict_mode = 0` (so an attacker-chosen session id is accepted)
  and `session.upload_progress.enabled = On` — both PHP defaults.
- `session.upload_progress.cleanup = Off` for this complete-upload form. With
  the default `On`, PHP reaps the progress entry when the upload finishes, so
  the payload is gone before the trigger reads it. (Defeating the default `On`
  requires a stalled-delivery variant that holds the upload open; that is out of
  scope for this benign demonstration.)
- The two directory contexts with their `.user.ini` serialize-handler settings
  described above.

## Run (own lab only)

1. Place the two endpoints in their directories with the `.user.ini` settings
   above.
2. **Authorize** the demonstration by creating the sentinel in the trigger
   directory — without it the gadget no-ops:
   ```
   touch /path/to/trigger/.benevolent-poc-authorized
   ```
3. Run the driver:
   ```
   php fire-benevolent.php --i-own-this-system /upload/benevolent-upload.php /trigger/benevolent-trigger.php
   ```

On success the trigger request's destructor appends
`session.upload_progress.enabled=0` to the `.user.ini` in the trigger directory,
closing the feature the demonstration rode in on. Re-run `php2shell-remediate`'s
re-verification probe afterward and the trigger path is gone.

This has been reproduced on a FreeBSD 15 / PHP 8.4 lab: before the run the
trigger `.user.ini` carried only the serialize-handler line; after it carried
the containment line as well, written through the deserialization path.

## Why publish the benevolent form

The mechanism is already public: it is derivable from the vendor fix commit. The
value a defender needs is not a weaponized payload but a worked, safe example of
reaching and then **closing** the path — proof that the flaw is real, shown
without shipping something whose default behavior is harm.

## License

BSD-2-Clause, the same as the rest of the repository. See [../../LICENSE](../../LICENSE).
