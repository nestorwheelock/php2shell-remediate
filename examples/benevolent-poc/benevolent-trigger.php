<?php
// Trigger-context endpoint for the benevolent demonstration. LAB ONLY.
//
// Its directory pins `session.serialize_handler = php` via a per-directory
// .user.ini. When it reads a session file written under `php_serialize`, the
// default handler splits at the first `|` and deserializes the right-hand side,
// instantiating the named object and running its destructor during var_hash
// cleanup.
//
// The gadget below is the whole point of the demonstration. In a real
// application this role is played by an existing class with a destructor; here
// UploadProgressContainment's destructor performs a REMEDIATION rather than a
// harmful action: it writes a per-directory .user.ini that disables the
// vulnerable session.upload_progress feature. The demonstration is at once the
// test (the destructor runs only if the deserialization path is live) and the
// mitigation (the feature is left disabled). It carries no attacker-controlled
// path and runs no external process.
header('Content-Type: text/plain');

// The directory this remediation protects: the directory of this script. Fixed
// at definition time so the payload cannot steer where anything is written.
define('BENEVOLENT_TARGET_DIR', __DIR__);

class UploadProgressContainment
{
    public function __destruct()
    {
        // Safety gate: act only when the operator has explicitly authorized
        // this demonstration by placing an authorization sentinel in the target
        // directory. Without that file — e.g. on any production system — this
        // does nothing at all, even if the deserialization path is reached and
        // the destructor runs. A sentinel is environment-independent, unlike a
        // loopback address check: behind a reverse proxy, or inside a jail or
        // container where 127.0.0.1 is remapped, the request address is not
        // loopback, so an address check is both brittle and easy to get wrong.
        if (!is_file(BENEVOLENT_TARGET_DIR . '/.benevolent-poc-authorized')) {
            return;
        }
        $ini = BENEVOLENT_TARGET_DIR . '/.user.ini';
        $line = "session.upload_progress.enabled=0\n";
        if (@file_put_contents($ini, $line, FILE_APPEND) !== false) {
            error_log('benevolent-poc: wrote containment to ' . $ini);
        }
    }
}

session_start();
echo "benevolent-trigger: serialize_handler=", ini_get('session.serialize_handler'), "\n";
echo "benevolent-trigger: if the session carried the payload, containment is now written to ",
    BENEVOLENT_TARGET_DIR, "/.user.ini\n";
