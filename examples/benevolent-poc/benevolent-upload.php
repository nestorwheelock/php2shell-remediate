<?php
// Upload-context endpoint for the benevolent demonstration. LAB ONLY.
//
// Its directory pins `session.serialize_handler = php_serialize` via a
// per-directory .user.ini. It deliberately does NOT call session_start(): the
// PHP_SESSION_UPLOAD_PROGRESS handler writes the progress entry — carrying the
// payload inside the uploaded filename — into the session file before any user
// code runs. This endpoint's only job is to accept the multipart upload.
http_response_code(204);
