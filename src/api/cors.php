<?php
/**
 * DevTalk API extension — Cross-Origin Resource Sharing (CORS) policy.
 *
 * Called once, at the top of public/api/index.php, before any route runs.
 *
 * Background: DevTalk's product team plans a separate JavaScript front end
 * that will be developed at http://localhost:5173 and needs to call this API
 * from that origin. While testing it, a developer kept hitting the browser
 * error "The value of the 'Access-Control-Allow-Origin' header must not be
 * the wildcard '*' when the request's credentials mode is 'include'", and
 * "fixed" it with the code below.
 *
 * LAB 8, PART A: this is the file you fix.
 */

/**
 * Origins allowed to read API responses cross-origin (with credentials).
 * DevTalk's own pages are same-origin and need no entry here.
 */
const API_CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',   // planned separate JavaScript front end
];

function api_cors(): void
{
    // Every API response depends on the Origin header, so tell caches never
    // to serve one origin's CORS headers to another.
    header('Vary: Origin', false);

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // Exact, strict string match against the allowlist. The "null" origin
    // (sandboxed iframes, file:// pages) is never trusted.
    $allowed = $origin !== 'null'
        && in_array($origin, API_CORS_ALLOWED_ORIGINS, true);

    if ($allowed) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
    }

    // Answer CORS preflight requests (sent by the browser before a PATCH,
    // a JSON POST, or any request with an Authorization header). Only an
    // allowed origin gets any Access-Control-* headers back.
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        if ($allowed) {
            header('Access-Control-Allow-Methods: GET, POST, PATCH, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization');
            header('Access-Control-Max-Age: 600');
        }
        http_response_code(204);
        exit;
    }
}
