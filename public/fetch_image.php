<?php
require_once __DIR__ . '/../src/config.php';

$url = $_GET['url'] ?? '';

if ($url === '') {
    http_response_code(400);
    echo 'No url provided.';
    exit;
}

// 1) Only absolute http/https URLs. This alone blocks file://, php://,
//    data://, and relative paths like ../src/config.php (which have no scheme).
$parts = parse_url($url);
if ($parts === false || empty($parts['scheme']) || empty($parts['host'])) {
    http_response_code(400);
    echo 'Invalid URL.';
    exit;
}
$scheme = strtolower($parts['scheme']);
if ($scheme !== 'http' && $scheme !== 'https') {
    http_response_code(400);
    echo 'Only http and https URLs are allowed.';
    exit;
}

// 2) Resolve the host and refuse loopback, private, and reserved ranges so the
//    URL cannot be aimed back at the server or the internal network.
$host = $parts['host'];
$ips  = [];
if (filter_var($host, FILTER_VALIDATE_IP)) {
    $ips[] = $host;
} else {
    foreach (array_merge(
        dns_get_record($host, DNS_A) ?: [],
        dns_get_record($host, DNS_AAAA) ?: []
    ) as $r) {
        if (!empty($r['ip']))   { $ips[] = $r['ip']; }
        if (!empty($r['ipv6'])) { $ips[] = $r['ipv6']; }
    }
}
if (!$ips) {
    http_response_code(502);
    echo 'Could not resolve host.';
    exit;
}
foreach ($ips as $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        http_response_code(400);
        echo 'Refusing to fetch a private or local address.';
        exit;
    }
}

// 3) Do not follow redirects — a 3xx to file:// or to an internal host would
//    otherwise bypass the checks above.
$context = stream_context_create([
    'http' => ['timeout' => 5, 'follow_location' => 0, 'max_redirects' => 0],
]);
$data = @file_get_contents($url, false, $context);

if ($data === false) {
    http_response_code(502);
    echo 'Could not fetch the image.';
    exit;
}

// 4) Only serve back content that is actually an image.
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->buffer($data) ?: 'application/octet-stream';
if (strncmp($mime, 'image/', 6) !== 0) {
    http_response_code(415);
    echo 'The URL did not return an image.';
    exit;
}

header('Content-Type: ' . $mime);
echo $data;
