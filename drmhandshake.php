<?php

declare(strict_types=1);

/**
 * Replay captured iDevice DRM handshake response from repository fixtures.
 */

$root = __DIR__;
$source = $root . '/4 handshake/handshake_response.json';

if (!is_file($source)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Missing capture file: {$source}\n";
    exit;
}

$rawJson = file_get_contents($source);
if ($rawJson === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Unable to read capture file: {$source}\n";
    exit;
}

$decoded = json_decode($rawJson, true);
if (!is_array($decoded)) {
    $start = strpos($rawJson, '{');
    if ($start !== false) {
        $length = strlen($rawJson);
        for ($i = $start + 1; $i <= $length; $i++) {
            if ($rawJson[$i - 1] !== '}') {
                continue;
            }
            $candidate = substr($rawJson, $start, $i - $start);
            $parsed = json_decode($candidate, true);
            if (is_array($parsed)) {
                $decoded = $parsed;
                break;
            }
        }
    }
}

if (!is_array($decoded)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Invalid handshake capture JSON\n";
    exit;
}

ksort($decoded, SORT_NUMERIC);
$binary = '';
foreach ($decoded as $value) {
    $byte = (int)$value;
    if ($byte < 0 || $byte > 255) {
        continue;
    }
    $binary .= chr($byte);
}

header('Content-Type: text/x-xml-plist');
header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
http_response_code(200);
echo $binary;
