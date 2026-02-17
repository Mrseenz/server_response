<?php

declare(strict_types=1);

/**
 * DRM handshake replay endpoint.
 *
 * Analysis/replay only: returns captured plist payloads and does not generate
 * Apple-signed handshake artifacts.
 */

header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
header('Connection: close');
header('Content-Type: application/xml');

function loadHandshakeResponse(string $repoRoot): string
{
    $preferred = $repoRoot . '/4 handshake/handshake_response.json';
    $fallback = $repoRoot . '/1 handshake_headers/handshake_response.json';
    $path = file_exists($preferred) ? $preferred : $fallback;

    if (!file_exists($path)) {
        http_response_code(500);
        return 'Missing handshake_response.json capture.';
    }

    $json = file_get_contents($path);
    if ($json === false) {
        http_response_code(500);
        return 'Unable to read handshake response capture.';
    }

    // Some captures contain multiple concatenated JSON objects; consume only the first.
    $firstJson = null;
    if (preg_match('/^\s*(\{.*?\})\s*/s', $json, $m) === 1) {
        $firstJson = $m[1];
    }

    $decoded = is_string($firstJson) ? json_decode($firstJson, true) : null;
    if (!is_array($decoded)) {
        http_response_code(500);
        return 'Invalid handshake response capture format.';
    }

    $bytes = '';
    for ($i = 0; array_key_exists((string) $i, $decoded); $i++) {
        $byte = (int) $decoded[(string) $i];
        $bytes .= chr($byte);
    }

    return $bytes;
}

$repoRoot = __DIR__;
echo loadHandshakeResponse($repoRoot);
