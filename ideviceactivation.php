<?php

declare(strict_types=1);

/**
 * iDevice activation replay endpoint.
 *
 * Analysis/replay only: returns captured activation HTML with embedded plist.
 * Does not generate or forge cryptographic activation records.
 */

header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
header('Connection: close');
header('Content-Type: text/html');

function readBody(): string
{
    $body = file_get_contents('php://input');
    return $body === false ? '' : $body;
}

function loadActivationHtml(string $repoRoot, string $path): ?string
{
    $full = $repoRoot . '/' . $path;
    if (!file_exists($full)) {
        return null;
    }
    $content = file_get_contents($full);
    return $content === false ? null : $content;
}

function selectActivationResponse(string $repoRoot, string $requestBody): string
{
    $postActivationInfo = isset($_POST['activation-info']) ? (string) $_POST['activation-info'] : '';

    $hasActivationInfo = $postActivationInfo !== '' || preg_match('/name="activation-info"/i', $requestBody) === 1;
    $hasActivationInfoXml = preg_match('/ActivationInfoXML/i', $requestBody) === 1 || preg_match('/ActivationInfoXML/i', $postActivationInfo) === 1;

    // Try ProductType-aware profile selection first.
    $productType = null;
    $searchBlob = $postActivationInfo !== '' ? $postActivationInfo : $requestBody;
    if (preg_match('/<key>ProductType<\/key>\s*<string>([^<]+)<\/string>/i', $searchBlob, $m) === 1) {
        $productType = $m[1];
    }

    if ($productType !== null && strcasecmp($productType, 'iPhone9,3') === 0) {
        $profileHtml = loadActivationHtml($repoRoot, '2 deviceActivation/deviceActivation_response.txt');
        if ($profileHtml !== null) {
            return $profileHtml;
        }
    }

    if ($hasActivationInfo && $hasActivationInfoXml) {
        $success = loadActivationHtml($repoRoot, '2 deviceActivation/deviceActivation_response.txt');
        if ($success !== null) {
            return $success;
        }
    }

    $fallback = loadActivationHtml($repoRoot, '5 deviceActivation/deviceActivation_response.txt');
    if ($fallback !== null) {
        return $fallback;
    }

    http_response_code(500);
    return 'Missing activation response captures.';
}

$repoRoot = __DIR__;
$requestBody = readBody();
echo selectActivationResponse($repoRoot, $requestBody);
