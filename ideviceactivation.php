<?php

declare(strict_types=1);

/**
 * iDevice activation endpoint backed by repository captures.
 *
 * - Parses activation requests and decodes ActivationInfoXML.
 * - Builds a response ActivationRecord using extracted captured cert/signature
 *   artifacts while deriving request-specific AccountToken content.
 * - Falls back to the captured failure response if request parsing fails.
 */

$root = __DIR__;
$successCapture = $root . '/2 deviceActivation/deviceActivation_response.txt';
$failureCapture = $root . '/5 deviceActivation/deviceActivation_response.txt';

function fail_500(string $message): never
{
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo $message . "\n";
    exit;
}

function load_capture(string $path): string
{
    if (!is_file($path)) {
        fail_500("Missing capture file: {$path}");
    }

    $content = file_get_contents($path);
    if ($content === false) {
        fail_500("Unable to read capture file: {$path}");
    }

    return $content;
}

function extract_protocol_plist(string $html): ?string
{
    if (preg_match('/<script id="protocol" type="text\/x-apple-plist">\s*(<plist.*?<\/plist>)\s*<\/script>/s', $html, $m) === 1) {
        return $m[1];
    }
    return null;
}

function plist_parse_value(\SimpleXMLElement $node): mixed
{
    $name = $node->getName();

    if ($name === 'dict') {
        $children = $node->children();
        $count = count($children);
        $result = [];
        for ($i = 0; $i < $count; $i += 2) {
            if (!isset($children[$i], $children[$i + 1])) {
                break;
            }
            $keyNode = $children[$i];
            $valueNode = $children[$i + 1];
            if ($keyNode->getName() !== 'key') {
                continue;
            }
            $result[(string)$keyNode] = plist_parse_value($valueNode);
        }
        return $result;
    }

    if ($name === 'array') {
        $result = [];
        foreach ($node->children() as $child) {
            $result[] = plist_parse_value($child);
        }
        return $result;
    }

    if ($name === 'string') {
        return (string)$node;
    }

    if ($name === 'integer') {
        return (int)$node;
    }

    if ($name === 'real') {
        return (float)$node;
    }

    if ($name === 'true') {
        return true;
    }

    if ($name === 'false') {
        return false;
    }

    if ($name === 'data') {
        $clean = preg_replace('/\s+/', '', (string)$node);
        if ($clean === null || $clean === '') {
            return '';
        }
        $decoded = base64_decode($clean, true);
        return $decoded === false ? '' : $decoded;
    }

    if ($name === 'date') {
        return (string)$node;
    }

    return (string)$node;
}

function parse_plist_xml(string $xml): ?array
{
    libxml_use_internal_errors(true);
    $plist = simplexml_load_string($xml);
    if ($plist === false || $plist->getName() !== 'plist') {
        return null;
    }

    $children = $plist->children();
    if (!isset($children[0])) {
        return null;
    }

    $value = plist_parse_value($children[0]);
    return is_array($value) ? $value : null;
}

function xml_escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
}

function plist_write_value(mixed $value): string
{
    if (is_array($value)) {
        $isList = array_keys($value) === range(0, count($value) - 1);
        if ($isList) {
            $xml = '<array>';
            foreach ($value as $item) {
                $xml .= plist_write_value($item);
            }
            $xml .= '</array>';
            return $xml;
        }

        $xml = '<dict>';
        foreach ($value as $k => $v) {
            $xml .= '<key>' . xml_escape((string)$k) . '</key>';
            $xml .= plist_write_value($v);
        }
        $xml .= '</dict>';
        return $xml;
    }

    if (is_bool($value)) {
        return $value ? '<true/>' : '<false/>';
    }

    if (is_int($value)) {
        return '<integer>' . $value . '</integer>';
    }

    if (is_float($value)) {
        return '<real>' . $value . '</real>';
    }

    if ($value instanceof stdClass) {
        return plist_write_value((array)$value);
    }

    if (is_string($value)) {
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value) === 1) {
            return '<data>' . chunk_split(base64_encode($value), 68, "\n") . '</data>';
        }

        $binaryLike = preg_match('/-----BEGIN (CERTIFICATE|CONTAINER|PUBLIC KEY|PRIVATE KEY)-----/m', $value) === 1;
        if ($binaryLike) {
            return '<data>' . chunk_split(base64_encode($value), 68, "\n") . '</data>';
        }

        return '<string>' . xml_escape($value) . '</string>';
    }

    return '<string>' . xml_escape((string)$value) . '</string>';
}

function write_plist_xml(array $rootDict): string
{
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        . "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        . "<plist version=\"1.0\">"
        . plist_write_value($rootDict)
        . '</plist>';
}

function decode_activation_info_xml(string $rawBody): ?array
{
    // Primary form from repository captures: multipart field named activation-info
    if (preg_match('/name="activation-info"\s*\R\s*(<dict>.*?<\/dict>)/s', $rawBody, $m) === 1) {
        $wrapped = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            . '<plist version="1.0">' . $m[1] . '</plist>';

        $container = parse_plist_xml($wrapped);
        if (is_array($container) && isset($container['ActivationInfoXML'])) {
            $inner = $container['ActivationInfoXML'];
            if (is_string($inner) && str_contains($inner, '<plist')) {
                return parse_plist_xml($inner);
            }
            if (is_string($inner) && $inner !== '') {
                return parse_plist_xml($inner);
            }
        }
    }

    // Alternate form: x-www-form-urlencoded activation-info payload.
    parse_str($rawBody, $form);
    if (isset($form['activation-info']) && is_string($form['activation-info'])) {
        $container = parse_plist_xml($form['activation-info']);
        if (is_array($container) && isset($container['ActivationInfoXML']) && is_string($container['ActivationInfoXML'])) {
            return parse_plist_xml($container['ActivationInfoXML']);
        }
    }

    // Fallback: raw plist body directly containing ActivationInfoXML or request dict.
    if (str_contains($rawBody, '<plist')) {
        $rawParsed = parse_plist_xml($rawBody);
        if (is_array($rawParsed)) {
            if (isset($rawParsed['ActivationInfoXML']) && is_string($rawParsed['ActivationInfoXML'])) {
                return parse_plist_xml($rawParsed['ActivationInfoXML']);
            }
            if (isset($rawParsed['DeviceID']) || isset($rawParsed['ActivationRequestInfo'])) {
                return $rawParsed;
            }
        }
    }

    return null;
}

function build_account_token(array $activationInfo): string
{
    $deviceId = isset($activationInfo['DeviceID']) && is_array($activationInfo['DeviceID']) ? $activationInfo['DeviceID'] : [];
    $deviceInfo = isset($activationInfo['DeviceInfo']) && is_array($activationInfo['DeviceInfo']) ? $activationInfo['DeviceInfo'] : [];
    $requestInfo = isset($activationInfo['ActivationRequestInfo']) && is_array($activationInfo['ActivationRequestInfo']) ? $activationInfo['ActivationRequestInfo'] : [];

    $token = [
        'SerialNumber' => (string)($deviceId['SerialNumber'] ?? 'UNKNOWN-SERIAL'),
        'UniqueDeviceID' => (string)($deviceId['UniqueDeviceID'] ?? 'UNKNOWN-UDID'),
        'ProductType' => (string)($deviceInfo['ProductType'] ?? 'UnknownProduct'),
        'BuildVersion' => (string)($deviceInfo['BuildVersion'] ?? 'UnknownBuild'),
        'ActivationRandomness' => (string)($requestInfo['ActivationRandomness'] ?? 'UNKNOWN-RAND'),
        'ActivationState' => (string)($requestInfo['ActivationState'] ?? 'UnknownState'),
        'GeneratedAtUTC' => gmdate('c'),
        'Source' => 'ideviceactivation.php capture-based generator',
    ];

    $json = json_encode($token, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    return $json === false ? '{}' : $json;
}

function render_activation_html(string $plistXml): string
{
    return "<!DOCTYPE html>\n"
        . "<html>\n"
        . "  <head>\n"
        . "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />\n"
        . "    <title>iPhone Activation</title>\n"
        . "    <script id=\"protocol\" type=\"text/x-apple-plist\">{$plistXml}</script>\n"
        . "    <script>\n"
        . "      var protocolElement = document.getElementById('protocol');\n"
        . "      var protocolContent = protocolElement.innerText;\n"
        . "      if (typeof iTunes !== 'undefined' && iTunes.addProtocol) {\n"
        . "        iTunes.addProtocol(protocolContent);\n"
        . "      }\n"
        . "    </script>\n"
        . "  </head>\n"
        . "  <body></body>\n"
        . "</html>\n";
}

$failureResponse = load_capture($failureCapture);
$successResponse = load_capture($successCapture);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$rawBody = file_get_contents('php://input');
if ($rawBody === false) {
    $rawBody = '';
}

$activationInfo = ($method === 'POST') ? decode_activation_info_xml($rawBody) : null;

if (!is_array($activationInfo)) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
    http_response_code(200);
    echo $failureResponse;
    exit;
}

$successPlist = extract_protocol_plist($successResponse);
if (!is_string($successPlist)) {
    // If capture format ever changes, still return known-good capture body.
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
    http_response_code(200);
    echo $successResponse;
    exit;
}

$successPayload = parse_plist_xml($successPlist);
if (!is_array($successPayload) || !isset($successPayload['ActivationRecord']) || !is_array($successPayload['ActivationRecord'])) {
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
    http_response_code(200);
    echo $successResponse;
    exit;
}

$capturedRecord = $successPayload['ActivationRecord'];
$generatedRecord = [
    'unbrick' => true,
    'AccountTokenCertificate' => (string)($capturedRecord['AccountTokenCertificate'] ?? ''),
    'DeviceCertificate' => (string)($capturedRecord['DeviceCertificate'] ?? ''),
    'UniqueDeviceCertificate' => (string)($capturedRecord['UniqueDeviceCertificate'] ?? ''),
    'FairPlayKeyData' => (string)($capturedRecord['FairPlayKeyData'] ?? ''),
    'RegulatoryInfo' => (string)($capturedRecord['RegulatoryInfo'] ?? '{}'),
    'AccountToken' => build_account_token($activationInfo),
    'AccountTokenSignature' => (string)($capturedRecord['AccountTokenSignature'] ?? ''),
];

$payload = ['ActivationRecord' => $generatedRecord];
$plistXml = write_plist_xml($payload);
$responseHtml = render_activation_html($plistXml);

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-cache, no-store, max-age=0, must-revalidate');
http_response_code(200);
echo $responseHtml;
