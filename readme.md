# iPhone activation protocol analysis + replay tooling

This repository provides **analysis and replay utilities** for captured iDevice activation traffic.

> ⚠️ Security/legal note: this project does **not** generate Apple-signed activation tickets and is not a bypass tool.

## Tools

- `analyze_capture.py`
  - Discovers capture directories automatically.
  - Decodes nested plist/base64 structures.
  - Summarizes handshake and activation message shapes across captures.

- `activation_server.py`
  - Replays captured responses for:
    - `POST /deviceservices/drmHandshake`
    - `POST /deviceservices/deviceActivation`
  - Supports multiple capture profiles and attempts ProductType-based replay selection.

## Captured protocol structure (high-level)

1. **DRM handshake**
   - Request: XML plist with `CollectionBlob`.
   - Inside `CollectionBlob`: `IngestBody`, `X-Apple-Sig-Key`, `X-Apple-Signature`.
   - Response: XML plist including `serverKP`, `FDRBlob`, `SUInfo`, `HandshakeResponseMessage`.

2. **Device activation**
   - Request: `multipart/form-data` with `activation-info`.
   - `activation-info` contains `ActivationInfoXML` (base64 plist) with device/baseband/cert metadata.
   - Response: HTML containing an embedded plist in `<script type="text/x-apple-plist">`.

## Usage

```bash
python3 analyze_capture.py
python3 activation_server.py --host 0.0.0.0 --port 8080
```

## Limitations

- Apple activation records are cryptographically signed and validated by device-side trust chains.
- Replay can help compatibility testing and protocol research, but cannot mint universally valid tickets.
- Use only in lawful, authorized test/lab environments.


## ActivationRecord regeneration + verification

You can regenerate a deterministic binary plist from the captured `ActivationRecord` and verify it against the original capture:

```bash
python3 activation_record_tool.py regenerate   --input "2 deviceActivation/deviceActivation_response.txt"   --output /tmp/activation_record.plist

python3 activation_record_tool.py verify   --original "2 deviceActivation/deviceActivation_response.txt"   --regenerated /tmp/activation_record.plist
```

Notes:
- This performs structural reserialization from captured data and checks strict semantic equality.
- Signature-bearing fields (e.g. `AccountTokenSignature`) are compared byte-for-byte and hashed for verification.
- No new signatures are produced.


### Request-to-record binding verification

To confirm that core identity values in `ActivationRecord/AccountToken` are derived from the captured activation request (`ActivationInfoXML`), run:

```bash
python3 activation_record_tool.py verify-binding   --request "2 deviceActivation/deviceActivation_request.txt"   --response "2 deviceActivation/deviceActivation_response.txt"
```

This checks fields such as `ProductType`, `UniqueDeviceID`, `SerialNumber`, `InternationalMobileEquipmentIdentity`, and `ActivationRandomness`.


## PHP endpoints

The repository now includes protocol-compatible replay endpoints:

- `DRMhandshake.php` → replays captured `drmHandshake` plist response.
- `ideviceactivation.php` → replays captured `deviceActivation` HTML/plist response.

Example with PHP built-in server:

```bash
php -S 0.0.0.0:8080
```

Then call:

- `POST /DRMhandshake.php`
- `POST /ideviceactivation.php`

These scripts replay captured artifacts and do not mint new cryptographic tickets.
