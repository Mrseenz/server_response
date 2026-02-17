# iPhone activation protocol notes + replay server

This repository now contains:

- `analyze_capture.py`: parses the captured request/response files and prints a protocol summary.
- `activation_server.py`: a minimal HTTP server that replays captured handshake and activation responses.

## What the capture shows

1. **DRM handshake**
   - Endpoint: `POST /deviceservices/drmHandshake`
   - Request body: XML plist containing `CollectionBlob` (base64 plist with `IngestBody`, `X-Apple-Sig-Key`, `X-Apple-Signature`).
   - Response body: XML plist with fields including `serverKP`, `FDRBlob`, `SUInfo`, `HandshakeResponseMessage`.

2. **Device activation**
   - Endpoint: `POST /deviceservices/deviceActivation`
   - Request body: `multipart/form-data` with `activation-info` form field.
   - `activation-info` includes `ActivationInfoXML` (base64 plist) with device/baseband/certificate info.
   - Response body: HTML that embeds an Apple plist in:
     - `<script id="protocol" type="text/x-apple-plist">...`.
   - Success capture includes an `ActivationRecord` dict with fields like `DeviceCertificate`, `FairPlayKeyData`, `AccountToken`, `AccountTokenSignature`.

## Important limitation

This implementation **does not generate valid activation tickets**. Apple-signed activation records are cryptographically signed and generally device-specific. This project is for protocol analysis/replay experiments only.

## Usage

### 1) Analyze the captures

```bash
python analyze_capture.py
```

### 2) Run replay server

```bash
python activation_server.py --host 0.0.0.0 --port 8080
```

Endpoints served:

- `POST /deviceservices/drmHandshake` → returns captured handshake plist.
- `POST /deviceservices/deviceActivation` → returns captured activation HTML/plist response.

## Notes for real-device testing

If you test against real devices, route the device traffic to this server in a controlled lab setup only. Activation may still fail unless every cryptographic check is satisfied.
