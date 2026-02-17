# iPhone activation protocol notes + replay server

This repository now contains:

- `analyze_capture.py`: parses the captured request/response files and prints a protocol summary.
- `build_activation_artifacts.py`: extracts Apple-signed handshake and activation cryptographic artifacts into files for offline analysis.
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

3. **Cryptographic artifacts now materialized**
   - Handshake artifacts are exported as raw files:
     - `handshake_ingest_body.json`
     - `handshake_sig_key.bin` (decoded `X-Apple-Sig-Key`)
     - `handshake_signature.der` (decoded `X-Apple-Signature`)
   - Activation artifacts are exported as raw files:
     - Apple certificate-like blobs (`AccountTokenCertificate.pem`, `DeviceCertificate.pem`, `UniqueDeviceCertificate.pem`)
     - `FairPlayKeyData.pem` (Apple `CONTAINER` block)
     - `AccountToken.json` and `AccountTokenSignature.bin`
   - A `crypto_report.json` is generated with hashes and parsed certificate summaries.

## Important limitation

This implementation **does not generate valid activation tickets**. Apple-signed activation records are cryptographically signed and generally device-specific. This project is for protocol analysis/replay experiments only.

## Usage

### 1) Analyze the captures

```bash
python analyze_capture.py
```

### 2) Build activation cryptographic artifacts

```bash
python build_activation_artifacts.py
```

Default output directory:

- `artifacts/apple_crypto`

### 3) Run replay server

```bash
python activation_server.py --host 0.0.0.0 --port 8080
```

Endpoints served:

- `POST /deviceservices/drmHandshake` → returns captured handshake plist.
- `POST /deviceservices/deviceActivation` → returns captured activation HTML/plist response.

## Notes for real-device testing

If you test against real devices, route the device traffic to this server in a controlled lab setup only. Activation may still fail unless every cryptographic check is satisfied.
