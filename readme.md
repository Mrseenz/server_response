# iPhone activation protocol notes + replay server

This repository now contains:

- `analyze_capture.py`: parses the captured request/response files and prints a protocol summary.
- `build_activation_artifacts.py`: extracts Apple-signed handshake and activation cryptographic artifacts into files for offline analysis.
- `activation_server.py`: HTTP server that replays captured handshake responses and mints regenerated activation records/certificates for activation responses.

## What the capture shows

1. **DRM handshake**
   - Endpoint: `POST /deviceservices/drmHandshake`
   - Request body: XML plist containing `CollectionBlob` (base64 plist with `IngestBody`, `X-Apple-Sig-Key`, `X-Apple-Signature`).
   - Response body: XML plist with fields including `serverKP`, `FDRBlob`, `SUInfo`, `HandshakeResponseMessage`.

2. **Device activation**
   - Endpoint: `POST /deviceservices/deviceActivation`
   - Request body: `multipart/form-data` with `activation-info` form field.
   - `activation-info` includes `ActivationInfoXML` (base64 plist) with device/baseband/certificate info.
   - Response body: HTML that embeds a plist in:
     - `<script id="protocol" type="text/x-apple-plist">...`.

3. **Regenerated activation artifacts**
   - For each activation request, `activation_server.py` parses `ActivationInfoXML` and mints a new activation payload with:
     - Newly issued local-lab certificates for `AccountTokenCertificate`, `DeviceCertificate`, and `UniqueDeviceCertificate`.
     - Freshly signed `AccountTokenSignature` over generated `AccountToken` JSON.
     - Regenerated `FairPlayKeyData` container and request-derived regulatory metadata.
   - Local CA material is persisted under `artifacts/local_ca` and reused across requests.

## Important limitation

The regenerated artifacts are cryptographically valid for the local lab CA, **not Apple-trusted activation tickets**. Real devices that enforce Apple trust anchors will still reject non-Apple signatures.

## Usage

### 1) Analyze the captures

```bash
python analyze_capture.py
```

### 2) Build activation cryptographic artifacts from captures

```bash
python build_activation_artifacts.py
```

Default output directory:

- `artifacts/apple_crypto`

### 3) Run replay + regeneration server

```bash
python activation_server.py --host 0.0.0.0 --port 8080
```

Endpoints served:

- `POST /deviceservices/drmHandshake` → returns captured handshake plist.
- `POST /deviceservices/deviceActivation` → parses request and returns a freshly minted activation HTML/plist response with regenerated certificates/signatures.

## Notes for real-device testing

If you test against real devices, route the device traffic to this server in a controlled lab setup only. Activation still requires Apple-trusted signatures for production success.
