#!/usr/bin/env python3
"""Generate an activation record from captured activation request info.

This script parses the repository's captured activation request payload,
extracts ActivationInfoXML, and builds a new activation record payload that
reuses extracted certificate/signature artifacts from the captured activation
response.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import plistlib
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _extract_activation_info_from_request(request_path: Path) -> dict[str, Any]:
    text = request_path.read_text()

    # activation-info multipart field contains a plist dict with ActivationInfoXML data.
    block = re.search(r'name="activation-info"\s*\n\s*(<dict>.*?</dict>)', text, re.S)
    if not block:
        raise ValueError('Could not locate multipart field "activation-info"')

    dict_xml = block.group(1)
    wrapped = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        f"<plist version=\"1.0\">{dict_xml}</plist>"
    )
    container_plist = plistlib.loads(wrapped.encode())
    encoded_activation_xml = container_plist.get("ActivationInfoXML")
    if not isinstance(encoded_activation_xml, bytes):
        raise ValueError('"ActivationInfoXML" missing or malformed in activation-info payload')

    return plistlib.loads(encoded_activation_xml)


def _extract_captured_activation_record(response_path: Path) -> dict[str, Any]:
    html = response_path.read_text()
    match = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>', html, re.S)
    if not match:
        raise ValueError("Could not locate activation plist in captured response")
    payload = plistlib.loads(match.group(1).encode())
    return payload["ActivationRecord"]


def _build_generated_account_token(activation_info: dict[str, Any]) -> bytes:
    device_id = activation_info.get("DeviceID", {})
    device_info = activation_info.get("DeviceInfo", {})
    req_info = activation_info.get("ActivationRequestInfo", {})

    token = {
        "SerialNumber": str(device_id.get("SerialNumber", "UNKNOWN-SERIAL")),
        "UniqueDeviceID": str(device_id.get("UniqueDeviceID", "UNKNOWN-UDID")),
        "ProductType": str(device_info.get("ProductType", "UnknownProduct")),
        "BuildVersion": str(device_info.get("BuildVersion", "UnknownBuild")),
        "ActivationRandomness": str(req_info.get("ActivationRandomness", "UNKNOWN-RAND")),
        "ActivationState": str(req_info.get("ActivationState", "UnknownState")),
        "GeneratedAtUTC": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
        "Source": "Generated from repository activation request info",
    }
    return json.dumps(token, indent=2, sort_keys=True).encode()


def generate_activation_record(
    request_path: Path,
    response_path: Path,
    output_plist_path: Path,
    output_json_path: Path,
) -> None:
    activation_info = _extract_activation_info_from_request(request_path)
    captured_record = _extract_captured_activation_record(response_path)

    account_token = _build_generated_account_token(activation_info)

    # Reuse extracted certificates/signature directly from captured activation response.
    activation_record = {
        "unbrick": True,
        "AccountTokenCertificate": captured_record["AccountTokenCertificate"],
        "DeviceCertificate": captured_record["DeviceCertificate"],
        "UniqueDeviceCertificate": captured_record["UniqueDeviceCertificate"],
        "FairPlayKeyData": captured_record["FairPlayKeyData"],
        "RegulatoryInfo": captured_record.get("RegulatoryInfo", b"{}"),
        "AccountToken": account_token,
        "AccountTokenSignature": captured_record["AccountTokenSignature"],
    }

    payload = {"ActivationRecord": activation_record}
    output_plist_path.parent.mkdir(parents=True, exist_ok=True)
    output_json_path.parent.mkdir(parents=True, exist_ok=True)

    output_plist_path.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False))

    summary = {
        "request_file": str(request_path.relative_to(ROOT)),
        "response_file": str(response_path.relative_to(ROOT)),
        "output_plist": str(output_plist_path.relative_to(ROOT)),
        "account_token_preview": json.loads(account_token.decode()),
        "certificates_reused": [
            "AccountTokenCertificate",
            "DeviceCertificate",
            "UniqueDeviceCertificate",
        ],
        "signature_reused": "AccountTokenSignature",
        "handshake_material_reference": {
            "source": "4 handshake/handshake_request.xml",
            "keys": ["X-Apple-Sig-Key", "X-Apple-Signature"],
        },
    }
    output_json_path.write_text(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate activation record using extracted cert/signature artifacts")
    parser.add_argument(
        "--request",
        default=str(ROOT / "2 deviceActivation" / "deviceActivation_request.txt"),
        help="Captured activation request file (multipart body)",
    )
    parser.add_argument(
        "--response",
        default=str(ROOT / "2 deviceActivation" / "deviceActivation_response.txt"),
        help="Captured activation response containing source ActivationRecord",
    )
    parser.add_argument(
        "--output-plist",
        default=str(ROOT / "artifacts" / "generated_activation_record.plist"),
        help="Output plist path",
    )
    parser.add_argument(
        "--output-json",
        default=str(ROOT / "artifacts" / "generated_activation_record_summary.json"),
        help="Output JSON summary path",
    )
    args = parser.parse_args()

    generate_activation_record(
        request_path=Path(args.request),
        response_path=Path(args.response),
        output_plist_path=Path(args.output_plist),
        output_json_path=Path(args.output_json),
    )
    print(f"Wrote activation record plist: {args.output_plist}")
    print(f"Wrote generation summary: {args.output_json}")


if __name__ == "__main__":
    main()
