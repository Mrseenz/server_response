#!/usr/bin/env python3
"""Extract protocol structure from captured iDevice activation traffic."""

from __future__ import annotations

import base64
import json
import plistlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _extract_data_block(text: str, key_name: str) -> bytes:
    m = re.search(rf"<key>{re.escape(key_name)}</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        raise ValueError(f"Missing {key_name}")
    b64 = "".join(m.group(1).split())
    return base64.b64decode(b64)


def analyze_handshake() -> dict:
    req_xml = (ROOT / "4 handshake" / "handshake_request.xml").read_text()
    collection_blob = _extract_data_block(req_xml, "CollectionBlob")
    inner = plistlib.loads(collection_blob)

    resp_json = (ROOT / "4 handshake" / "handshake_response.json").read_text()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(resp_json)
    resp_plist = plistlib.loads(bytes(obj[str(i)] for i in range(len(obj))))

    return {
        "request": {
            "container": "plist",
            "fields": sorted(inner.keys()),
            "IngestBody_length": len(inner["IngestBody"]),
            "X-Apple-Sig-Key_length": len(inner["X-Apple-Sig-Key"]),
            "X-Apple-Signature_length": len(inner["X-Apple-Signature"]),
        },
        "response": {
            "container": "plist",
            "fields": sorted(resp_plist.keys()),
            "serverKP_length": len(resp_plist.get("serverKP", b"")),
            "FDRBlob_length": len(resp_plist.get("FDRBlob", b"")),
            "SUInfo_length": len(resp_plist.get("SUInfo", b"")),
            "HandshakeResponseMessage": resp_plist.get("HandshakeResponseMessage", ""),
        },
    }


def analyze_activation() -> dict:
    req_text = (ROOT / "2 deviceActivation" / "deviceActivation_request.txt").read_text()
    activation_xml = _extract_data_block(req_text, "ActivationInfoXML")
    activation_plist = plistlib.loads(activation_xml)

    resp_html = (ROOT / "2 deviceActivation" / "deviceActivation_response.txt").read_text()
    m = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>', resp_html, re.S)
    response_plist = plistlib.loads(m.group(1).encode()) if m else {}

    act_record = response_plist.get("ActivationRecord", {})

    return {
        "request": {
            "transport": "multipart/form-data",
            "required_form_field": "activation-info",
            "activation_plist_fields": sorted(activation_plist.keys()),
            "ActivationRequestInfo": activation_plist.get("ActivationRequestInfo", {}),
            "DeviceInfo": {
                k: activation_plist.get("DeviceInfo", {}).get(k)
                for k in ["ProductType", "ProductVersion", "BuildVersion", "DeviceClass"]
            },
        },
        "response": {
            "content_type": "text/html with <script type=text/x-apple-plist>",
            "plist_root_fields": sorted(response_plist.keys()),
            "ActivationRecord_fields": sorted(act_record.keys()) if isinstance(act_record, dict) else [],
            "ActivationRecord_binary_lengths": {
                k: len(v)
                for k, v in act_record.items()
                if isinstance(v, (bytes, bytearray))
            }
            if isinstance(act_record, dict)
            else {},
        },
    }


def main() -> None:
    report = {
        "endpoints": {
            "drmHandshake": "https://albert.apple.com/deviceservices/drmHandshake",
            "deviceActivation": "https://albert.apple.com/deviceservices/deviceActivation",
        },
        "handshake": analyze_handshake(),
        "deviceActivation": analyze_activation(),
        "limitations": [
            "Captured responses are signed by Apple and device-specific.",
            "A replay server cannot mint new valid activation records.",
        ],
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
