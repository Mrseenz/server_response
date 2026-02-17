#!/usr/bin/env python3
"""ActivationRecord extraction/regeneration/verification helper.

This utility operates only on captured data already present in repository files.
It does not generate new cryptographic signatures.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import plistlib
import re
from pathlib import Path
from typing import Any


def _extract_protocol_plist_from_html(html_text: str) -> dict[str, Any]:
    m = re.search(
        r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>',
        html_text,
        re.S,
    )
    if not m:
        raise ValueError("No protocol plist script block found")
    return plistlib.loads(m.group(1).encode())


def _extract_activation_info_from_request_text(request_text: str) -> dict[str, Any]:
    m = re.search(r"<key>ActivationInfoXML</key>\s*<data>\s*(.*?)\s*</data>", request_text, re.S)
    if not m:
        raise ValueError("ActivationInfoXML not found in request")
    payload = base64.b64decode("".join(m.group(1).split()))
    return plistlib.loads(payload)


def _parse_account_token_kv(account_token_bytes: bytes) -> dict[str, str]:
    text = account_token_bytes.decode("utf-8", errors="replace")
    pairs = re.findall(r'"([^"]+)"\s*=\s*"([^"]*)";', text)
    return {k: v for k, v in pairs}


def extract_activation_record(response_html: Path) -> dict[str, Any]:
    html = response_html.read_text()
    protocol = _extract_protocol_plist_from_html(html)

    if "ActivationRecord" in protocol:
        return protocol["ActivationRecord"]

    if "iphone-activation" in protocol:
        raise ValueError("Response contains iphone-activation ack only, no ActivationRecord")

    raise ValueError("Unsupported protocol plist structure")


def regenerate_activation_record(input_html: Path, output_plist: Path) -> dict[str, Any]:
    """Re-serialize captured ActivationRecord as deterministic binary plist."""
    record = extract_activation_record(input_html)
    payload = plistlib.dumps(record, fmt=plistlib.FMT_BINARY, sort_keys=True)
    output_plist.write_bytes(payload)
    return record


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes_b64__": base64.b64encode(bytes(value)).decode()}
    return str(value)


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=_json_default)


def verify_record_equivalence(original_html: Path, regenerated_plist: Path) -> dict[str, Any]:
    original_record = extract_activation_record(original_html)
    regenerated_record = plistlib.loads(regenerated_plist.read_bytes())

    semantic_match = original_record == regenerated_record
    original_norm = _stable_json(original_record).encode()
    regenerated_norm = _stable_json(regenerated_record).encode()

    keys_to_check = ["AccountTokenSignature", "AccountToken", "DeviceCertificate", "FairPlayKeyData"]
    per_key = {}
    for key in keys_to_check:
        a = original_record.get(key)
        b = regenerated_record.get(key)
        per_key[key] = {
            "present_in_original": key in original_record,
            "present_in_regenerated": key in regenerated_record,
            "byte_match": isinstance(a, (bytes, bytearray)) and isinstance(b, (bytes, bytearray)) and a == b,
            "sha256_original": hashlib.sha256(a).hexdigest() if isinstance(a, (bytes, bytearray)) else None,
            "sha256_regenerated": hashlib.sha256(b).hexdigest() if isinstance(b, (bytes, bytearray)) else None,
        }

    return {
        "semantic_match": semantic_match,
        "normalized_sha256_original": hashlib.sha256(original_norm).hexdigest(),
        "normalized_sha256_regenerated": hashlib.sha256(regenerated_norm).hexdigest(),
        "normalized_match": original_norm == regenerated_norm,
        "per_key": per_key,
    }


def verify_record_binding(request_file: Path, response_html: Path) -> dict[str, Any]:
    request_text = request_file.read_text()
    request_plist = _extract_activation_info_from_request_text(request_text)
    record = extract_activation_record(response_html)

    account_token = record.get("AccountToken")
    if not isinstance(account_token, (bytes, bytearray)):
        raise ValueError("ActivationRecord missing AccountToken bytes")
    token_kv = _parse_account_token_kv(bytes(account_token))

    checks = {
        "ProductType": {
            "request": request_plist.get("DeviceInfo", {}).get("ProductType"),
            "account_token": token_kv.get("ProductType"),
        },
        "UniqueDeviceID": {
            "request": request_plist.get("DeviceID", {}).get("UniqueDeviceID"),
            "account_token": token_kv.get("UniqueDeviceID"),
        },
        "SerialNumber": {
            "request": request_plist.get("DeviceID", {}).get("SerialNumber"),
            "account_token": token_kv.get("SerialNumber"),
        },
        "InternationalMobileEquipmentIdentity": {
            "request": request_plist.get("BasebandRequestInfo", {}).get("InternationalMobileEquipmentIdentity"),
            "account_token": token_kv.get("InternationalMobileEquipmentIdentity"),
        },
        "ActivationRandomness": {
            "request": request_plist.get("ActivationRequestInfo", {}).get("ActivationRandomness"),
            "account_token": token_kv.get("ActivationRandomness"),
        },
    }

    for value in checks.values():
        value["match"] = value["request"] == value["account_token"]

    return {
        "all_checked_fields_match": all(v["match"] for v in checks.values()),
        "checks": checks,
        "account_token_keys_found": sorted(token_kv.keys()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract/regenerate/verify ActivationRecord from captured responses")
    sub = parser.add_subparsers(dest="command", required=True)

    extract_p = sub.add_parser("extract", help="Extract ActivationRecord from captured response HTML")
    extract_p.add_argument("--input", required=True, type=Path)
    extract_p.add_argument("--output", required=True, type=Path)

    regen_p = sub.add_parser("regenerate", help="Regenerate ActivationRecord plist from captured response HTML")
    regen_p.add_argument("--input", required=True, type=Path)
    regen_p.add_argument("--output", required=True, type=Path)

    verify_p = sub.add_parser("verify", help="Verify regenerated plist against original captured response")
    verify_p.add_argument("--original", required=True, type=Path)
    verify_p.add_argument("--regenerated", required=True, type=Path)

    binding_p = sub.add_parser(
        "verify-binding",
        help="Verify that ActivationRecord AccountToken values are bound to ActivationInfoXML request fields",
    )
    binding_p.add_argument("--request", required=True, type=Path)
    binding_p.add_argument("--response", required=True, type=Path)

    args = parser.parse_args()

    if args.command == "extract":
        record = extract_activation_record(args.input)
        args.output.write_text(_stable_json(record))
        print(f"Wrote extracted ActivationRecord JSON to {args.output}")
    elif args.command == "regenerate":
        record = regenerate_activation_record(args.input, args.output)
        print(f"Regenerated ActivationRecord with {len(record.keys())} keys to {args.output}")
    elif args.command == "verify":
        result = verify_record_equivalence(args.original, args.regenerated)
        print(json.dumps(result, indent=2))
    else:
        result = verify_record_binding(args.request, args.response)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
