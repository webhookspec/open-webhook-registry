#!/usr/bin/env python3
"""
AparHub Webhook Provider Spec — Test Signature Generator

Computes the expected signature for a provider spec's test harness.
Run this when creating a new spec to generate the correct expected_signature value.

Usage:
    python3 generate_test_sig.py --provider providers/india/razorpay.yaml

The tool reads the spec, extracts the strategy params, and computes
the expected HMAC digest using the test_harness values.

For asymmetric/JWT providers, it outputs the signing input bytes
so you can compute the signature with your test key pair externally.
"""

import sys
import hmac
import hashlib
import base64
import yaml
import json
import re
import argparse
import pathlib
from typing import Any


def evaluate_cel_simple(expr: str, context: dict) -> str:
    """
    Simplified CEL evaluator for the subset of expressions used in provider specs.

    Supported conventions:
      request.body                           — raw request body
      request.method                         — HTTP method string
      request.url                            — full URL string
      request.headers['name'][0]             — header value (lowercase name)
      request.form['field']                  — URL-encoded form field value (decoded)
      request.form_sorted                    — sorted key+value concat for Twilio-style signing
      params.<name>                          — non-secret customer field
      params.secrets.<name>                  — secret customer field
      base64_encode(x)                       — base64 encode
      crc32(x)                               — CRC32 as string
      int(x)                                 — pass-through (value already a string)
      .trimPrefix('p') / .split() etc.       — standard string ops

    Legacy (still accepted for backward compat):
      raw_body                               — alias for request.body
      header('Name')                         — alias for request.headers['name'][0]
      request_method / request_uri           — legacy aliases
      body_field('f')                        — alias for request.form['f']
    """
    expr = expr.strip()

    # request.body / raw_body
    if expr in ("request.body", "raw_body"):
        return context.get("body", context.get("raw_body", ""))

    # request.method / request_method
    if expr in ("request.method", "request_method"):
        return context.get("method", "POST")

    # request.url / request_uri
    if expr in ("request.url", "request_uri"):
        return context.get("url", context.get("sample_url", ""))

    # request.form_sorted  — sorted key+value concat (Twilio)
    if expr == "request.form_sorted":
        from urllib.parse import parse_qsl
        body = context.get("body", context.get("raw_body", ""))
        params = sorted(parse_qsl(body))
        return "".join(k + v for k, v in params)

    # String literal
    if expr.startswith("'") and expr.endswith("'"):
        return expr[1:-1]

    # int(x) — pass-through, value is already a string in this evaluator
    m = re.fullmatch(r"int\((.+)\)", expr)
    if m:
        return evaluate_cel_simple(m.group(1), context)

    # base64_encode(x)
    m = re.fullmatch(r"base64_encode\((.+)\)", expr)
    if m:
        inner = evaluate_cel_simple(m.group(1), context)
        data = inner.encode() if isinstance(inner, str) else inner
        return base64.b64encode(data).decode()

    # crc32(x)
    m = re.fullmatch(r"crc32\((.+)\)", expr)
    if m:
        import binascii
        inner = evaluate_cel_simple(m.group(1), context)
        data = inner.encode() if isinstance(inner, str) else inner
        return str(binascii.crc32(data) & 0xFFFFFFFF)

    # request.headers['name'][0]
    m = re.fullmatch(r"request\.headers\['([^']+)'\]\[0\]", expr)
    if m:
        name = m.group(1).lower()
        headers = context.get("headers", {})
        # Try lowercase key first, then original case
        return headers.get(name, headers.get(m.group(1), ""))

    # request.form['field']  /  body_field('field')
    m = re.fullmatch(r"request\.form\['([^']+)'\]", expr)
    if not m:
        m = re.fullmatch(r"body_field\('([^']+)'\)", expr)
    if m:
        from urllib.parse import parse_qs
        body = context.get("body", context.get("raw_body", ""))
        parsed = parse_qs(body, keep_blank_values=True)
        vals = parsed.get(m.group(1), [""])
        return vals[0]

    # params.secrets.<name>  /  params.<name>
    m = re.fullmatch(r"params\.secrets\.(\w+)", expr)
    if m:
        return context.get("params", {}).get(m.group(1), "")
    m = re.fullmatch(r"params\.(\w+)", expr)
    if m:
        return context.get("params", {}).get(m.group(1), "")

    # header('Name')  — legacy, case-insensitive lookup
    m = re.fullmatch(r"header\('([^']+)'\)", expr)
    if m:
        name_lc = m.group(1).lower()
        headers = context.get("headers", {})
        return headers.get(name_lc, headers.get(m.group(1), ""))

    # .trimPrefix('prefix')
    m = re.match(r"^(.+)\.trimPrefix\('([^']*)'\)$", expr)
    if m:
        val = evaluate_cel_simple(m.group(1), context)
        prefix = m.group(2)
        return val.removeprefix(prefix) if val.startswith(prefix) else val

    # .split(sep).filter(s, s.startsWith(pfx)).first().split(sep2, n)[idx]
    m = re.match(
        r"^(.+)\.split\('([^']*)'\)\.filter\(s,\s*s\.startsWith\('([^']*)'\)\)\.first\(\)\.split\('([^']*)'(?:,\s*(\d+))?\)\[(\d+)\]$",
        expr,
    )
    if m:
        val = evaluate_cel_simple(m.group(1), context)
        sep, prefix, sep2 = m.group(2), m.group(3), m.group(4)
        maxsplit = int(m.group(5)) if m.group(5) else -1
        idx = int(m.group(6))
        filtered = [p for p in val.split(sep) if p.startswith(prefix)]
        if not filtered:
            return ""
        parts2 = filtered[0].split(sep2, maxsplit) if maxsplit > 0 else filtered[0].split(sep2)
        return parts2[idx] if idx < len(parts2) else ""

    # Simple .split('sep')[n]
    m = re.match(r"^(.+)\.split\('([^']*)'\)\[(\d+)\]$", expr)
    if m:
        val = evaluate_cel_simple(m.group(1), context)
        parts = val.split(m.group(2))
        idx = int(m.group(3))
        return parts[idx] if idx < len(parts) else ""

    # String concatenation: split on top-level + only
    parts = split_concat(expr)
    if len(parts) > 1:
        return "".join(evaluate_cel_simple(p.strip(), context) for p in parts)

    return expr  # fallback — return as-is


def split_concat(expr: str) -> list[str]:
    """Split a CEL expression on top-level + operators."""
    parts = []
    depth = 0
    in_string = False
    current = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "'" and not in_string:
            in_string = True
            current.append(c)
        elif c == "'" and in_string:
            in_string = False
            current.append(c)
        elif c in "([" and not in_string:
            depth += 1
            current.append(c)
        elif c in ")]" and not in_string:
            depth -= 1
            current.append(c)
        elif c == "+" and depth == 0 and not in_string:
            parts.append("".join(current))
            current = []
        else:
            current.append(c)
        i += 1
    if current:
        parts.append("".join(current))
    return parts if len(parts) > 1 else [expr]


def compute_hmac(secret: str, data: str, algo: str, encoding: str, secret_encoding: str = "raw") -> str:
    """Compute HMAC and return the digest in the specified encoding."""
    # Decode the secret
    if secret_encoding == "base64":
        # Strip common prefixes (whsec_, etc.)
        raw = secret
        for prefix in ["whsec_", "whsec "]:
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        key = base64.b64decode(raw)
    elif secret_encoding == "hex":
        key = bytes.fromhex(secret)
    else:
        key = secret.encode()

    # Choose hash function
    hash_func = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha1": hashlib.sha1,
    }.get(algo)
    
    if not hash_func:
        raise ValueError(f"Unsupported algo: {algo}")

    data_bytes = data.encode() if isinstance(data, str) else data
    digest = hmac.new(key, data_bytes, hash_func).digest()

    if encoding == "hex":
        return digest.hex()
    elif encoding == "base64":
        return base64.b64encode(digest).decode()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def process_spec(spec_path: pathlib.Path) -> None:
    spec = yaml.safe_load(open(spec_path))
    harness = spec.get("test_harness", {})
    primary = spec.get("verification", {}).get("primary", {})
    strategy_type = primary.get("type")

    print(f"\n{'═' * 60}")
    print(f"  {spec['name']}  ({spec['slug']})")
    print(f"  Strategy: {strategy_type}")
    print(f"{'═' * 60}\n")

    if strategy_type != "hmac":
        print(f"  Strategy '{strategy_type}' requires cryptographic key material beyond this tool.")
        print(f"  For asymmetric/JWT providers, the signing input bytes are:\n")
        
        context = {
            "body": harness.get("sample_payload", ""),
            "raw_body": harness.get("sample_payload", ""),
            "method": "POST",
            "url": harness.get("sample_url", ""),
            "headers": {k.lower(): v for k, v in harness.get("sample_headers", {}).items()},
            "params": {},
        }
        
        signing_input_expr = primary.get("signing_input", "raw_body")
        signing_input = evaluate_cel_simple(signing_input_expr, context)
        print(f"  signing_input = {repr(signing_input[:100])}{'...' if len(signing_input) > 100 else ''}")
        print(f"\n  Use your test private key to sign this and populate expected_signature.")
        return

    # HMAC provider
    test_secret = harness.get("test_secret", "")
    sample_payload = harness.get("sample_payload", "")
    sample_headers = harness.get("sample_headers", {})
    sample_url = harness.get("sample_url", "")
    test_timestamp_unix = harness.get("test_timestamp_unix")

    # Build lowercase header lookup (headers are lowercased in the engine)
    headers_lc = {k.lower(): v for k, v in sample_headers.items()}

    # Determine secret_field name and build params context
    secret_field = primary.get("secret_field", "webhook_secret")
    params_ctx = {secret_field: test_secret}

    context = {
        "body": sample_payload,
        "raw_body": sample_payload,  # legacy alias
        "method": "POST",
        "url": sample_url,
        "sample_url": sample_url,
        "headers": headers_lc,
        "params": params_ctx,
    }

    # Evaluate signing_input
    signing_input_expr = primary.get("signing_input", "request.body")
    if spec.get("standard_webhooks"):
        msg_id = sample_headers.get("webhook-id", "test-msg-id")
        timestamp = sample_headers.get("webhook-timestamp", str(test_timestamp_unix or "1714000000"))
        signing_input = f"{msg_id}.{timestamp}.{sample_payload}"
    else:
        signing_input = evaluate_cel_simple(signing_input_expr, context)

    algo = primary.get("algo", "sha256")
    encoding = primary.get("encoding", "hex")
    secret_encoding = primary.get("secret_encoding", "raw")

    print(f"  test_secret:    {test_secret}")
    print(f"  algo:           {algo}")
    print(f"  encoding:       {encoding}")
    print(f"  secret_encoding:{secret_encoding}")
    print(f"  signing_input:  {repr(signing_input[:120])}{'...' if len(signing_input) > 120 else ''}")
    print()

    try:
        computed = compute_hmac(test_secret, signing_input, algo, encoding, secret_encoding)
        print(f"  Computed digest: {computed}")

        # Show what the sig_value CEL extracts from sample_headers
        sig_val_expr = primary.get("sig_value", "")
        claimed = evaluate_cel_simple(sig_val_expr, context)

        # Apply sig_header_format if present to show expected header value
        sig_fmt = primary.get("sig_header_format", "")
        if sig_fmt and test_timestamp_unix:
            expected_header_val = sig_fmt.replace("{sig}", computed).replace("{ts}", str(test_timestamp_unix))
            print(f"  sig_header_format: {expected_header_val}")
        print(f"  Claimed (from headers): {claimed}")
        
        if claimed == computed:
            print(f"\n  ✓ MATCH — test harness signature is correct")
        elif not claimed:
            print(f"\n  ⚠ No claimed signature in sample_headers — update test_harness.sample_headers")
            print(f"    Set the signature header to: {computed}")
        else:
            print(f"\n  ✗ MISMATCH — update test_harness.sample_headers")
            print(f"    Expected: {computed}")
            print(f"    Got:      {claimed}")
            
            # Generate the correct header entry
            sig_header = _extract_header_name(primary.get("sig_value", ""))
            if sig_header:
                prefix = _extract_prefix(primary.get("sig_value", ""))
                print(f"\n    Update sample_headers:")
                print(f"      {sig_header}: \"{prefix}{computed}\"")

    except Exception as e:
        print(f"  Error computing HMAC: {e}")


def _extract_header_name(sig_value_expr: str) -> str:
    """Extract the header name from a sig_value CEL expression."""
    m = re.search(r"header\('([^']+)'\)", sig_value_expr)
    return m.group(1) if m else ""


def _extract_prefix(sig_value_expr: str) -> str:
    """Detect if a known prefix should be prepended (e.g. sha256=, sha1=, v1=)."""
    # If trimPrefix is called, the stored value doesn't have the prefix
    # Return empty — the prefix is stripped before comparison
    if "trimPrefix" in sig_value_expr:
        m = re.search(r"trimPrefix\('([^']*)'\)", sig_value_expr)
        if m:
            return m.group(1)
    return ""


def main():
    parser = argparse.ArgumentParser(description="Compute expected HMAC signatures for test harnesses")
    parser.add_argument("--provider", required=False, help="Path to provider YAML. If omitted, runs all HMAC providers.")
    args = parser.parse_args()

    if args.provider:
        process_spec(pathlib.Path(args.provider))
    else:
        root = pathlib.Path(__file__).parent.parent
        for spec_path in sorted(root.glob("providers/**/*.yaml")):
            process_spec(spec_path)
    print()


if __name__ == "__main__":
    main()
