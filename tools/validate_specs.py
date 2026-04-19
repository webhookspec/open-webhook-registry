#!/usr/bin/env python3
"""
AparHub Webhook Provider Spec — CI Validator

Validates every provider YAML file against the JSON schema.
Checks test harness structure.
Run in CI on every PR to providers/ directory.

Usage:
    python3 validate_specs.py                    # validate all providers
    python3 validate_specs.py providers/india/razorpay.yaml  # validate one
"""

import sys
import json
import yaml
import pathlib
import argparse
from typing import Any

try:
    import jsonschema
except ImportError:
    print("ERROR: pip install jsonschema pyyaml", file=sys.stderr)
    sys.exit(1)

SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "schema" / "provider-spec.schema.json"
PROVIDERS_PATH = pathlib.Path(__file__).parent.parent / "providers"

REQUIRED_CEL_FIELDS_FOR_HMAC = ["sig_value", "signing_input"]
REQUIRED_STRATEGY_TYPES = {"hmac", "shared_secret", "asymmetric", "jwt", "dataless", "mtls"}
VALID_RESULTS = {"verified", "rejected_sig", "rejected_replay", "rejected_challenge"}


def load_schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def load_yaml(path: pathlib.Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def validate_schema(spec: dict, schema: dict, path: pathlib.Path) -> list[str]:
    errors = []
    try:
        jsonschema.validate(spec, schema)
    except jsonschema.ValidationError as e:
        errors.append(f"Schema validation failed at {e.json_path}: {e.message}")
    except jsonschema.SchemaError as e:
        errors.append(f"Invalid schema: {e.message}")
    return errors


def validate_test_harness(spec: dict, path: pathlib.Path) -> list[str]:
    errors = []
    harness = spec.get("test_harness", {})
    primary = spec.get("verification", {}).get("primary", {})
    strategy_type = primary.get("type", "")
    has_replay = bool(spec.get("verification", {}).get("replay_prevention"))
    has_otv = bool(spec.get("verification", {}).get("registration_challenge"))

    if not harness.get("test_secret"):
        errors.append("test_harness.test_secret is empty")

    if not harness.get("sample_payload"):
        errors.append("test_harness.sample_payload is empty")

    if not harness.get("sample_headers"):
        errors.append("test_harness.sample_headers is empty")

    result = harness.get("expected_result")
    if result not in VALID_RESULTS:
        errors.append(f"test_harness.expected_result '{result}' not in {VALID_RESULTS}")

    if result != "verified":
        errors.append("test_harness.expected_result for primary case must be 'verified'")

    # Collect case_tags from additional_cases
    cases = harness.get("additional_cases", [])
    for i, case in enumerate(cases):
        if not case.get("description"):
            errors.append(f"additional_cases[{i}].description is missing")
        if not case.get("mutate"):
            errors.append(f"additional_cases[{i}].mutate is missing")
        if case.get("expected_result") not in VALID_RESULTS:
            errors.append(f"additional_cases[{i}].expected_result invalid")
        if case.get("expected_result") == "verified":
            errors.append(f"additional_cases[{i}] has expected_result='verified' — additional cases must test rejection paths")
        if not case.get("case_tag"):
            errors.append(f"additional_cases[{i}].case_tag is missing — required for coverage enforcement")

    tags = {c.get("case_tag") for c in cases}

    # Mandatory coverage per strategy type
    if strategy_type == "hmac":
        if "wrong_secret" not in tags:
            errors.append("test_harness missing case_tag='wrong_secret' — required for hmac strategy")
        if "tampered_payload" not in tags:
            errors.append("test_harness missing case_tag='tampered_payload' — required for hmac strategy")
        if "missing_header" not in tags:
            errors.append("test_harness missing case_tag='missing_header' — required for hmac strategy")
        if has_replay and "expired_timestamp" not in tags:
            errors.append("test_harness missing case_tag='expired_timestamp' — required when replay_prevention is declared")

    elif strategy_type == "shared_secret":
        if "wrong_secret" not in tags:
            errors.append("test_harness missing case_tag='wrong_secret' — required for shared_secret strategy")
        if "missing_header" not in tags:
            errors.append("test_harness missing case_tag='missing_header' — required for shared_secret strategy")

    elif strategy_type in {"asymmetric", "jwt"}:
        if "invalid_signature" not in tags:
            errors.append(f"test_harness missing case_tag='invalid_signature' — required for {strategy_type} strategy")

    if has_otv and "wrong_verify_token" not in tags:
        errors.append("test_harness missing case_tag='wrong_verify_token' — required when registration_challenge is declared")

    return errors


def validate_strategy(spec: dict, path: pathlib.Path) -> list[str]:
    errors = []
    verification = spec.get("verification", {})
    primary = verification.get("primary", {})
    strategy_type = primary.get("type")

    if strategy_type not in REQUIRED_STRATEGY_TYPES:
        errors.append(f"Unknown strategy type: {strategy_type}")
        return errors

    if strategy_type == "hmac":
        # HMAC must have sig_value. signing_input can be omitted only if standard_webhooks: true
        if not primary.get("sig_value"):
            errors.append("HMAC strategy missing sig_value CEL expression")
        if not primary.get("signing_input") and not spec.get("standard_webhooks"):
            errors.append("HMAC strategy missing signing_input CEL expression (required unless standard_webhooks: true)")

    if strategy_type == "asymmetric":
        if not primary.get("key_source"):
            errors.append("Asymmetric strategy missing key_source")
        if primary.get("key_source") == "jwks_url" and not primary.get("jwks_url"):
            errors.append("Asymmetric key_source=jwks_url but no jwks_url provided")
        if primary.get("key_source") == "cert_url_in_header" and not primary.get("cert_header"):
            errors.append("Asymmetric key_source=cert_url_in_header but no cert_header provided")

    if strategy_type == "jwt":
        if not primary.get("key_source"):
            errors.append("JWT strategy missing key_source")
        if primary.get("key_source") == "jwks_url" and not primary.get("jwks_url"):
            errors.append("JWT key_source=jwks_url but no jwks_url provided")

    # Tier check — asymmetric/jwt/dataless require scale+
    tier = spec.get("tier_required", "starter")
    if strategy_type in {"asymmetric", "jwt", "dataless"} and tier == "starter":
        errors.append(f"Strategy '{strategy_type}' requires tier_required: scale (or higher)")

    if strategy_type == "mtls" and tier not in {"enterprise"}:
        errors.append("mTLS strategy requires tier_required: enterprise")

    return errors


def validate_replay_prevention(spec: dict) -> list[str]:
    errors = []
    rp = spec.get("verification", {}).get("replay_prevention")
    if not rp:
        return errors

    mechanism = rp.get("mechanism")
    if mechanism == "timestamp" and not rp.get("timestamp_value"):
        errors.append("replay_prevention.mechanism=timestamp but no timestamp_value CEL expression")
    if mechanism == "nonce" and not rp.get("nonce_value"):
        errors.append("replay_prevention.mechanism=nonce but no nonce_value CEL expression")

    return errors


def validate_registration_fields(spec: dict) -> list[str]:
    errors = []
    fields = spec.get("registration", {}).get("customer_fields", [])

    if not fields:
        errors.append("registration.customer_fields is empty — at least one field required")

    names = [f.get("name") for f in fields]
    if len(names) != len(set(names)):
        errors.append("Duplicate customer_field names detected")

    for field in fields:
        if field.get("type") == "select" and not field.get("options"):
            errors.append(f"Field '{field.get('name')}' has type=select but no options")
        if not field.get("help_text"):
            errors.append(f"Field '{field.get('name')}' missing help_text — customers need to know where to find this value")

    return errors


def validate_spec(path: pathlib.Path, schema: dict) -> tuple[bool, list[str]]:
    all_errors = []

    try:
        spec = load_yaml(path)
    except yaml.YAMLError as e:
        return False, [f"YAML parse error: {e}"]

    # 1. JSON Schema validation
    all_errors.extend(validate_schema(spec, schema, path))

    # Stop here if schema validation fails — subsequent checks may crash
    if all_errors:
        return False, all_errors

    # 2. Strategy-specific validation
    all_errors.extend(validate_strategy(spec, path))

    # 3. Replay prevention validation
    all_errors.extend(validate_replay_prevention(spec))

    # 4. Registration fields validation
    all_errors.extend(validate_registration_fields(spec))

    # 5. Test harness validation
    all_errors.extend(validate_test_harness(spec, path))

    # 6. Slug matches filename
    slug = spec.get("slug", "")
    expected_slug = path.stem
    if slug != expected_slug:
        all_errors.append(f"slug '{slug}' does not match filename '{expected_slug}.yaml'")

    return len(all_errors) == 0, all_errors


def main():
    parser = argparse.ArgumentParser(description="Validate AparHub webhook provider specs")
    parser.add_argument("files", nargs="*", help="Specific spec files to validate. Validates all if omitted.")
    args = parser.parse_args()

    schema = load_schema()

    if args.files:
        spec_files = [pathlib.Path(f) for f in args.files]
    else:
        spec_files = sorted(PROVIDERS_PATH.rglob("*.yaml"))

    total = 0
    passed = 0
    failed = 0

    for spec_path in spec_files:
        total += 1
        ok, errors = validate_spec(spec_path, schema)

        rel = spec_path.relative_to(pathlib.Path(__file__).parent.parent)
        if ok:
            print(f"  ✓  {rel}")
            passed += 1
        else:
            print(f"  ✗  {rel}")
            for err in errors:
                print(f"       → {err}")
            failed += 1

    print(f"\n{'─' * 50}")
    print(f"  {total} specs  |  {passed} passed  |  {failed} failed")
    print(f"{'─' * 50}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
