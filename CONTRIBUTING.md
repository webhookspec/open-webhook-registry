# Contributing

Thank you for contributing to the Open Webhook Registry.

---

## Adding a new provider

### 1. Set up

```bash
git clone https://github.com/<org>/open-webhook-registry
cd open-webhook-registry
pip install jsonschema pyyaml
```

### 2. Create the spec file

```bash
cp providers/global/github.yaml providers/<region>/<slug>.yaml
```

Use `india` for India-first providers (Razorpay, Cashfree, etc.), `global` for everything else.

The slug must be lowercase, hyphen-separated, and match the filename exactly.

### 3. Fill in the spec

Read the [schema](schema/provider-spec.schema.json) and the existing specs for reference.

**The most important fields:**

`verification.primary.signing_input` — the exact bytes that get signed. Read the provider's docs carefully. Common gotchas:
- Some providers sign `timestamp + "." + body` (Stripe), others sign `body` only (GitHub)
- Some use the full URL in the construction (HubSpot)
- Encoding matters — `hex` vs `base64` are different

`verification.primary.sig_value` — how to extract the claimed signature from the request. Include the header name and any prefix stripping (e.g. `sha256=`).

`registration.customer_fields[].help_text` — be specific. "Find this in your dashboard" is not helpful. "Stripe Dashboard → Developers → Webhooks → select webhook → Signing secret" is.

### 4. Generate and verify the test harness signature

```bash
python3 tools/generate_test_sig.py --provider providers/<region>/<slug>.yaml
```

If it shows `✓ MATCH`, the signature in `sample_headers` is correct. If it shows `✗ MISMATCH`, update `sample_headers` with the computed value.

### 5. Validate

```bash
python3 tools/validate_specs.py providers/<region>/<slug>.yaml
```

All checks must pass. CI will run this on your PR automatically.

### 6. Open a PR

Use the PR template. CI runs automatically — if it passes, your spec is mechanically correct.

---

## Rules

**The test harness is mandatory and must have complete failure coverage.** No spec without a passing test harness will be merged.

Every `additional_cases` entry requires a `case_tag`. The validator enforces mandatory coverage per strategy:

| Strategy | Required case_tags |
|---|---|
| `hmac` | `wrong_secret`, `tampered_payload`, `missing_header` |
| `hmac` + `replay_prevention` | above + `expired_timestamp` |
| `shared_secret` | `wrong_secret`, `missing_header` |
| `asymmetric` / `jwt` | `invalid_signature` |
| any + `registration_challenge` | `wrong_verify_token` |

A spec that passes schema validation but is missing required case_tags will be rejected by CI.

**No production secrets.** `test_harness.test_secret` must be a clearly fake value. Never use a real API key, signing secret, or credential.

**Specs must be verifiable.** Every claim in the spec must be traceable to the provider's official documentation. Include `docs_url`.

**One provider per PR.** Easier to review, easier to revert if a provider changes their implementation.

---

## Updating an existing spec

If a provider has changed their webhook implementation, open an issue first with the "Spec is incorrect" template, then open a PR with the fix and a link to the issue.

---

## What makes a good spec

Look at `providers/global/stripe.yaml` for a complex HMAC example with embedded timestamp parsing.
Look at `providers/global/facebook.yaml` for an HMAC + one-time verification challenge example.
Look at `providers/global/paypal.yaml` for an asymmetric (Scale+) example.
Look at `providers/india/razorpay.yaml` for the simplest possible HMAC example.
