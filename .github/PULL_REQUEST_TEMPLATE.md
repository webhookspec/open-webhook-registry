## Provider spec PR

**Provider name:**
**Provider slug:**
**Region:** India / Global
**Strategy type:** HMAC / Shared Secret / Asymmetric / JWT / Dataless / mTLS
**Tier required:** Starter / Builder / Scale+ / Enterprise

---

### Checklist

- [ ] Spec validates locally: `python3 tools/validate_specs.py providers/<region>/<slug>.yaml`
- [ ] `test_harness.expected_result` is `verified` for the primary case
- [ ] `test_harness.sample_headers` contains real computed signatures (not placeholders)
- [ ] Run `python3 tools/generate_test_sig.py --provider providers/<region>/<slug>.yaml` to verify signatures match
- [ ] `help_text` for every `customer_field` points to a real, specific location in the provider dashboard
- [ ] `docs_url` links to the provider's webhook verification documentation
- [ ] At least one failure `additional_cases` entry (tampered payload or wrong secret)
- [ ] No production secrets or real API keys in `test_harness`
- [ ] Slug matches filename exactly

### Source

Link to the provider's official webhook verification documentation:

### Notes

Any quirks, gotchas, or non-obvious implementation details about this provider's webhook verification:
