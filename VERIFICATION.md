# Reproducible metrics (pytest)

Sigma rules and enrichment CSVs are validated in code. Mixed-event simulations use **synthetic** Intune-style fields, not your production tenant.

## Command

```bash
pip install pyyaml pytest
pytest tests/ -v -s
```

## What is tested

- Six YAML rules: required Sigma fields and MITRE `attack.t*` tags.
- Per rule: three benign and three malicious synthetic cases.
- `intune_mass_device_wipe`: naive “count &gt; 50” vs enriched logic using `enrichment/admin_baseline.csv` (KV-style baseline).

**Interview line:** “Numbers on my resume for this pack trace to `tests/test_rules.py`; run pytest and you get the same outputs.”
