# CI Integration Guide

Wardline integrates into CI pipelines via its exit codes and SARIF output.

## Exit Code Reference

| Code | Meaning | CI Action |
|------|---------|-----------|
| 0 | No gate-blocking findings | Pass |
| 1 | ERROR-severity findings present | Fail the build |
| 2 | Configuration error | Fail the build (fix config) |
| 3 | Internal tool error | Fail the build (report bug) |

## GitHub Actions

### Basic: Fail on Findings

```yaml
name: Wardline
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install wardline
      - run: wardline scan src/ --verification-mode
```

### With SARIF Upload (GitHub Code Scanning)

```yaml
name: Wardline
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install wardline
      - name: Run Wardline
        run: wardline scan src/ --verification-mode -o wardline.sarif
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wardline.sarif
        if: always()
```

This uploads findings to the **Security** tab in your repository, where they
appear as code scanning alerts with inline annotations on pull requests.

### With Coverage Threshold

```yaml
      - name: Run Wardline
        run: |
          wardline scan src/ \
            --verification-mode \
            --max-unknown-raw-percent 5.0 \
            -o wardline.sarif
```

This fails the build if more than 5% of scanned files have `UNKNOWN_RAW` taint —
a proxy for annotation coverage.

### Changed Files Only

```yaml
      - name: Run Wardline (changed files)
        run: |
          wardline scan src/ \
            --changed-only \
            --verification-mode
```

Scans only files changed in the current commit or PR. Useful for incremental
adoption — existing violations do not block new PRs.

## GitLab CI

```yaml
wardline:
  stage: test
  image: python:3.12
  script:
    - pip install wardline
    - wardline scan src/ --verification-mode -o wardline.sarif
  artifacts:
    reports:
      sast: wardline.sarif
    when: always
```

GitLab ingests the SARIF file as a SAST report, displaying findings in the
merge request security widget.

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: wardline
        name: wardline scan
        entry: wardline scan
        language: python
        types: [python]
        pass_filenames: false
```

## Tips

- **Use `--verification-mode`** in CI to get deterministic output (no timestamps).
  This makes SARIF output diffable and cacheable.
- **Start with `continue-on-error: true`** during adoption so you can upload
  SARIF without blocking builds, then remove it once findings are triaged.
- **Gate on ERROR only** — WARNING and SUPPRESS findings are non-blocking by
  default. Use `--strict-governance` only when you want governance findings to
  also block.

## Further Reading

- [CLI Reference](../reference/cli.md) — all scan options
- [SARIF Format](../reference/sarif-format.md) — understanding the output
- [Adoption Guide](adoption.md) — incremental adoption strategy
