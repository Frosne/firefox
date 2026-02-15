# WAICT (Web Application Integrity Content-Type) Tests

This directory contains Web Platform Tests for the WAICT specification, which provides integrity checking for web resources through manifest-based hash verification.

## Test Files

### Image Tests
- **`image-enforce.https.html`** - Tests image loading with WAICT policy in enforce mode (blocks non-compliant resources)
- **`image-report.https.html`** - Tests image loading with WAICT policy in report mode (allows resources but reports violations)

### Script Tests
- **`script-enforce.https.html`** - Tests script loading with WAICT policy in enforce mode
- **`script-report.https.html`** - Tests script loading with WAICT policy in report mode

## Test Scenarios

Each test suite covers the following scenarios:

### Common Scenarios (Images & Scripts)
1. **Correct hash in hashes section** - Resource with matching hash in manifest's `hashes` section should load without generating violation reports
2. **Incorrect hash in hashes section** - Resource with non-matching hash should:
   - In enforce mode: fail to load and generate violation report
   - In report mode: load successfully but generate violation report
3. **Correct hash in any_hashes section** - Resource with matching hash in manifest's `any_hashes` (wildcard) section should load without generating violation reports
4. **Incorrect hash in any_hashes section** - Resource with non-matching hash in wildcards should:
   - In enforce mode: fail to load and generate violation report
   - In report mode: load successfully but generate violation report
5. **Resource not in manifest** - Resource not listed in manifest at all should:
   - In enforce mode: fail to load and generate violation report
   - In report mode: load successfully but generate violation report

### Policy Validation Scenarios (tested with scripts)
These scenarios test WAICT policy and manifest validation. While they apply to all resource types, they are currently only tested with scripts.

6. **Missing integrity-policy field** - Manifest without required `integrity-policy` field should:
   - In enforce mode: block resource and generate violation report
   - In report mode: allow resource to load and generate violation report
7. **Missing mode parameter** - Header missing required `mode` parameter should:
   - WAICT is disabled: resource loads normally without any reports

## Running the Tests

Tests can be run using the standard WPT test runner:

```bash
./mach wpt testing/web-platform/tests/waict/
```

To run specific test files:

```bash
./mach wpt testing/web-platform/tests/waict/image-enforce.https.html
./mach wpt testing/web-platform/tests/waict/script-report.https.html
```

## Test Modes

- **Enforce mode** (`mode=enforce`): Resources that fail integrity checks are blocked from loading
- **Report mode** (`mode=report`): Resources that fail integrity checks are allowed to load but violations are reported via the Reporting API

## Notes

- Image tests use ReportingObserver in the main document context
- Script tests use iframes with ReportingObserver to isolate policy contexts
- All tests use HTTPS as WAICT requires secure contexts
- Tests verify both loading behavior and integrity violation reporting
