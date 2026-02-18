# WAICT (Web Application Integrity Content-Type) Tests

This directory contains Web Platform Tests for the WAICT specification, which provides integrity checking for web resources through manifest-based hash verification.

## Test Files

### Image Tests
- **`image-enforce.https.html`** - Tests image loading with WAICT policy in enforce mode (blocks non-compliant resources; reports violations)
- **`image-report.https.html`** - Tests image loading with WAICT policy in report mode (allows resources but reports violations)
- **`image-enforce-invalid-hash.https.html`** - Tests that invalid manifest (hash too long for a resource that's not an image) blocks images when `blocked-destinations=(image)` (enforce mode)
- **`image-report-invalid-hash.https.html`** - Tests that invalid manifest (hash too long for a resource that's not an image) generates reports for images when `blocked-destinations=(image)` (report mode)
- **`image-enforce-nonexistent-manifest.https.html`** - Tests that images are blocked when manifest file doesn't exist (enforce mode)
- **`image-report-nonexistent-manifest.https.html`** - Tests that images load but generate reports when manifest file doesn't exist (report mode)
- **`image-max-age-downgrade-protection.https.html`** - Tests that document load is blocked when WAICT header is removed during max-age period (downgrade protection)
- **`image-max-age-persist.https.html`** - Tests that WAICT policy persists when header continues to be sent during max-age period
- **`image-max-age-expire.https.html`** - Tests that WAICT policy expires after max-age period
- **`image-cross-origin-header-ignored.https.html`** - Tests that WAICT headers from cross-origin are ignored
- **`image-top-level-policy-applies-cross-origin.https.html`** - Tests that top-level WAICT policy applies to resources loaded by cross-origin iframes

### Script (and General) Tests
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

### Policy Validation Scenarios

#### Tested with Scripts
6. **Missing blocked-destinations parameter** - Header missing required `blocked-destinations` parameter should:
   - WAICT is disabled: resource loads normally without any reports
7. **Missing mode parameter** - Header missing required `mode` parameter should:
   - WAICT is disabled: resource loads normally without any reports
8. **Missing optional resource_delimiter field** - Manifest without optional `resource_delimiter` field should:
   - Manifest is valid: resource loads normally without any reports in both modes
9. **Empty blocked-destinations** - Header with empty `blocked-destinations=()` should:
   - No resource types blocked: resource loads normally without any reports in both modes
12. **Missing optional preload field** - Header without optional `preload` field, testing with incorrect hash:
   - WAICT still functions: resource with incorrect hash is blocked in enforce mode, loads with report in report mode

#### Tested with Images
13. **Nonexistent manifest file** - Header with `manifest` pointing to file that doesn't exist:
   - In enforce mode: resource is blocked and generates violation report
   - In report mode: resource loads but generates violation report

#### Tested with Images
10. **Invalid manifest with images** - Tests `image-enforce-invalid-hash.https.html` and `image-report-invalid-hash.https.html`:
   - Header with `blocked-destinations=(image)` and manifest has invalid hash format (too long) for a resource that's not an image
   - Manifest is invalid, affecting resources in blocked-destinations:
     - In enforce mode: image is blocked and generates violation report
     - In report mode: image loads but generates violation report

### Max-age Downgrade Protection (Tested with Images, Enforce Mode)
14. **Downgrade protection blocks document load** - `image-max-age-downgrade-protection.https.html`:
   - Test loads a page with WAICT header (`max-age=90`), verifies image is blocked
   - Then tries to load the same page WITHOUT WAICT header (within 90s)
   - Expected: Document load fails (downgrade protection blocks removal of WAICT header during max-age period)
15. **Policy persists when header continues to be sent** - `image-max-age-persist.https.html`:
   - Test loads a page with WAICT header (`max-age=90`), verifies image is blocked
   - Then loads the same page WITH WAICT header again (within 90s)
   - Expected: Policy continues to apply, image remains blocked
16. **Policy expires after max-age** - `image-max-age-expire.https.html`:
   - Test loads a page with WAICT header (`max-age=1`), verifies image is blocked
   - Waits 2+ seconds, then loads the same page WITHOUT WAICT header
   - Expected: max-age has expired, image now loads normally (no downgrade protection)
### Origin Validation (Tested with Images, Enforce Mode)
17. **Cross-origin WAICT headers are ignored** - `image-cross-origin-header-ignored.https.html`:
   - Spec requirement: "We only care about this header if it's received from a path that matches the top-level origin. E.g. we're on foo.com and this header is set on the response for foo.com/index.html. We want to ignore this header if it's received from another origin, e.g. cdn.com/resource.js."
   - Test loads a cross-origin iframe with WAICT header (enforce mode)
   - Cross-origin iframe tries to load image with incorrect hash
   - Expected: Image loads successfully (cross-origin WAICT header is ignored)

18. **Top-level WAICT policy applies to cross-origin contexts** - `image-top-level-policy-applies-cross-origin.https.html`:
   - Spec requirement: "This information is partitioned to this top level origin and impacts all (active content) resource loads for this top level origin (including sub resources on third-party sites)."
   - Top-level page with WAICT policy, cross-origin iframe loads main-origin image with incorrect hash
   - Expected: Image blocked (top-level policy applies to all resources in page context)

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
