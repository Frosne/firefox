# WAICT Max-age Downgrade Protection Tests

This directory contains Web Platform Tests specifically for WAICT max-age downgrade protection functionality. These tests are separated from the main WAICT tests to avoid max-age cache interference.

## Why a Separate Directory?

WAICT max-age protection is **origin-wide** and persists across page loads within the max-age period. When tests with `max-age > 0` run alongside other tests, they can cause interference:
- Tests that set max-age protection can block subsequent tests that don't have WAICT headers
- This leads to `corruptedContentErrorv2` errors and test failures

By running these tests separately, we ensure:
1. Clean test execution without interference from other WAICT tests
2. Proper testing of max-age downgrade protection behavior
3. Reliable results regardless of test execution order

## Test Files

- **`image-max-age-downgrade-enforce.https.html`** - Tests that document load is blocked when WAICT header is removed during max-age period (enforce mode)
  - Phase 1: Load with WAICT header (mode=enforce, max-age=2), verify image blocked
  - Phase 2: Try to load WITHOUT header (within max-age), expect document load to fail
  - This tests downgrade protection in enforce mode - blocks when WAICT header is removed

- **`image-max-age-downgrade-report-mode.https.html`** - Tests that document load succeeds with violation report when WAICT header is removed (report mode)
  - Phase 1: Load with WAICT header (mode=report, max-age=90), verify image loads (report mode)
  - Phase 2: Try to load WITHOUT header (within max-age), expect document load to SUCCEED but generate violation report
  - This tests downgrade protection in report mode - allows load but reports violation

- **`image-max-age-persist.https.html`** - Tests that WAICT policy persists when header continues to be sent
  - Phase 1: Load with WAICT header (max-age=2), verify image blocked
  - Phase 2: Load WITH WAICT header again (within max-age), verify policy still applies
  - This tests that the policy continues to work when properly maintained

- **`image-max-age-expire.https.html`** - Tests that WAICT policy expires after max-age period
  - Phase 1: Load with WAICT header (max-age=1), verify image blocked
  - Wait 2+ seconds for expiration
  - Phase 2: Load without header, verify image now loads (policy expired)
  - This tests that downgrade protection properly expires

## Running the Tests

Run these tests separately from the main WAICT tests:

```bash
# Run all max-age downgrade protection tests
./mach wpt testing/web-platform/tests/waict-downgrade-protection/

# Run a specific test
./mach wpt testing/web-platform/tests/waict-downgrade-protection/image-max-age-persist.https.html
```

**Do not run these together with main WAICT tests** (`testing/web-platform/tests/waict/`) as they will interfere with each other.

## Technical Details

### Max-age Behavior
- **max-age** parameter defines how long (in seconds) clients should enforce WAICT downgrade protection
- Protection is stored per origin (host-based, not per-path)
- When a URI has active max-age protection:
  - Subsequent loads WITH a WAICT header: allowed (policy is updated/continued)
  - Subsequent loads WITHOUT a WAICT header (downgrade protection):
    - **Enforce mode**: Document load is **blocked**
    - **Report mode**: Document load **succeeds** but generates a violation report

### Resource Dependencies
These tests use resources from the main WAICT directory:
- `../waict/resources/waict-max-age.py` - Python handler that serves pages with/without WAICT headers
- `../waict/resources/waict-test-helpers.js` - Helper functions for WAICT tests
- `../waict/resources/waict-manifest.json` - Manifest with resource hashes

### Test Configuration
- Tests require `security.waict.enabled:true` (set in `testing/web-platform/meta/waict-downgrade-protection/__dir__.ini`)
- Tests use HTTPS (required for WAICT)
- Each test is self-contained with its own iframe loads

## Notes

- These tests use short max-age values (1-2 seconds) to allow tests to complete quickly
- Tests include waits between phases to allow for proper timing
- The main WAICT tests (in `../waict/`) use `max-age=0` to avoid interference
