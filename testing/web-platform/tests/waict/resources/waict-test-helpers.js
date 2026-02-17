// Helper functions for WAICT tests

// Helper function to set up ReportingObserver for integrity violations
// Used by image tests (resources loaded in main document)
// For script tests, ReportingObserver is set up inside iframes
// Pass t (test object) if you want cleanup, omit for no cleanup (e.g., in iframes)
function setupIntegrityViolationObserver(t = null) {
  const reports = [];
  const observer = new ReportingObserver((reportList) => {
    reports.push(...reportList);
  }, {types: ['integrity-violation']});
  observer.observe();
  // Cleanup is needed for image tests to prevent observers from previous tests
  // interfering with subsequent tests. Not needed for iframes since they're
  // destroyed after each test.
  if (t && t.add_cleanup) {
    t.add_cleanup(() => observer.disconnect());
  }
  return reports;
}

// Check integrity violation report
// Verifies report type, blocked URL, reportOnly flag, and optionally the violation reason
// Reason values: "manifest_unavailable", "invalid_manifest", "missing_from_manifest", "no_manifest_match", etc.
function checkIntegrityViolationReport(reports, expectedURL, reportOnly, reason) {
  assert_equals(reports.length, 1, 'Should generate exactly one integrity violation report');
  const report = reports[0];
  assert_equals(report.type, 'integrity-violation', 'Report type should be integrity-violation');
  assert_true(report.body.blockedURL.includes(expectedURL), 'Report should reference the blocked resource');
  assert_equals(report.body.reportOnly, reportOnly, reportOnly ? 'Report should be report-only' : 'Report should not be report-only');

  // Check reason if provided
  if (reason !== undefined) {
    assert_equals(report.body.reason, reason, `Report should have reason: ${reason}`);
  }
}

async function loadScriptInIframe(iframeSrc, scriptSrc) {
  const iframe = document.createElement('iframe');
  iframe.src = iframeSrc;

  const readyPromise = new Promise(resolve => {
    window.addEventListener('message', function handler(event) {
      if (event.data.type === 'ready') {
        window.removeEventListener('message', handler);
        resolve();
      }
    });
  });

  document.body.appendChild(iframe);
  await readyPromise;

  // Request script load and wait for result
  const resultPromise = new Promise(resolve => {
    window.addEventListener('message', function handler(event) {
      if (event.data.type === 'scriptResult') {
        window.removeEventListener('message', handler);
        resolve(event.data);
      }
    });
  });

  iframe.contentWindow.postMessage({
    action: 'loadScript',
    src: scriptSrc
  }, '*');

  return await resultPromise;
}
