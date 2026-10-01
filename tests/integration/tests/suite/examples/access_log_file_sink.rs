// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Praxis Contributors

//! Tests for the access log file sink example configuration.

use std::{collections::HashMap, thread::sleep, time::Duration};

use praxis_core::config::Config;
use praxis_test_utils::{
    allow_loopback_endpoints, example_config_path, free_port, http_send, parse_status, patch_yaml,
    start_backend_with_shutdown, start_proxy,
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Read a file, retrying briefly so the asynchronous response-phase emit has
/// time to flush its line before the assertion runs.
fn read_with_retry(path: &std::path::Path) -> String {
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        sleep(Duration::from_millis(20));
    }
    std::fs::read_to_string(path).unwrap_or_default()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn access_log_file_sink() {
    let backend_port_guard = start_backend_with_shutdown("logged");
    let backend_port = backend_port_guard.port();
    let proxy_port = free_port();

    // Point the file sink at a unique temp path so the test is isolated and
    // self-cleaning; the example ships a fixed `/tmp` path for operators.
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("access.log");
    let yaml =
        std::fs::read_to_string(example_config_path("observability/access-log-file-sink.yaml")).expect("read example");
    let yaml = yaml.replace("/tmp/praxis-access.log", log_path.to_str().expect("utf8 path"));
    let patched = allow_loopback_endpoints(&patch_yaml(
        &yaml,
        proxy_port,
        &HashMap::from([("127.0.0.1:3000", backend_port)]),
    ));
    let config = Config::from_yaml(&patched).expect("parse patched config");
    let proxy = start_proxy(&config);

    let raw = http_send(
        proxy.addr(),
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(parse_status(&raw), 200, "file sink should not disrupt proxying");

    // The file sink writes one NDJSON record per request. Prove the feature
    // end-to-end by parsing the written line back into a JSON object carrying
    // the configured fields with real per-request values.
    let contents = read_with_retry(&log_path);
    let line = contents.lines().next().expect("file sink should write one NDJSON line");
    let record: HashMap<String, String> = serde_json::from_str(line).expect("line should be valid NDJSON");
    assert_eq!(
        record.get("method").map(String::as_str),
        Some("GET"),
        "record: {record:?}"
    );
    assert_eq!(
        record.get("status").map(String::as_str),
        Some("200"),
        "record: {record:?}"
    );
    assert!(
        record.contains_key("path"),
        "record should carry the configured path field: {record:?}"
    );
    assert!(
        record.get("request_id").is_some_and(|id| !id.is_empty()),
        "record should carry the id promoted by the request_id filter: {record:?}"
    );
}
