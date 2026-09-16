use std::{net::TcpListener, process::Command};

#[test]
fn diagnostic_retrieval_failure_returns_json_and_a_failure_exit_code() {
    // Keep the port reserved without responding, so the request deadline fires.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = format!("http://{}", listener.local_addr().unwrap());
    let id = "99BUQ6ek1UJnAt3eTp_4dEHM3Isc3hZquixMmJ_5vF0";
    let mut command = Command::new(env!("CARGO_BIN_EXE_ar-io-gateway"));
    command.env_clear();
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    let output = command
        .args(["diagnose", id])
        .env("ARWEAVE_NODE_URL", &source)
        .env("ARWEAVE_ARCHIVE_URL", &source)
        .env("ARWEAVE_CHUNK_SOURCES", &source)
        .env("ARWEAVE_GRAPHQL_URLS", format!("{source}/graphql"))
        .env("ARWEAVE_REQUEST_TIMEOUT_SECS", "1")
        .env("ARWEAVE_RETRIEVAL_TIMEOUT_SECS", "2")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "failed");
    assert_eq!(report["resolved_id"], id);
    assert!(report["content"].is_null());
    assert!(
        report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["stage"] == "verified_retrieval" && step["status"] != "passed")
    );
}

#[tokio::test]
async fn public_id_diagnostic_returns_a_report_without_crashing_the_server() {
    use std::io::BufRead;
    use std::process::Stdio;
    use std::time::Duration;

    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let source = format!("http://{}", upstream.local_addr().unwrap());
    let mut command = Command::new(env!("CARGO_BIN_EXE_ar-io-gateway"));
    command.env_clear();
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    let mut child = command
        .arg("serve")
        .env("AR_IO_LISTEN_ADDR", "127.0.0.1:0")
        .env("ARWEAVE_NODE_URL", &source)
        .env("ARWEAVE_ARCHIVE_URL", &source)
        .env("ARWEAVE_CHUNK_SOURCES", &source)
        .env("ARWEAVE_GRAPHQL_URLS", format!("{source}/graphql"))
        .env("SOLANA_RPC_URL", &source)
        .env("ARWEAVE_REQUEST_TIMEOUT_SECS", "1")
        .env("ARWEAVE_RETRIEVAL_TIMEOUT_SECS", "2")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let url = format!(
        "{}/ar-io/diagnostics/run",
        line.trim().trim_start_matches("listening on ")
    );
    let id = "99BUQ6ek1UJnAt3eTp_4dEHM3Isc3hZquixMmJ_5vF0";
    let result = async {
        reqwest::Client::new()
            .post(url)
            .timeout(Duration::from_secs(10))
            .json(&serde_json::json!({"input": id}))
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await
    }
    .await;
    let running = child.try_wait().unwrap().is_none();
    if running {
        child.kill().unwrap();
    }
    child.wait().unwrap();
    assert!(running, "diagnostic crashed the gateway");
    let report = result.unwrap();
    assert_eq!(report["resolved_id"], id);
    assert_eq!(report["status"], "failed");
    assert!(report["content"].is_null());
    assert!(
        report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["stage"] == "verified_retrieval")
    );
}
