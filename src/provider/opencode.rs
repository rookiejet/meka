//! The OpenCode Go gateway: the request facts its endpoints require, and the usage endpoint
//! `meka account usage` reads.
//!
//! One place for every fact meka sends to or reads from `opencode.ai`, so the three backends that
//! reach it cannot drift. The session header is the product's own requirement, enforced by its
//! gateway, so it is a constant here rather than a config key.

use super::{AccountUsage, UsageWindow};
use crate::error::{MekaError, Result};

/// The two wire facts an OpenCode Go backend carries that its generic protocol sibling does not.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gateway {
    /// The header every inference request must carry: a stable per-conversation id, so the gateway
    /// can route and prompt-cache the session.
    pub(crate) session_header: &'static str,
    /// The user agent every request carries: meka's own name, not a generic HTTP library's.
    pub(crate) user_agent: &'static str,
}

impl Gateway {
    /// The one gateway meka knows: OpenCode Go.
    pub(crate) const GO: Gateway = Gateway {
        session_header: "x-opencode-session",
        user_agent: concat!("meka/", env!("CARGO_PKG_VERSION")),
    };
}

/// Stamp the gateway's request facts onto `request`.
///
/// Nothing is removed: a generic backend passes `None`, and a request without an
/// `attribution.session_id` carries no session value, so a request that reaches these lines sends
/// exactly what it sent before the gateway existed.
pub(crate) fn apply_request_headers(
    mut request: reqwest::RequestBuilder,
    attribution: &crate::provider::Attribution,
    gateway: Option<Gateway>,
) -> reqwest::RequestBuilder {
    let Some(gateway) = gateway else {
        return request;
    };
    if let Some(session_id) = attribution.session_id {
        request = request.header(gateway.session_header, session_id.to_string());
    }
    request.header(reqwest::header::USER_AGENT, gateway.user_agent)
}

/// Fetch an OpenCode Go account's usage: the three dollar-budget windows the subscription has.
///
/// The same API key the inference requests carry; a missing or expired key is the endpoint's
/// 401/403, surfaced like any other provider HTTP error. `url` is the full usage endpoint, which
/// each driver derives from the base URL it stores (the Messages driver keeps its base without a
/// trailing `/v1`, so it re-appends one here).
pub(crate) async fn fetch_usage(
    client: &reqwest::Client,
    url: String,
    api_key: &str,
    gateway: Gateway,
) -> Result<AccountUsage> {
    let response = client
        .get(url)
        .header("Authorization", crate::text::bearer(api_key))
        .header(reqwest::header::USER_AGENT, gateway.user_agent)
        .send()
        .await
        .map_err(|error| {
            crate::error::provider_transport_error("opencode usage request failed", &error, None)
        })?;
    let status = response.status();
    let body = response.text().await.map_err(|error| {
        MekaError::Provider(format!(
            "failed to read the OpenCode Go usage response: {error}"
        ))
    })?;
    if !status.is_success() {
        return Err(crate::error::provider_http_error(
            status,
            &body,
            None,
            crate::error::ProviderRequest::Auxiliary,
        ));
    }
    serde_json::from_str::<UsageWire>(&body)
        .map(UsageWire::into_account_usage)
        .map_err(|error| MekaError::Provider(format!("invalid OpenCode Go usage JSON: {error}")))
}

/// One usage window as OpenCode reports it: how much of a dollar-budget window is spent, and when
/// the window resets. The `status` field is not modeled: a `rate-limited` status is exactly what a
/// 100% `percent` says, and the reset time is what a user acts on.
#[derive(Debug, serde::Deserialize)]
struct WindowWire {
    /// Percent of the window's dollar limit consumed.
    percent: f64,
    /// When the window resets, RFC 3339.
    #[serde(rename = "resetsAt")]
    resets_at: String,
}

/// The `GET /zen/go/v1/usage` body: the three windows the Go subscription is metered on.
#[derive(Debug, serde::Deserialize)]
struct UsageWire {
    usage: UsageWindowsWire,
}

#[derive(Debug, serde::Deserialize)]
struct UsageWindowsWire {
    rolling: WindowWire,
    weekly: WindowWire,
    monthly: WindowWire,
}

impl UsageWire {
    fn into_account_usage(self) -> AccountUsage {
        let window = |label: &str, wire: WindowWire| UsageWindow {
            label: label.to_string(),
            used_percent: wire.percent,
            // Unparseable reset times degrade to `None`, never an error: the percentage is the
            // number a user acts on, and a wrong reset only misplaces the countdown.
            resets_at: chrono::DateTime::parse_from_rfc3339(&wire.resets_at)
                .ok()
                .map(|when| when.timestamp()),
        };
        AccountUsage {
            windows: vec![
                window("5-hour (rolling)", self.usage.rolling),
                window("Weekly", self.usage.weekly),
                window("Monthly", self.usage.monthly),
            ],
            extra_usage: None,
            note: None,
        }
    }
}

/// A mock endpoint that captures the head of the one request it receives, lowercased, and refuses
/// it with a 400: the request is the point of the tests that use it, not an answer.
#[cfg(test)]
pub(crate) async fn mock_endpoint_capturing_the_head()
-> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    mock_endpoint_answering(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await
}

/// A mock endpoint that answers `response` and captures the head of the one request it receives,
/// lowercased. Shared by the driver tests that assert what an OpenCode Go request carries, and by
/// the usage-fetch tests, which need a real answer.
#[cfg(test)]
pub(crate) async fn mock_endpoint_answering(
    response: &'static str,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a mock endpoint");
    let local = listener.local_addr().expect("local addr");
    let (head_sender, head_receiver) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buffer = Vec::with_capacity(4096);
        loop {
            let mut chunk = [0u8; 2048];
            let read = match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let end = buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or(buffer.len());
        let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
        if socket.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if socket.shutdown().await.is_err() {
            return;
        }
        if head_sender.send(head).is_err() {
            tracing::debug!("the test dropped its receiver before the head arrived");
        }
    });
    (local, head_receiver)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::provider::Attribution;

    #[test]
    fn session_header_rides_the_attribution_and_user_agent_always_rides() {
        let session_id = Uuid::new_v4();
        let request = apply_request_headers(
            reqwest::Client::new().post("http://localhost/chat/completions"),
            &Attribution {
                session_id: Some(session_id),
                ..Default::default()
            },
            Some(Gateway::GO),
        )
        .build()
        .expect("the request should build");
        let headers = request.headers();
        assert!(
            headers
                .get("x-opencode-session")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == session_id.to_string().as_str()),
            "the request must carry the session under the gateway's header name"
        );
        assert!(
            headers
                .get(reqwest::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ua| ua.starts_with("meka/"))
        );
    }

    #[test]
    fn a_turn_without_a_session_sends_the_user_agent_but_no_session_header() {
        let request = apply_request_headers(
            reqwest::Client::new().post("http://localhost/chat/completions"),
            &Attribution::default(),
            Some(Gateway::GO),
        )
        .build()
        .expect("the request should build");
        assert!(request.headers().get("x-opencode-session").is_none());
        assert!(request.headers().get(reqwest::header::USER_AGENT).is_some());
    }

    #[test]
    fn a_generic_backend_adds_nothing() {
        let request = apply_request_headers(
            reqwest::Client::new().post("http://localhost/chat/completions"),
            &Attribution::default(),
            None,
        )
        .build()
        .expect("the request should build");
        let headers = request.headers();
        assert!(headers.get("x-opencode-session").is_none());
        assert!(headers.get(reqwest::header::USER_AGENT).is_none());
    }

    #[test]
    fn usage_windows_map_name_percent_and_reset() {
        let wire: UsageWire = serde_json::from_str(
            r#"{"usage":{
                "rolling":{"status":"ok","percent":41.5,"resetsAt":"2026-09-15T17:00:00.000000+00:00"},
                "weekly":{"status":"ok","percent":12.0,"resetsAt":"2026-09-20T00:00:00+00:00"},
                "monthly":{"status":"rate-limited","percent":100.0,"resetsAt":"2026-09-30T23:59:59+00:00"}
            }}"#,
        )
        .expect("the wire shape should parse");
        let usage = wire.into_account_usage();
        assert_eq!(usage.windows.len(), 3);
        assert_eq!(usage.windows[0].label, "5-hour (rolling)");
        assert_eq!(usage.windows[0].used_percent, 41.5);
        assert_eq!(usage.windows[1].label, "Weekly");
        assert_eq!(usage.windows[1].used_percent, 12.0);
        assert_eq!(usage.windows[2].label, "Monthly");
        assert_eq!(usage.windows[2].used_percent, 100.0);
        assert_eq!(
            usage.windows[0].resets_at,
            chrono::DateTime::parse_from_rfc3339("2026-09-15T17:00:00.000000+00:00")
                .map(|when| when.timestamp())
                .ok()
        );
        assert!(usage.extra_usage.is_none());
        assert!(usage.note.is_none());
    }

    #[test]
    fn an_unparseable_reset_time_degrades_to_none() {
        let wire: UsageWire = serde_json::from_str(
            r#"{"usage":{
                "rolling":{"status":"ok","percent":1.0,"resetsAt":"not-a-date"},
                "weekly":{"status":"ok","percent":2.0,"resetsAt":"2026-09-20T00:00:00+00:00"},
                "monthly":{"status":"ok","percent":3.0,"resetsAt":"2026-09-30T23:59:59+00:00"}
            }}"#,
        )
        .expect("the wire shape should parse");
        let usage = wire.into_account_usage();
        assert_eq!(usage.windows[0].resets_at, None);
        assert_eq!(usage.windows[0].used_percent, 1.0);
    }

    /// The usage GET carries the inference key and meka's user agent, and nothing else: the
    /// endpoint is account-level, so there is no session to name.
    #[tokio::test]
    async fn fetch_usage_reads_the_windows_over_the_bearer_key() {
        let (local, head_receiver) = mock_endpoint_answering(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
             {\"usage\":{\
             \"rolling\":{\"status\":\"ok\",\"percent\":41.5,\"resetsAt\":\"2026-09-15T17:00:00.000000+00:00\"},\
             \"weekly\":{\"status\":\"ok\",\"percent\":12.0,\"resetsAt\":\"2026-09-20T00:00:00+00:00\"},\
             \"monthly\":{\"status\":\"rate-limited\",\"percent\":100.0,\"resetsAt\":\"2026-09-30T23:59:59+00:00\"}}}",
        )
        .await;
        let usage = fetch_usage(
            &reqwest::Client::new(),
            format!("http://{local}/usage"),
            "test-key",
            Gateway::GO,
        )
        .await
        .expect("the usage should fetch");
        assert_eq!(usage.windows[0].label, "5-hour (rolling)");
        assert_eq!(usage.windows[0].used_percent, 41.5);
        assert_eq!(usage.windows[1].used_percent, 12.0);
        assert_eq!(usage.windows[2].used_percent, 100.0);
        let head = head_receiver.await.expect("the mock saw the request");
        assert!(
            head.lines()
                .any(|line| line == "authorization: bearer test-key"),
            "the usage request must carry the inference key; head:\n{head}"
        );
        assert!(
            head.lines()
                .any(|line| line.starts_with("user-agent: meka/")),
            "the usage request must carry meka's user agent; head:\n{head}"
        );
        assert!(
            !head.contains("x-opencode-session"),
            "the usage request is account-level and must not name a session; head:\n{head}"
        );
    }

    /// A 403 (no active subscription) surfaces as an error rather than an empty usage.
    #[tokio::test]
    async fn a_refused_usage_fetch_is_an_error() {
        let (local, _head_receiver) = mock_endpoint_answering(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await;
        let result = fetch_usage(
            &reqwest::Client::new(),
            format!("http://{local}/usage"),
            "test-key",
            Gateway::GO,
        )
        .await;
        assert!(result.is_err(), "a 403 must not read as empty usage");
    }
}
