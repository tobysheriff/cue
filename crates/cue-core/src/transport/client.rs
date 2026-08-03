//! [`NodeClient`]: a thin client for a `cue-node`'s delivery and
//! registration-read surface (docs/05) — HTTP for everything except the
//! live mailbox push, which is a `GET /v1/mailbox/{id}/ws` connection
//! ([`MailboxStream`]). Onion transport (Tor via `arti`) is still open;
//! plain `ws://`/`http://` or `wss://`/`https://` only, no TLS pinning
//! beyond what `reqwest`'s/`tokio-tungstenite`'s rustls stacks do already.

use cue_proto::v1::{AckRequest, Envelope, MailboxEnvelopes, PrekeyBundleResponse};
use futures_util::{SinkExt as _, StreamExt as _};
use prost::Message as _;
use reqwest::StatusCode;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::TransportError;

pub struct NodeClient {
    http: reqwest::Client,
    /// No trailing slash, e.g. `https://cue.example`.
    base_url: String,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }

    /// `GET /v1/accounts/{handle}/prekey-bundle` — the public key material
    /// (and current mailbox id) needed to open a PQXDH session with a peer
    /// (docs/03 "Session establishment").
    pub async fn fetch_prekey_bundle(
        &self,
        handle: &str,
    ) -> Result<PrekeyBundleResponse, TransportError> {
        let response = self
            .http
            .get(format!(
                "{}/v1/accounts/{handle}/prekey-bundle",
                self.base_url
            ))
            .send()
            .await?;
        decode_protobuf_response(response).await
    }

    /// `POST /v1/deliver` — enqueue one envelope.
    pub async fn deliver(&self, envelope: &Envelope) -> Result<(), TransportError> {
        let response = self
            .http
            .post(format!("{}/v1/deliver", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(envelope.encode_to_vec())
            .send()
            .await?;
        expect_status(response, StatusCode::ACCEPTED).await?;
        Ok(())
    }

    /// `GET /v1/mailbox/{mailbox_id}` — peek at what's queued, without
    /// deleting anything (docs/09: only an ack deletes).
    pub async fn fetch_mailbox(
        &self,
        mailbox_id: [u8; 16],
    ) -> Result<Vec<Envelope>, TransportError> {
        let response = self
            .http
            .get(format!("{}/v1/mailbox/{}", self.base_url, hex(mailbox_id)))
            .send()
            .await?;
        let envelopes: MailboxEnvelopes = decode_protobuf_response(response).await?;
        Ok(envelopes.envelopes)
    }

    /// `POST /v1/mailbox/{mailbox_id}/ack` — delete-on-ack (docs/09
    /// "deliver and delete").
    pub async fn ack(
        &self,
        mailbox_id: [u8; 16],
        envelope_ids: Vec<Vec<u8>>,
    ) -> Result<(), TransportError> {
        let request = AckRequest { envelope_ids };
        let response = self
            .http
            .post(format!(
                "{}/v1/mailbox/{}/ack",
                self.base_url,
                hex(mailbox_id)
            ))
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .body(request.encode_to_vec())
            .send()
            .await?;
        expect_status(response, StatusCode::OK).await?;
        Ok(())
    }

    /// `GET /v1/mailbox/{mailbox_id}/ws` — connect for live delivery. The
    /// server flushes whatever's already queued on connect, then pushes new
    /// envelopes as they arrive; [`fetch_mailbox`](Self::fetch_mailbox)
    /// remains the polling fallback for a shell that doesn't want to hold a
    /// socket open (docs/05).
    pub async fn watch_mailbox(
        &self,
        mailbox_id: [u8; 16],
    ) -> Result<MailboxStream, TransportError> {
        let (socket, _response) =
            tokio_tungstenite::connect_async(ws_url(&self.base_url, mailbox_id)).await?;
        Ok(MailboxStream { socket })
    }
}

/// A live `GET /v1/mailbox/{id}/ws` connection: each server→client frame is
/// one protobuf-encoded [`Envelope`], each client→server frame one 16-byte
/// envelope id to ack (`cue-node`'s `handle_mailbox_socket`).
pub struct MailboxStream {
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl MailboxStream {
    /// The next envelope, or `None` once the Node closes the connection.
    /// Ping/pong/text frames are transparently skipped rather than
    /// surfaced — this is a delivery stream, not a raw socket.
    pub async fn recv(&mut self) -> Option<Result<Envelope, TransportError>> {
        loop {
            match self.socket.next().await? {
                Ok(WsMessage::Binary(bytes)) => {
                    return Some(Envelope::decode(bytes.as_ref()).map_err(TransportError::from))
                }
                Ok(WsMessage::Close(_)) => return None,
                Ok(_) => continue,
                Err(err) => return Some(Err(err.into())),
            }
        }
    }

    /// Ack `envelope_id` over the same connection (docs/09 "deliver and
    /// delete") — an alternative to [`NodeClient::ack`] that doesn't need a
    /// separate HTTP round trip.
    pub async fn ack(&mut self, envelope_id: &[u8]) -> Result<(), TransportError> {
        self.socket
            .send(WsMessage::Binary(envelope_id.to_vec().into()))
            .await?;
        Ok(())
    }
}

/// `http(s)://host[:port]` → `ws(s)://host[:port]/v1/mailbox/{hex}/ws`.
fn ws_url(base_url: &str, mailbox_id: [u8; 16]) -> String {
    let ws_base = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base_url.to_owned()
    };
    format!("{ws_base}/v1/mailbox/{}/ws", hex(mailbox_id))
}

fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn decode_protobuf_response<T: prost::Message + Default>(
    response: reqwest::Response,
) -> Result<T, TransportError> {
    let response = expect_status(response, StatusCode::OK).await?;
    let bytes = response.bytes().await?;
    Ok(T::decode(bytes)?)
}

async fn expect_status(
    response: reqwest::Response,
    expected: StatusCode,
) -> Result<reqwest::Response, TransportError> {
    if response.status() == expected {
        Ok(response)
    } else {
        Err(TransportError::UnexpectedStatus(response.status()))
    }
}
