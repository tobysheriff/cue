//! A minimal axum extractor/response pair for protobuf bodies (docs/05:
//! "Protobuf (`prost`) serialization"), so the registration API speaks the
//! same wire format as everything else in the workspace rather than
//! reaching for JSON out of convenience.

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use prost::Message;

pub struct Protobuf<T>(pub T);

impl<T, S> FromRequest<S> for Protobuf<T>
where
    T: Message + Default,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        T::decode(bytes).map(Protobuf).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid protobuf body: {e}"),
            )
        })
    }
}

impl<T: Message> IntoResponse for Protobuf<T> {
    fn into_response(self) -> Response {
        (
            [(header::CONTENT_TYPE, "application/x-protobuf")],
            self.0.encode_to_vec(),
        )
            .into_response()
    }
}
