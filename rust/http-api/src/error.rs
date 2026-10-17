//! HTTP status mapping for upstream RPC errors.

use axum::http::StatusCode;

pub(crate) fn grpc_status_to_http(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        // Ok / Cancelled / Unknown / Internal / DataLoss — no HTTP
        // status distinguishes these usefully to a caller.  500
        // ensures an unmapped upstream signal never surfaces as 200.
        //
        // Exhaustive rather than `_` so a tonic upgrade that adds a
        // new `Code` variant breaks the build here loudly instead of
        // silently degrading production callers to 500.  When that
        // happens: add the new variant with a considered HTTP mapping
        // (or leave it in this fallback group with a docstring
        // update) — do NOT add `_ => 500` back.
        tonic::Code::Ok
        | tonic::Code::Cancelled
        | tonic::Code::Unknown
        | tonic::Code::Internal
        | tonic::Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
