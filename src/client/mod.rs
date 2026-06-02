//! Gateway-agnostic HTTP client for the CIP-309 service surface.
//!
//! The client targets any CIP-309 gateway: the caller passes an explicit
//! `base_url` and an opaque bearer key, and every request is built through the
//! verifier's single outbound egress
//! ([`crate::verifier::fetch`]) so the deny-host policy, the protocol/method
//! allowlist, the bounded response-body cap, and the audit trail all apply.
//!
//! The surface mirrors the TypeScript and Python SDKs:
//!
//! - [`Cip309Client`] — construction (required `base_url` + optional
//!   opaque bearer) and the three namespaces.
//! - [`PoeNamespace`] — quote, multipart uploads, publish, publish-batch, and
//!   the high-level [`publish_content`](PoeNamespace::publish_content) /
//!   `publish_prehashed` / `publish_sealed` / `publish_merkle` helpers.
//! - [`RecordsNamespace`] — record list, fetch, and verify.
//! - [`AccountNamespace`] — account balance read.
//! - The RFC 7807 / RFC 9457 [`ProblemDetails`] parser and the full typed
//!   [`Cip309HttpError`] catalogue, with an unknown-code fallback to
//!   [`HttpErrorKind::Other`].
//! - The off-host signing helpers ([`prepare_sig_structure`] / `assemble_*`),
//!   which reuse [`crate::cose`] and never see the integrator's private key.

pub mod account;
pub mod cip309_client;
pub mod errors;
pub mod http;
pub mod off_host_sign;
pub mod poe;
pub mod publish;
pub mod records;
pub mod transport;
pub mod types;

pub use account::AccountNamespace;
pub use cip309_client::{Cip309Client, Cip309ClientConfig, InvalidClientConfigError};
pub use errors::{
    parse_http_error, Cip309HttpError, HttpErrorKind, ParseHttpErrorArgs, ProblemDetails,
    ProblemErrorEntry,
};
pub use http::{ClientError, NamespaceConfig};
pub use off_host_sign::{
    assemble_cose_sign1, assemble_cose_sign1_hashed, build_to_sign, prepare_sig_structure,
    prepare_sig_structure_hashed, AssembledCoseSign1, OffHostSignError, PreparedSigStructure,
    PreparedSigStructureHashed,
};
pub use poe::PoeNamespace;
pub use publish::{
    publish_content, publish_merkle, publish_prehashed, publish_sealed, PartialUploadError,
    PublishError, PublishHelperError, Signer, SignerError,
};
pub use records::RecordsNamespace;
pub use transport::{
    ClientResponse, ClientTransport, MultipartField, RequestBody, ReqwestClientTransport,
    ResponseHeaders,
};
pub use types::{
    AccountBalance, ConformanceProfile, MerkleLeaf, PoeItemResponse, PoeStatus,
    PoeVerifyDecryption, PoeVerifyInput, PublishBatchEntry, PublishBatchFailureEntry,
    PublishBatchFailureError, PublishBatchInput, PublishBatchResponse, PublishBatchResultEntry,
    PublishBatchSuccessEntry, PublishContentInput, PublishInput, PublishMerkleInput,
    PublishMerkleResponse, PublishPrehashedInput, PublishResponse, PublishSealedInput, QuoteInput,
    QuoteResponse, RecordResource, RecordSignature, RecordsListInput, RecordsListResponse,
    SealedKemChoice, SupportedHashAlg, UploadEntry, UploadError, UploadsInput, UploadsResponse,
};
