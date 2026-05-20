// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! KMIP 2.1 core type definitions.
//!
//! Enumerations for tags, object types, operations, cryptographic algorithms,
//! result statuses, and result reasons as specified by OASIS KMIP 2.1.

use std::fmt;

// ---------------------------------------------------------------------------
// KmipTag
// ---------------------------------------------------------------------------

/// KMIP wire-format tags (3-byte identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmipTag {
    /// `Operation` (§9.1.3.2.27).
    Operation,
    /// `Unique Identifier` — managed-object ID.
    UniqueIdentifier,
    /// `Object Type`.
    ObjectType,
    /// `Template-Attribute` structure (request-side attribute bundle).
    TemplateAttribute,
    /// `Attribute` structure.
    Attribute,
    /// `Attribute Name` string.
    AttributeName,
    /// `Attribute Value` polymorphic payload.
    AttributeValue,
    /// `Cryptographic Algorithm`.
    CryptographicAlgorithm,
    /// `Cryptographic Length` (bits).
    CryptographicLength,
    /// `Name` structure (container of `NameValue` + `NameType`).
    Name,
    /// `Name Value` string.
    NameValue,
    /// `Name Type` enumeration.
    NameType,
    /// `Request Header` structure.
    RequestHeader,
    /// `Response Header` structure.
    ResponseHeader,
    /// Top-level `Request Message`.
    RequestMessage,
    /// Top-level `Response Message`.
    ResponseMessage,
    /// `Batch Item` structure.
    BatchItem,
    /// `Result Status` enumeration.
    ResultStatus,
    /// `Result Reason` enumeration.
    ResultReason,
    /// `Result Message` free-form string.
    ResultMessage,
    /// `Key Block` structure.
    KeyBlock,
    /// `Key Value` structure.
    KeyValue,
    /// `Key Material` bytes.
    KeyMaterial,
    /// `Protocol Version` structure.
    ProtocolVersion,
    /// `Protocol Version Major` integer.
    ProtocolVersionMajor,
    /// `Protocol Version Minor` integer.
    ProtocolVersionMinor,
    /// `Time Stamp` (Unix seconds).
    TimeStamp,
    /// `Batch Count` integer.
    BatchCount,
    /// `Client Correlation Value` (KMIP 2.1 §6.13) — opaque per-request
    /// nonce used to detect replay across a session (audit M).
    ClientCorrelationValue,
}

impl KmipTag {
    /// Return the 3-byte wire tag (packed into a `u32`).
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Operation => 0x0042_005C,
            Self::UniqueIdentifier => 0x0042_0094,
            Self::ObjectType => 0x0042_0057,
            Self::TemplateAttribute => 0x0042_0091,
            Self::Attribute => 0x0042_0008,
            Self::AttributeName => 0x0042_000A,
            Self::AttributeValue => 0x0042_000B,
            Self::CryptographicAlgorithm => 0x0042_0028,
            Self::CryptographicLength => 0x0042_002A,
            Self::Name => 0x0042_0053,
            Self::NameValue => 0x0042_0055,
            Self::NameType => 0x0042_0054,
            Self::RequestHeader => 0x0042_0077,
            Self::ResponseHeader => 0x0042_007A,
            Self::RequestMessage => 0x0042_0078,
            Self::ResponseMessage => 0x0042_007B,
            Self::BatchItem => 0x0042_000D,
            Self::ResultStatus => 0x0042_007F,
            Self::ResultReason => 0x0042_0080,
            Self::ResultMessage => 0x0042_0081,
            Self::KeyBlock => 0x0042_0040,
            Self::KeyValue => 0x0042_0045,
            Self::KeyMaterial => 0x0042_0043,
            Self::ProtocolVersion => 0x0042_0069,
            Self::ProtocolVersionMajor => 0x0042_006A,
            Self::ProtocolVersionMinor => 0x0042_006B,
            Self::TimeStamp => 0x0042_0092,
            Self::BatchCount => 0x0042_000E,
            Self::ClientCorrelationValue => 0x0042_009A,
        }
    }

    /// Map a wire tag back to its `KmipTag`, or `None` if unknown.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x0042_005C => Some(Self::Operation),
            0x0042_0094 => Some(Self::UniqueIdentifier),
            0x0042_0057 => Some(Self::ObjectType),
            0x0042_0091 => Some(Self::TemplateAttribute),
            0x0042_0008 => Some(Self::Attribute),
            0x0042_000A => Some(Self::AttributeName),
            0x0042_000B => Some(Self::AttributeValue),
            0x0042_0028 => Some(Self::CryptographicAlgorithm),
            0x0042_002A => Some(Self::CryptographicLength),
            0x0042_0053 => Some(Self::Name),
            0x0042_0055 => Some(Self::NameValue),
            0x0042_0054 => Some(Self::NameType),
            0x0042_0077 => Some(Self::RequestHeader),
            0x0042_007A => Some(Self::ResponseHeader),
            0x0042_0078 => Some(Self::RequestMessage),
            0x0042_007B => Some(Self::ResponseMessage),
            0x0042_000D => Some(Self::BatchItem),
            0x0042_007F => Some(Self::ResultStatus),
            0x0042_0080 => Some(Self::ResultReason),
            0x0042_0081 => Some(Self::ResultMessage),
            0x0042_0040 => Some(Self::KeyBlock),
            0x0042_0045 => Some(Self::KeyValue),
            0x0042_0043 => Some(Self::KeyMaterial),
            0x0042_0069 => Some(Self::ProtocolVersion),
            0x0042_006A => Some(Self::ProtocolVersionMajor),
            0x0042_006B => Some(Self::ProtocolVersionMinor),
            0x0042_0092 => Some(Self::TimeStamp),
            0x0042_000E => Some(Self::BatchCount),
            0x0042_009A => Some(Self::ClientCorrelationValue),
            _ => None,
        }
    }
}

impl fmt::Display for KmipTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Operation => "Operation",
            Self::UniqueIdentifier => "UniqueIdentifier",
            Self::ObjectType => "ObjectType",
            Self::TemplateAttribute => "TemplateAttribute",
            Self::Attribute => "Attribute",
            Self::AttributeName => "AttributeName",
            Self::AttributeValue => "AttributeValue",
            Self::CryptographicAlgorithm => "CryptographicAlgorithm",
            Self::CryptographicLength => "CryptographicLength",
            Self::Name => "Name",
            Self::NameValue => "NameValue",
            Self::NameType => "NameType",
            Self::RequestHeader => "RequestHeader",
            Self::ResponseHeader => "ResponseHeader",
            Self::RequestMessage => "RequestMessage",
            Self::ResponseMessage => "ResponseMessage",
            Self::BatchItem => "BatchItem",
            Self::ResultStatus => "ResultStatus",
            Self::ResultReason => "ResultReason",
            Self::ResultMessage => "ResultMessage",
            Self::KeyBlock => "KeyBlock",
            Self::KeyValue => "KeyValue",
            Self::KeyMaterial => "KeyMaterial",
            Self::ProtocolVersion => "ProtocolVersion",
            Self::ProtocolVersionMajor => "ProtocolVersionMajor",
            Self::ProtocolVersionMinor => "ProtocolVersionMinor",
            Self::TimeStamp => "TimeStamp",
            Self::BatchCount => "BatchCount",
            Self::ClientCorrelationValue => "ClientCorrelationValue",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// KmipObjectType
// ---------------------------------------------------------------------------

/// KMIP object types per Section 9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipObjectType {
    /// Symmetric secret key.
    SymmetricKey,
    /// Asymmetric public key.
    PublicKey,
    /// Asymmetric private key.
    PrivateKey,
    /// X.509 certificate or equivalent.
    Certificate,
    /// Opaque secret (e.g. password, passphrase, raw shared secret).
    SecretData,
    /// Opaque data blob whose format is not interpreted by the server.
    OpaqueData,
}

impl KmipObjectType {
    /// Return the integer wire value for this object type.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::SymmetricKey => 1,
            Self::PublicKey => 2,
            Self::PrivateKey => 3,
            Self::Certificate => 6,
            Self::SecretData => 7,
            Self::OpaqueData => 8,
        }
    }

    /// Map a wire value back to a `KmipObjectType`, or `None` if unknown.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::SymmetricKey),
            2 => Some(Self::PublicKey),
            3 => Some(Self::PrivateKey),
            6 => Some(Self::Certificate),
            7 => Some(Self::SecretData),
            8 => Some(Self::OpaqueData),
            _ => None,
        }
    }
}

impl fmt::Display for KmipObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SymmetricKey => "SymmetricKey",
            Self::PublicKey => "PublicKey",
            Self::PrivateKey => "PrivateKey",
            Self::Certificate => "Certificate",
            Self::SecretData => "SecretData",
            Self::OpaqueData => "OpaqueData",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// KmipOperation
// ---------------------------------------------------------------------------

/// KMIP operations per Section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipOperation {
    /// `Create` — generate a new managed object.
    Create,
    /// `CreateKeyPair` — generate an asymmetric key pair (currently returns
    /// `OperationNotSupported`; tracked as a future work item — wiring into
    /// real key-pair generation requires hooking the cryptographic backend
    /// in `craton-hsm-openssl` / `craton-hsm-awslc`).
    // TODO: implement asymmetric key-pair generation in a follow-up commit.
    CreateKeyPair,
    /// `Register` — import an externally produced object.
    Register,
    /// `Locate` — search for objects by attribute.
    Locate,
    /// `Get` — retrieve an object by unique identifier.
    Get,
    /// `GetAttributes` — fetch attribute values.
    GetAttributes,
    /// `AddAttribute` — attach a new attribute to an object.
    AddAttribute,
    /// `ModifyAttribute` — replace the value of an existing attribute on an object.
    ModifyAttribute,
    /// `DeleteAttribute` — remove an attribute from an object.
    DeleteAttribute,
    /// `Activate` — transition an object to the `Active` state.
    Activate,
    /// `Revoke` — transition an object to a revoked state.
    Revoke,
    /// `Destroy` — permanently remove an object.
    Destroy,
    /// `Query` — discover server capabilities.
    Query,
    /// `Check` — verify an object's usage limits.
    Check,
    /// `Encrypt` — encrypt plaintext under a managed key (stub: returns
    /// `OperationNotSupported`).
    Encrypt,
    /// `Decrypt` — decrypt ciphertext under a managed key (stub: returns
    /// `OperationNotSupported`).
    Decrypt,
    /// `Sign` — produce a digital signature with a managed key (stub).
    Sign,
    /// `SignatureVerify` — verify a digital signature with a managed key (stub).
    SignatureVerify,
    /// `MAC` — compute a message authentication code (stub).
    MAC,
    /// `MACVerify` — verify a message authentication code (stub).
    MACVerify,
    /// `RNG_Retrieve` — retrieve random bytes from the server's RNG.
    RngRetrieve,
    /// `DeriveKey` — derive a new key from existing key material (HKDF-SHA256).
    DeriveKey,
}

impl KmipOperation {
    /// Return the integer wire value for this operation code.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Create => 1,
            Self::CreateKeyPair => 2,
            Self::Register => 3,
            Self::DeriveKey => 4,
            Self::Locate => 8,
            Self::Get => 10,
            Self::GetAttributes => 11,
            Self::AddAttribute => 13,
            Self::ModifyAttribute => 14,
            Self::DeleteAttribute => 15,
            Self::Activate => 18,
            Self::Revoke => 19,
            Self::Destroy => 20,
            Self::Query => 24,
            Self::Check => 25,
            Self::Encrypt => 31,
            Self::Decrypt => 32,
            Self::Sign => 33,
            Self::SignatureVerify => 34,
            Self::MAC => 35,
            Self::MACVerify => 36,
            Self::RngRetrieve => 37,
        }
    }

    /// Map a wire value back to a `KmipOperation`, or `None` if unknown.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Create),
            2 => Some(Self::CreateKeyPair),
            3 => Some(Self::Register),
            4 => Some(Self::DeriveKey),
            8 => Some(Self::Locate),
            10 => Some(Self::Get),
            11 => Some(Self::GetAttributes),
            13 => Some(Self::AddAttribute),
            14 => Some(Self::ModifyAttribute),
            15 => Some(Self::DeleteAttribute),
            18 => Some(Self::Activate),
            19 => Some(Self::Revoke),
            20 => Some(Self::Destroy),
            24 => Some(Self::Query),
            25 => Some(Self::Check),
            31 => Some(Self::Encrypt),
            32 => Some(Self::Decrypt),
            33 => Some(Self::Sign),
            34 => Some(Self::SignatureVerify),
            35 => Some(Self::MAC),
            36 => Some(Self::MACVerify),
            37 => Some(Self::RngRetrieve),
            _ => None,
        }
    }
}

impl fmt::Display for KmipOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Create => "Create",
            Self::CreateKeyPair => "CreateKeyPair",
            Self::Register => "Register",
            Self::DeriveKey => "DeriveKey",
            Self::Locate => "Locate",
            Self::Get => "Get",
            Self::GetAttributes => "GetAttributes",
            Self::AddAttribute => "AddAttribute",
            Self::ModifyAttribute => "ModifyAttribute",
            Self::DeleteAttribute => "DeleteAttribute",
            Self::Activate => "Activate",
            Self::Revoke => "Revoke",
            Self::Destroy => "Destroy",
            Self::Query => "Query",
            Self::Check => "Check",
            Self::Encrypt => "Encrypt",
            Self::Decrypt => "Decrypt",
            Self::Sign => "Sign",
            Self::SignatureVerify => "SignatureVerify",
            Self::MAC => "MAC",
            Self::MACVerify => "MACVerify",
            Self::RngRetrieve => "RNG_Retrieve",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// KmipCryptographicAlgorithm
// ---------------------------------------------------------------------------

/// KMIP cryptographic algorithm identifiers per Section 9.1.3.2.13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipCryptographicAlgorithm {
    /// AES (symmetric block cipher).
    AES,
    /// RSA (asymmetric).
    RSA,
    /// ECDSA over a NIST-recommended curve.
    ECDSA,
    /// HMAC-SHA-256 keyed MAC.
    #[allow(non_camel_case_types)]
    HMAC_SHA256,
}

impl KmipCryptographicAlgorithm {
    /// Return the integer wire value for this algorithm.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::AES => 3,
            Self::RSA => 4,
            Self::ECDSA => 6,
            Self::HMAC_SHA256 => 17,
        }
    }

    /// Map a wire value back to a `KmipCryptographicAlgorithm`.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            3 => Some(Self::AES),
            4 => Some(Self::RSA),
            6 => Some(Self::ECDSA),
            17 => Some(Self::HMAC_SHA256),
            _ => None,
        }
    }
}

impl fmt::Display for KmipCryptographicAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::AES => "AES",
            Self::RSA => "RSA",
            Self::ECDSA => "ECDSA",
            Self::HMAC_SHA256 => "HMAC-SHA256",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// KmipResultStatus
// ---------------------------------------------------------------------------

/// Result status codes returned in KMIP response batch items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipResultStatus {
    /// Operation completed successfully.
    Success,
    /// Operation failed; see the accompanying [`KmipResultReason`].
    OperationFailed,
    /// Operation was accepted but has not yet completed.
    OperationPending,
    /// A previously completed operation has been rolled back.
    OperationUndone,
}

impl KmipResultStatus {
    /// Return the integer wire value for this status.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Success => 0,
            Self::OperationFailed => 1,
            Self::OperationPending => 2,
            Self::OperationUndone => 3,
        }
    }

    /// Map a wire value back to a `KmipResultStatus`.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Success),
            1 => Some(Self::OperationFailed),
            2 => Some(Self::OperationPending),
            3 => Some(Self::OperationUndone),
            _ => None,
        }
    }
}

impl fmt::Display for KmipResultStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Success => "Success",
            Self::OperationFailed => "OperationFailed",
            Self::OperationPending => "OperationPending",
            Self::OperationUndone => "OperationUndone",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// KmipResultReason
// ---------------------------------------------------------------------------

/// Reason codes that accompany non-success result statuses. Values match
/// the OASIS KMIP 2.1 spec enumeration (§6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmipResultReason {
    /// Named item (e.g. attribute) was not found on the target object.
    ItemNotFound,
    /// Caller is authenticated but not authorized for this operation.
    NotAuthorized,
    /// Caller is authorized to speak to the server but not to touch this
    /// specific object.
    PermissionDenied,
    /// Target object does not exist.
    ObjectNotFound,
    /// Cryptographic operation (e.g. sign, wrap) failed at a lower layer.
    CryptographicFailure,
    /// Wire-format or top-level framing problem with the request.
    InvalidMessage,
    /// Emitted when a request field fails validation (e.g. missing mandatory
    /// attribute, out-of-range length). Distinct from `InvalidMessage` which
    /// signals wire-format problems.
    InvalidField,
    /// Emitted when the requested operation is not implemented by this server.
    OperationNotSupported,
    /// Catch-all server-internal failure reported when no more specific
    /// reason applies. Emitted by [`crate::server`] when an outgoing
    /// response cannot be TTLV-encoded for a non-attacker-controlled
    /// reason (e.g. an oversize attribute value built locally).
    GeneralFailure,
}

impl KmipResultReason {
    /// Return the integer wire value for this reason.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::ItemNotFound => 1,
            Self::NotAuthorized => 3,
            Self::PermissionDenied => 4,
            Self::ObjectNotFound => 5,
            Self::CryptographicFailure => 11,
            Self::InvalidMessage => 15,
            Self::InvalidField => 19,
            Self::OperationNotSupported => 20,
            // KMIP 2.1 §6.7 — `General Failure` is reserved at 0x100 in
            // the OASIS-published code table.
            Self::GeneralFailure => 0x100,
        }
    }

    /// Map a wire value back to a `KmipResultReason`.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::ItemNotFound),
            3 => Some(Self::NotAuthorized),
            4 => Some(Self::PermissionDenied),
            5 => Some(Self::ObjectNotFound),
            11 => Some(Self::CryptographicFailure),
            15 => Some(Self::InvalidMessage),
            19 => Some(Self::InvalidField),
            20 => Some(Self::OperationNotSupported),
            0x100 => Some(Self::GeneralFailure),
            _ => None,
        }
    }
}

impl fmt::Display for KmipResultReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ItemNotFound => "ItemNotFound",
            Self::NotAuthorized => "NotAuthorized",
            Self::PermissionDenied => "PermissionDenied",
            Self::ObjectNotFound => "ObjectNotFound",
            Self::CryptographicFailure => "CryptographicFailure",
            Self::InvalidMessage => "InvalidMessage",
            Self::InvalidField => "InvalidField",
            Self::OperationNotSupported => "OperationNotSupported",
            Self::GeneralFailure => "GeneralFailure",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_operation_value() {
        assert_eq!(KmipTag::Operation.to_u32(), 0x0042_005C);
    }

    #[test]
    fn tag_unique_identifier_value() {
        assert_eq!(KmipTag::UniqueIdentifier.to_u32(), 0x0042_0094);
    }

    #[test]
    fn tag_roundtrip_all() {
        let tags = [
            KmipTag::Operation,
            KmipTag::UniqueIdentifier,
            KmipTag::ObjectType,
            KmipTag::TemplateAttribute,
            KmipTag::Attribute,
            KmipTag::AttributeName,
            KmipTag::AttributeValue,
            KmipTag::CryptographicAlgorithm,
            KmipTag::CryptographicLength,
            KmipTag::Name,
            KmipTag::NameValue,
            KmipTag::NameType,
            KmipTag::RequestHeader,
            KmipTag::ResponseHeader,
            KmipTag::RequestMessage,
            KmipTag::ResponseMessage,
            KmipTag::BatchItem,
            KmipTag::ResultStatus,
            KmipTag::ResultReason,
            KmipTag::ResultMessage,
            KmipTag::KeyBlock,
            KmipTag::KeyValue,
            KmipTag::KeyMaterial,
            KmipTag::ProtocolVersion,
            KmipTag::ProtocolVersionMajor,
            KmipTag::ProtocolVersionMinor,
            KmipTag::TimeStamp,
            KmipTag::BatchCount,
        ];
        for tag in tags {
            let v = tag.to_u32();
            assert_eq!(
                KmipTag::from_u32(v),
                Some(tag),
                "roundtrip failed for {tag}"
            );
        }
    }

    #[test]
    fn tag_from_unknown_returns_none() {
        assert_eq!(KmipTag::from_u32(0xFFFF_FFFF), None);
    }

    #[test]
    fn object_type_roundtrip() {
        let types = [
            KmipObjectType::SymmetricKey,
            KmipObjectType::PublicKey,
            KmipObjectType::PrivateKey,
            KmipObjectType::Certificate,
            KmipObjectType::SecretData,
            KmipObjectType::OpaqueData,
        ];
        for ot in types {
            assert_eq!(KmipObjectType::from_u32(ot.to_u32()), Some(ot));
        }
    }

    #[test]
    fn operation_roundtrip() {
        let ops = [
            KmipOperation::Create,
            KmipOperation::Register,
            KmipOperation::Locate,
            KmipOperation::Get,
            KmipOperation::GetAttributes,
            KmipOperation::AddAttribute,
            KmipOperation::Activate,
            KmipOperation::Revoke,
            KmipOperation::Destroy,
            KmipOperation::Query,
            KmipOperation::Check,
        ];
        for op in ops {
            assert_eq!(KmipOperation::from_u32(op.to_u32()), Some(op));
        }
    }

    #[test]
    fn crypto_algorithm_roundtrip() {
        let algos = [
            KmipCryptographicAlgorithm::AES,
            KmipCryptographicAlgorithm::RSA,
            KmipCryptographicAlgorithm::ECDSA,
            KmipCryptographicAlgorithm::HMAC_SHA256,
        ];
        for alg in algos {
            assert_eq!(
                KmipCryptographicAlgorithm::from_u32(alg.to_u32()),
                Some(alg)
            );
        }
    }

    #[test]
    fn result_status_roundtrip() {
        let statuses = [
            KmipResultStatus::Success,
            KmipResultStatus::OperationFailed,
            KmipResultStatus::OperationPending,
            KmipResultStatus::OperationUndone,
        ];
        for s in statuses {
            assert_eq!(KmipResultStatus::from_u32(s.to_u32()), Some(s));
        }
    }

    #[test]
    fn result_reason_roundtrip() {
        let reasons = [
            KmipResultReason::ItemNotFound,
            KmipResultReason::NotAuthorized,
            KmipResultReason::PermissionDenied,
            KmipResultReason::ObjectNotFound,
            KmipResultReason::CryptographicFailure,
            KmipResultReason::InvalidMessage,
        ];
        for r in reasons {
            assert_eq!(KmipResultReason::from_u32(r.to_u32()), Some(r));
        }
    }

    #[test]
    fn display_formatting() {
        assert_eq!(format!("{}", KmipTag::Operation), "Operation");
        assert_eq!(format!("{}", KmipObjectType::SymmetricKey), "SymmetricKey");
        assert_eq!(format!("{}", KmipOperation::Create), "Create");
        assert_eq!(
            format!("{}", KmipCryptographicAlgorithm::HMAC_SHA256),
            "HMAC-SHA256"
        );
        assert_eq!(format!("{}", KmipResultStatus::Success), "Success");
        assert_eq!(
            format!("{}", KmipResultReason::InvalidMessage),
            "InvalidMessage"
        );
    }

    #[test]
    fn specific_tag_values() {
        assert_eq!(KmipTag::RequestMessage.to_u32(), 0x0042_0078);
        assert_eq!(KmipTag::ResponseMessage.to_u32(), 0x0042_007B);
        assert_eq!(KmipTag::KeyMaterial.to_u32(), 0x0042_0043);
    }
}
