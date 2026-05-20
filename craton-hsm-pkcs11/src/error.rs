// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Typed mapping from `cryptoki::error::Error` to [`HsmError`].
//!
//! The previous implementation collapsed every PKCS#11 error to
//! `HsmError::GeneralError` and decided signature-verification outcomes by
//! substring-matching `format!("{e:?}")` -- a fragile, security-critical bug.
//! This module replaces that with a typed match on `RvError`, plus a
//! [`VerifyOutcome`] helper that explicitly distinguishes "signature is
//! invalid" from "the verify call failed for an unrelated reason".

use craton_hsm::error::HsmError;
use cryptoki::error::{Error as CryptokiError, RvError};

/// Result of a PKCS#11 verify call, decoded from the typed cryptoki error.
#[derive(Debug)]
pub enum VerifyOutcome {
    /// The token reported the signature as cryptographically valid.
    Valid,
    /// The token reported `CKR_SIGNATURE_INVALID` or `CKR_SIGNATURE_LEN_RANGE`.
    Invalid,
    /// Any other error -- propagate to the caller as `Err(HsmError)`.
    Error(HsmError),
}

impl VerifyOutcome {
    /// Convenience: collapse [`VerifyOutcome::Invalid`] / `Valid` into a `bool`,
    /// propagating other errors as `Err`.
    pub fn into_bool(self) -> Result<bool, HsmError> {
        match self {
            VerifyOutcome::Valid => Ok(true),
            VerifyOutcome::Invalid => Ok(false),
            VerifyOutcome::Error(e) => Err(e),
        }
    }
}

/// Convert the typed result of a `Session::verify` call to a [`VerifyOutcome`].
pub fn classify_verify_result(result: Result<(), CryptokiError>) -> VerifyOutcome {
    match result {
        Ok(()) => VerifyOutcome::Valid,
        Err(CryptokiError::Pkcs11(RvError::SignatureInvalid, _))
        | Err(CryptokiError::Pkcs11(RvError::SignatureLenRange, _)) => VerifyOutcome::Invalid,
        Err(other) => VerifyOutcome::Error(map_cryptoki_error(&other)),
    }
}

/// Map a `cryptoki::error::Error` to an [`HsmError`] preserving as much
/// semantic information as the craton-hsm error enum allows.
///
/// The original PKCS#11 error is also logged at DEBUG so that the underlying
/// vendor message is recoverable from a trace without leaking it via the
/// returned error type.
pub fn map_cryptoki_error(err: &CryptokiError) -> HsmError {
    tracing::debug!(target: "craton_hsm_pkcs11", "PKCS#11 error: {}", err);
    match err {
        CryptokiError::Pkcs11(rv, _) => map_rv_error(rv),
        // Library-loading / FFI / lifecycle errors.
        CryptokiError::LibraryLoading(_) => {
            HsmError::ConfigError("PKCS#11 library load error".to_string())
        }
        CryptokiError::NotSupported => HsmError::FunctionNotSupported,
        // A failed integer/slice conversion at the cryptoki FFI boundary
        // is NOT an attacker-controllable "arguments bad" -- it means a
        // token returned a usize/length value the host platform cannot
        // represent. Surface it as GeneralError so log triage does not
        // mistake an internal contract violation for a caller mistake.
        CryptokiError::TryFromInt(_) | CryptokiError::TryFromSlice(_) => HsmError::GeneralError,
        CryptokiError::NulError(_) => HsmError::ArgumentsBad,
        CryptokiError::AlreadyInitialized => HsmError::AlreadyInitialized,
        CryptokiError::PinNotSet => HsmError::UserPinNotInitialized,
        _ => HsmError::GeneralError,
    }
}

fn map_rv_error(rv: &RvError) -> HsmError {
    // We deliberately match only the well-known RvError variants. Anything
    // not enumerated here falls through to `GeneralError`; the original
    // variant name is captured at DEBUG by `map_cryptoki_error`. This keeps
    // the mapping forward-compatible across cryptoki minor versions where
    // new variants may be added.
    match rv {
        // ----- session / login -----
        RvError::SessionHandleInvalid => HsmError::SessionHandleInvalid,
        RvError::SessionCount => HsmError::SessionCount,
        RvError::SessionReadOnly => HsmError::SessionReadOnly,
        RvError::SessionParallelNotSupported => HsmError::SessionParallelNotSupported,
        RvError::SessionExists => HsmError::SessionExists,
        RvError::SessionReadOnlyExists => HsmError::SessionReadOnlyExists,
        RvError::SessionReadWriteSoExists => HsmError::SessionReadWriteSoExists,
        RvError::UserAlreadyLoggedIn => HsmError::UserAlreadyLoggedIn,
        RvError::UserNotLoggedIn => HsmError::UserNotLoggedIn,
        RvError::UserTypeInvalid => HsmError::UserTypeInvalid,
        RvError::UserAnotherAlreadyLoggedIn => HsmError::UserAnotherAlreadyLoggedIn,
        RvError::UserPinNotInitialized => HsmError::UserPinNotInitialized,
        RvError::PinIncorrect => HsmError::PinIncorrect,
        RvError::PinInvalid => HsmError::PinInvalid,
        RvError::PinLenRange => HsmError::PinLenRange,
        RvError::PinLocked => HsmError::PinLocked,

        // ----- lifecycle -----
        // CKR_CRYPTOKI_NOT_INITIALIZED maps cleanly to NotInitialized.
        RvError::CryptokiNotInitialized => HsmError::NotInitialized,

        // ----- token / device -----
        RvError::TokenNotPresent => HsmError::TokenNotPresent,
        RvError::TokenWriteProtected => HsmError::TokenWriteProtected,
        RvError::DeviceMemory => HsmError::DeviceMemory,
        // CKR_DEVICE_REMOVED maps to TokenNotPresent (the token has been
        // physically removed from the slot).
        RvError::DeviceRemoved => HsmError::TokenNotPresent,
        // Device-level / "transient" errors that do not fit any specific
        // craton-hsm variant. These fold to GeneralError but get an explicit
        // arm so they are not silently absorbed by the wildcard.
        RvError::DeviceError => HsmError::GeneralError,
        RvError::FunctionFailed => HsmError::GeneralError,
        RvError::StateUnsaveable => HsmError::GeneralError,

        // ----- RNG -----
        // CKR_RANDOM_SEED_NOT_SUPPORTED has its own dedicated craton-hsm
        // variant; route there instead of GeneralError so callers can
        // distinguish "this token does not let you seed its RNG".
        RvError::RandomSeedNotSupported => HsmError::RandomSeedNotSupported,

        // ----- objects / attributes -----
        RvError::ObjectHandleInvalid => HsmError::ObjectHandleInvalid,
        RvError::AttributeTypeInvalid => HsmError::AttributeTypeInvalid,
        RvError::AttributeValueInvalid => HsmError::AttributeValueInvalid,
        RvError::AttributeReadOnly => HsmError::AttributeReadOnly,
        RvError::AttributeSensitive => HsmError::AttributeSensitive,
        RvError::TemplateIncomplete => HsmError::TemplateIncomplete,
        RvError::TemplateInconsistent => HsmError::TemplateInconsistent,

        // ----- mechanism / key -----
        RvError::MechanismInvalid => HsmError::MechanismInvalid,
        RvError::MechanismParamInvalid => HsmError::MechanismParamInvalid,
        RvError::KeyHandleInvalid => HsmError::KeyHandleInvalid,
        RvError::KeyTypeInconsistent => HsmError::KeyTypeInconsistent,
        RvError::KeySizeRange => HsmError::KeySizeRange,
        RvError::KeyFunctionNotPermitted => HsmError::KeyFunctionNotPermitted,

        // ----- operation state -----
        RvError::OperationActive => HsmError::OperationActive,
        RvError::OperationNotInitialized => HsmError::OperationNotInitialized,

        // ----- data / signature -----
        RvError::DataInvalid => HsmError::DataInvalid,
        RvError::DataLenRange => HsmError::DataLenRange,
        RvError::EncryptedDataInvalid => HsmError::EncryptedDataInvalid,
        RvError::EncryptedDataLenRange => HsmError::EncryptedDataLenRange,
        RvError::SignatureInvalid => HsmError::SignatureInvalid,
        RvError::SignatureLenRange => HsmError::SignatureLenRange,

        // ----- buffers / memory -----
        RvError::BufferTooSmall => HsmError::BufferTooSmall,
        RvError::HostMemory => HsmError::HostMemory,

        // ----- function support -----
        RvError::FunctionNotSupported => HsmError::FunctionNotSupported,

        // ----- arguments / general -----
        RvError::ArgumentsBad => HsmError::ArgumentsBad,
        RvError::GeneralError => HsmError::GeneralError,

        _ => HsmError::GeneralError,
    }
}

/// Map any cryptoki error directly to an [`HsmError`] for use in `?`-chains.
#[inline]
pub fn pkcs11_err(err: CryptokiError) -> HsmError {
    map_cryptoki_error(&err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ok_is_valid() {
        let outcome = classify_verify_result(Ok(()));
        assert!(matches!(outcome, VerifyOutcome::Valid));
        assert_eq!(outcome.into_bool().unwrap(), true);
    }

    #[test]
    fn into_bool_propagates_errors() {
        let outcome = VerifyOutcome::Error(HsmError::SessionHandleInvalid);
        assert!(outcome.into_bool().is_err());
    }

    #[test]
    fn into_bool_invalid_is_false() {
        assert_eq!(VerifyOutcome::Invalid.into_bool().unwrap(), false);
    }

    #[test]
    fn map_signature_invalid_to_signature_invalid() {
        assert!(matches!(
            map_rv_error(&RvError::SignatureInvalid),
            HsmError::SignatureInvalid
        ));
        assert!(matches!(
            map_rv_error(&RvError::SignatureLenRange),
            HsmError::SignatureLenRange
        ));
    }

    #[test]
    fn map_pin_locked() {
        assert!(matches!(
            map_rv_error(&RvError::PinLocked),
            HsmError::PinLocked
        ));
    }

    #[test]
    fn map_key_handle_invalid() {
        assert!(matches!(
            map_rv_error(&RvError::KeyHandleInvalid),
            HsmError::KeyHandleInvalid
        ));
    }

    #[test]
    fn map_token_not_present() {
        assert!(matches!(
            map_rv_error(&RvError::TokenNotPresent),
            HsmError::TokenNotPresent
        ));
    }

    #[test]
    fn map_mechanism_errors() {
        assert!(matches!(
            map_rv_error(&RvError::MechanismInvalid),
            HsmError::MechanismInvalid
        ));
        assert!(matches!(
            map_rv_error(&RvError::MechanismParamInvalid),
            HsmError::MechanismParamInvalid
        ));
    }

    #[test]
    fn map_function_not_supported() {
        assert!(matches!(
            map_rv_error(&RvError::FunctionNotSupported),
            HsmError::FunctionNotSupported
        ));
    }

    #[test]
    fn map_cryptoki_not_initialized() {
        assert!(matches!(
            map_rv_error(&RvError::CryptokiNotInitialized),
            HsmError::NotInitialized
        ));
    }

    #[test]
    fn map_random_seed_not_supported() {
        assert!(matches!(
            map_rv_error(&RvError::RandomSeedNotSupported),
            HsmError::RandomSeedNotSupported
        ));
    }

    #[test]
    fn map_state_unsaveable_is_general_error() {
        assert!(matches!(
            map_rv_error(&RvError::StateUnsaveable),
            HsmError::GeneralError
        ));
    }

    #[test]
    fn map_device_removed_is_token_not_present() {
        assert!(matches!(
            map_rv_error(&RvError::DeviceRemoved),
            HsmError::TokenNotPresent
        ));
    }

    #[test]
    fn map_device_error_is_general() {
        assert!(matches!(
            map_rv_error(&RvError::DeviceError),
            HsmError::GeneralError
        ));
    }

    #[test]
    fn map_function_failed_is_general() {
        assert!(matches!(
            map_rv_error(&RvError::FunctionFailed),
            HsmError::GeneralError
        ));
    }
}
