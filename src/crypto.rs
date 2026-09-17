// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Shane Utt

//! Process-wide rustls crypto provider.
//!
//! Installs the `OpenSSL`-backed rustls provider as the process default so the
//! outbound TLS the AI filters perform (reqwest, rmcp) runs inside the system
//! `OpenSSL` (the FIPS module under FIPS) rather than a bundled provider. The
//! provider routes bulk ciphers, key exchange, signatures, HKDF and random
//! generation through `OpenSSL`.

/// Install the `OpenSSL`-backed rustls provider as the process default.
///
/// Call once at startup before any TLS client is built; outbound clients use
/// the process default when one is installed.
///
/// # Errors
///
/// Returns [`crate::error::ExtProcError::Config`] when a rustls default provider
/// is already installed.
pub fn install_default_provider() -> crate::error::Result<()> {
    // Pin key exchange to the FIPS-approved NIST curves. The default groups also
    // offer X25519 and the X25519MLKEM768 hybrid, which are not FIPS approved, so
    // restricting them keeps the ClientHello from offering non-approved groups.
    let mut provider = rustls_openssl::default_provider();
    provider.kx_groups = vec![rustls_openssl::kx_group::SECP256R1, rustls_openssl::kx_group::SECP384R1];
    match provider.install_default() {
        Ok(()) => Ok(()),
        Err(_) => Err(crate::error::ExtProcError::Config(
            "a rustls crypto provider is already installed".to_owned(),
        )),
    }
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn install_pins_fips_kx_groups() {
        install_default_provider().expect("install the OpenSSL rustls provider");
        let provider = rustls::crypto::CryptoProvider::get_default().expect("a default provider");
        assert_eq!(
            provider.kx_groups.len(),
            2,
            "key exchange is pinned to the two FIPS-approved NIST curves"
        );
    }
}
