//! Override `confirm_token` (protocol §15.1).
//!
//! Compact 64-byte ECDSA (`R||S`) over `SHA256(preimage)`, verified with the
//! pinned **override** pubkey. Not BIP322 and not a transaction sighash.
//!
//! Threshold keys off **external output amount only** (`OOB_CONFIRM_SATS`);
//! fee and vault change are excluded.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::ecdsa::Signature as EcdsaSignature;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::{BlockHash, PublicKey, Txid};

use crate::error::{PolicyError, PolicyErrorCode, PolicyResult};

/// ASCII domain separator. Locked length: **19 bytes** (not 18).
/// Do not change the UTF-8 string; other implementations concatenate these bytes.
pub const CONFIRM_DOMAIN: &[u8] = b"TESAURUS_CONFIRM_V1";
pub const CONFIRM_DOMAIN_LEN: usize = 19;
pub const CONFIRM_LAYOUT_VERSION: u8 = 1;

const _: () = assert!(CONFIRM_DOMAIN.len() == CONFIRM_DOMAIN_LEN);

/// External value at or above this requires a valid `confirm_token`.
pub const OOB_CONFIRM_SATS: u64 = 5_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmBinding {
    /// UUID RFC4122 16-byte wire order.
    pub request_id: [u8; 16],
    /// Txid as 32-byte decode of the usual Bitcoin txid hex string (display order).
    pub txid_display: [u8; 32],
    pub external_amount_sats: u64,
    /// `BlockHash::to_byte_array()` / internal order (not display hex).
    pub genesis_internal: [u8; 32],
}

pub fn confirm_required(external_amount_sats: u64) -> bool {
    external_amount_sats >= OOB_CONFIRM_SATS
}

pub fn txid_display_bytes(txid: Txid) -> [u8; 32] {
    let mut bytes = txid.to_byte_array();
    bytes.reverse();
    bytes
}

pub fn genesis_internal_bytes(genesis: BlockHash) -> [u8; 32] {
    genesis.to_byte_array()
}

pub fn confirm_preimage(binding: &ConfirmBinding) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(CONFIRM_DOMAIN.len() + 1 + 16 + 32 + 8 + 32);
    preimage.extend_from_slice(CONFIRM_DOMAIN);
    preimage.push(CONFIRM_LAYOUT_VERSION);
    preimage.extend_from_slice(&binding.request_id);
    preimage.extend_from_slice(&binding.txid_display);
    preimage.extend_from_slice(&binding.external_amount_sats.to_be_bytes());
    preimage.extend_from_slice(&binding.genesis_internal);
    preimage
}

pub fn confirm_message(binding: &ConfirmBinding) -> sha256::Hash {
    sha256::Hash::hash(&confirm_preimage(binding))
}

pub fn verify_confirm_token(
    token: &[u8],
    binding: &ConfirmBinding,
    override_pubkey: &PublicKey,
) -> PolicyResult<()> {
    if token.len() != 64 {
        return Err(PolicyError::new(
            PolicyErrorCode::ConfirmInvalid,
            format!("confirm_token must be 64 bytes, got {}", token.len()),
        ));
    }
    let mut compact = [0u8; 64];
    compact.copy_from_slice(token);
    let sig = EcdsaSignature::from_compact(&compact).map_err(|e| {
        PolicyError::new(
            PolicyErrorCode::ConfirmInvalid,
            format!("confirm_token is not a compact ECDSA signature: {e}"),
        )
    })?;
    let digest = confirm_message(binding).to_byte_array();
    let msg = Message::from_digest(digest);
    let secp = Secp256k1::verification_only();
    secp.verify_ecdsa(&msg, &sig, &override_pubkey.inner)
        .map_err(|_| {
            PolicyError::new(
                PolicyErrorCode::ConfirmInvalid,
                "confirm_token ECDSA verification failed",
            )
        })
}

/// CI-22 known encoding / signature vector (synthetic override key; not a vault).
pub mod vectors {
    /// secp256k1 secret scalar 1 (test fixture only).
    pub const OVERRIDE_SK_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    /// Compressed pubkey for scalar 1.
    pub const OVERRIDE_PK_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    pub const REQUEST_ID_HEX: &str = "0123456789ab4def81ff0123456789ab";
    pub const TXID_DISPLAY_HEX: &str =
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    pub const EXTERNAL_SATS: u64 = 5_000_000;
    /// Bitcoin genesis `BlockHash::to_byte_array()` (encoding fixture, not mainnet unlock).
    pub const GENESIS_INTERNAL_HEX: &str =
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
    pub const PREIMAGE_HEX: &str = "54455341555255535f434f4e4649524d5f5631010123456789ab4def81ff0123456789ab4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b00000000004c4b406fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
    pub const MESSAGE_SHA256_HEX: &str =
        "34d979d3b4f6b698c07276379ad94c3ff6684e675b72faa2d9fc8451aaada31c";
    /// RFC6979 compact64 from libsecp256k1 over SHA256(preimage) with OVERRIDE_SK_HEX.
    pub const SIGNATURE_COMPACT64_HEX: &str =
        "9e7a0b6def442c5eafb8175a3129f66ee802b7363703c8772b838777d924e760414781ff5658d78c648f8d05b1690ba1ef00c10f8ce668f1a4ec4f4b7b0b9590";
}

#[cfg(test)]
mod tests {
    use super::vectors;
    use super::*;
    use bitcoin::constants::genesis_block;
    use bitcoin::secp256k1::{SecretKey, Signing};
    use bitcoin::Network;
    use std::str::FromStr;

    fn decode32(hex: &str) -> [u8; 32] {
        let v = hex::decode(hex).unwrap();
        v.try_into().unwrap()
    }

    fn decode16(hex: &str) -> [u8; 16] {
        let v = hex::decode(hex).unwrap();
        v.try_into().unwrap()
    }

    fn vector_binding() -> ConfirmBinding {
        ConfirmBinding {
            request_id: decode16(vectors::REQUEST_ID_HEX),
            txid_display: decode32(vectors::TXID_DISPLAY_HEX),
            external_amount_sats: vectors::EXTERNAL_SATS,
            genesis_internal: decode32(vectors::GENESIS_INTERNAL_HEX),
        }
    }

    fn override_sk() -> SecretKey {
        SecretKey::from_slice(&hex::decode(vectors::OVERRIDE_SK_HEX).unwrap()).unwrap()
    }

    fn override_pk() -> PublicKey {
        PublicKey::from_str(vectors::OVERRIDE_PK_HEX).unwrap()
    }

    fn sign_compact<C: Signing>(secp: &Secp256k1<C>, binding: &ConfirmBinding) -> [u8; 64] {
        let msg = Message::from_digest(confirm_message(binding).to_byte_array());
        secp.sign_ecdsa(&msg, &override_sk()).serialize_compact()
    }

    #[test]
    fn confirm_keys_off_external_not_fee() {
        // Huge fee, external under 5M → confirm NOT required.
        let external = OOB_CONFIRM_SATS - 1;
        let _huge_fee = 80_000_000_u64;
        assert!(!confirm_required(external));

        // Tiny fee, external at 5M → confirm required.
        let external = OOB_CONFIRM_SATS;
        let _tiny_fee = 1_u64;
        assert!(confirm_required(external));
    }

    #[test]
    fn confirm_threshold_table_ci21() {
        assert!(!confirm_required(4_999_999));
        assert!(confirm_required(5_000_000));
        assert!(confirm_required(10_000_000));
        // Change must not drive the threshold (external-only).
        let change = 50_000_000_u64;
        assert!(!confirm_required(4_999_999));
        let _ = change;
        assert!(confirm_required(5_000_000));
    }

    #[test]
    fn preimage_matches_locked_hex() {
        assert_eq!(CONFIRM_DOMAIN.len(), CONFIRM_DOMAIN_LEN);
        assert_eq!(CONFIRM_DOMAIN_LEN, 19);
        let preimage = confirm_preimage(&vector_binding());
        assert_eq!(hex::encode(&preimage), vectors::PREIMAGE_HEX);
        assert_eq!(
            hex::encode(confirm_message(&vector_binding()).as_byte_array()),
            vectors::MESSAGE_SHA256_HEX
        );
    }

    #[test]
    fn genesis_uses_internal_byte_order() {
        let genesis = genesis_block(Network::Bitcoin).block_hash();
        assert_eq!(
            hex::encode(genesis_internal_bytes(genesis)),
            vectors::GENESIS_INTERNAL_HEX
        );
        let display = genesis.to_string();
        assert_eq!(
            display,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_ne!(hex::encode(genesis.to_byte_array()), display);
    }

    #[test]
    fn known_valid_compact64_verifies() {
        let secp = Secp256k1::new();
        let binding = vector_binding();
        let compact = sign_compact(&secp, &binding);
        verify_confirm_token(&compact, &binding, &override_pk()).unwrap();

        assert_eq!(hex::encode(compact), vectors::SIGNATURE_COMPACT64_HEX);
        verify_confirm_token(
            &hex::decode(vectors::SIGNATURE_COMPACT64_HEX).unwrap(),
            &binding,
            &override_pk(),
        )
        .unwrap();
    }

    #[test]
    fn flipped_fields_invalidate_token() {
        let secp = Secp256k1::new();
        let binding = vector_binding();
        let compact = sign_compact(&secp, &binding);

        let bad_version = binding.clone();
        let mut pre = confirm_preimage(&bad_version);
        pre[CONFIRM_DOMAIN.len()] = 2;
        let msg = sha256::Hash::hash(&pre);
        let sig = EcdsaSignature::from_compact(&compact).unwrap();
        assert!(secp
            .verify_ecdsa(
                &Message::from_digest(msg.to_byte_array()),
                &sig,
                &override_pk().inner
            )
            .is_err());

        let mut uuid = binding.clone();
        uuid.request_id[0] ^= 0x01;
        assert_eq!(
            verify_confirm_token(&compact, &uuid, &override_pk())
                .unwrap_err()
                .code,
            PolicyErrorCode::ConfirmInvalid
        );

        let mut txid = binding.clone();
        txid.txid_display.reverse(); // wrong endianness
        assert_eq!(
            verify_confirm_token(&compact, &txid, &override_pk())
                .unwrap_err()
                .code,
            PolicyErrorCode::ConfirmInvalid
        );

        let mut amount = binding.clone();
        amount.external_amount_sats = 5_000_001;
        assert_eq!(
            verify_confirm_token(&compact, &amount, &override_pk())
                .unwrap_err()
                .code,
            PolicyErrorCode::ConfirmInvalid
        );

        let mut genesis = binding.clone();
        genesis.genesis_internal.reverse();
        assert_eq!(
            verify_confirm_token(&compact, &genesis, &override_pk())
                .unwrap_err()
                .code,
            PolicyErrorCode::ConfirmInvalid
        );
    }

    #[test]
    fn txid_display_is_hex_decode_of_rpc_string() {
        let hex_str = vectors::TXID_DISPLAY_HEX;
        let txid = Txid::from_str(hex_str).unwrap();
        assert_eq!(hex::encode(txid_display_bytes(txid)), hex_str);
        assert_ne!(txid.to_byte_array(), txid_display_bytes(txid));
    }

    #[test]
    fn wrong_length_token_is_confirm_invalid() {
        let err = verify_confirm_token(&[0u8; 65], &vector_binding(), &override_pk()).unwrap_err();
        assert_eq!(err.code, PolicyErrorCode::ConfirmInvalid);
    }
}
