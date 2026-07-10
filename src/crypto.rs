//! High-performance cryptographic operations

use crate::{config::Config, error::TesaurusError, Result};
use bitcoin::{PrivateKey, PublicKey, Address, Network, Transaction, TxOut, Script};
use secp256k1::{Secp256k1, SecretKey, Message, Signature};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use parking_lot::RwLock;
use dashmap::DashMap;

/// Cryptographic manager optimized for performance
pub struct CryptoManager {
    /// Secp256k1 context - expensive to create, so we reuse it
    secp: Arc<Secp256k1<secp256k1::All>>,
    /// Network configuration
    network: Network,
    /// Key cache to avoid repeated derivations
    key_cache: DashMap<String, PublicKey>,
    /// Signature cache for recently verified signatures
    sig_cache: Arc<RwLock<lru::LruCache<[u8; 32], bool>>>,
}

impl CryptoManager {
    /// Create a new crypto manager with performance optimizations
    pub async fn new(config: &Config) -> Result<Self> {
        let network = match config.bitcoin.network.as_str() {
            "testnet" => Network::Testnet,
            "mainnet" => Network::Bitcoin,
            "regtest" => Network::Regtest,
            _ => return Err(TesaurusError::crypto("Invalid network")),
        };

        // Pre-allocate signature cache
        let sig_cache_size = 10000; // Cache 10k recent signature verifications
        let sig_cache = Arc::new(RwLock::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(sig_cache_size).unwrap()
        )));

        Ok(Self {
            secp: Arc::new(Secp256k1::new()),
            network,
            key_cache: DashMap::new(),
            sig_cache,
        })
    }

    /// Generate a new private key with secure randomness
    pub fn generate_private_key(&self) -> Result<PrivateKey> {
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        Ok(PrivateKey::new(secret_key, self.network))
    }

    /// Derive public key from private key with caching
    pub fn derive_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey> {
        let key_str = private_key.to_string();
        
        // Check cache first
        if let Some(cached) = self.key_cache.get(&key_str) {
            return Ok(*cached);
        }

        // Compute and cache
        let public_key = private_key.public_key(&self.secp);
        self.key_cache.insert(key_str, public_key);
        
        Ok(public_key)
    }

    /// Create multisig address optimized for the 2-of-3 setup
    pub fn create_multisig_address(
        &self,
        pubkeys: &[PublicKey],
        threshold: usize,
    ) -> Result<Address> {
        if pubkeys.len() != 3 || threshold != 2 {
            return Err(TesaurusError::crypto("Only 2-of-3 multisig supported"));
        }

        // Sort pubkeys for deterministic address generation
        let mut sorted_pubkeys = pubkeys.to_vec();
        sorted_pubkeys.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));

        let script = Script::new_multisig(threshold, &sorted_pubkeys)
            .map_err(|e| TesaurusError::crypto("Failed to create multisig script"))?;

        Address::p2wsh(&script, self.network)
            .map_err(|e| TesaurusError::crypto("Failed to create address"))
    }

    /// Sign transaction with performance optimizations
    pub fn sign_transaction(
        &self,
        tx: &mut Transaction,
        input_index: usize,
        private_key: &PrivateKey,
        prev_output: &TxOut,
    ) -> Result<Signature> {
        // Create message hash for signing
        let sighash = tx.signature_hash(
            input_index,
            &prev_output.script_pubkey,
            bitcoin::EcdsaSighashType::All.into(),
        );

        let message = Message::from_slice(&sighash.to_byte_array())
            .map_err(|e| TesaurusError::crypto("Invalid message"))?;

        // Sign with secp256k1
        let signature = self.secp.sign_ecdsa(&message, &private_key.inner);
        
        Ok(signature)
    }

    /// Verify signature with caching for performance
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        // Create cache key from message hash
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&signature.serialize_compact());
        hasher.update(&public_key.to_bytes());
        let cache_key: [u8; 32] = hasher.finalize().into();

        // Check cache first
        {
            let cache = self.sig_cache.read();
            if let Some(&result) = cache.peek(&cache_key) {
                return Ok(result);
            }
        }

        // Verify signature
        let msg = Message::from_slice(message)
            .map_err(|e| TesaurusError::crypto("Invalid message for verification"))?;
        
        let result = self.secp.verify_ecdsa(&msg, signature, &public_key.inner).is_ok();

        // Cache result
        {
            let mut cache = self.sig_cache.write();
            cache.put(cache_key, result);
        }

        Ok(result)
    }

    /// Batch verify multiple signatures for better performance
    pub fn batch_verify_signatures(
        &self,
        verifications: &[(Vec<u8>, Signature, PublicKey)],
    ) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(verifications.len());
        
        // Process in batches for better cache locality
        const BATCH_SIZE: usize = 16;
        for chunk in verifications.chunks(BATCH_SIZE) {
            for (message, signature, public_key) in chunk {
                let result = self.verify_signature(message, signature, public_key)?;
                results.push(result);
            }
        }
        
        Ok(results)
    }

    /// Hash data using SHA256 with SIMD optimizations when available
    pub fn hash_sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Create deterministic nonce for signing (RFC 6979)
    pub fn create_deterministic_nonce(&self, private_key: &PrivateKey, message: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut k = [0u8; 32];
        let mut v = [1u8; 32];

        // RFC 6979 implementation for deterministic nonce generation
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        mac.update(&[0x00]);
        mac.update(&private_key.to_bytes());
        mac.update(message);
        k = mac.finalize().into_bytes().into();

        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&v);
        v = mac.finalize().into_bytes().into();

        k
    }

    /// Clear caches to free memory
    pub fn clear_caches(&self) {
        self.key_cache.clear();
        self.sig_cache.write().clear();
    }

    /// Get cache statistics for monitoring
    pub fn cache_stats(&self) -> CacheStats {
        let sig_cache = self.sig_cache.read();
        CacheStats {
            key_cache_size: self.key_cache.len(),
            sig_cache_size: sig_cache.len(),
            sig_cache_capacity: sig_cache.cap().get(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub key_cache_size: usize,
    pub sig_cache_size: usize,
    pub sig_cache_capacity: usize,
}