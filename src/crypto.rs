//! Wire encryption for CopyTunnel.
//!
//! Every frame that leaves a node is `seal()`-ed and every frame that arrives is
//! `open()`-ed. The module offers several ciphers so an operator can trade raw
//! speed, hardware acceleration, nonce safety, and obfuscation against each
//! other. The README explains the practical differences; the short version:
//!
//! | Cipher                | Auth | Key | Nonce | Notes                                   |
//! |-----------------------|------|-----|-------|-----------------------------------------|
//! | `chacha20poly1305`    | AEAD | 256 | 96b   | Fast everywhere, no AES hardware needed |
//! | `xchacha20poly1305`   | AEAD | 256 | 192b  | Random-nonce safe at huge volumes       |
//! | `aes256gcm`           | AEAD | 256 | 96b   | Fastest with AES-NI / ARMv8 crypto      |
//! | `aes128gcm`           | AEAD | 128 | 96b   | Slightly faster AES, smaller key        |
//! | `xor`                 | none | 256 | n/a   | Obfuscation only — NOT confidential     |
//! | `none`                | none | n/a | n/a   | Plaintext passthrough (debugging)       |
//!
//! Wire layout for AEAD ciphers:   `[ nonce ][ ciphertext || tag ]`
//! Wire layout for `xor`/`none`:   `[ payload ]` (xor keystream applied in place)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Associated data bound into every AEAD frame. Any tampering with it (or a
/// peer configured with a different value) makes authentication fail. This also
/// cheaply rejects foreign/garbage UDP packets before they ever touch the TUN.
const AAD: &[u8] = b"copytunnel/v1";

/// Selectable cipher. Serialized form matches the config file spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CipherKind {
    #[serde(alias = "chacha20poly1305", alias = "chacha20")]
    ChaCha20Poly1305,
    #[serde(alias = "xchacha20poly1305", alias = "xchacha20")]
    XChaCha20Poly1305,
    #[serde(alias = "aes256gcm", alias = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(alias = "aes128gcm", alias = "aes-128-gcm")]
    Aes128Gcm,
    Xor,
    None,
}

impl CipherKind {
    /// Whether this cipher provides authentication (AEAD). Part of the public
    /// cipher API; useful for callers that want to warn when a non-AEAD mode is
    /// selected.
    #[allow(dead_code)]
    pub fn is_authenticated(self) -> bool {
        matches!(
            self,
            CipherKind::ChaCha20Poly1305
                | CipherKind::XChaCha20Poly1305
                | CipherKind::Aes256Gcm
                | CipherKind::Aes128Gcm
        )
    }

    pub fn human_name(self) -> &'static str {
        match self {
            CipherKind::ChaCha20Poly1305 => "ChaCha20-Poly1305 (AEAD, 256-bit)",
            CipherKind::XChaCha20Poly1305 => "XChaCha20-Poly1305 (AEAD, 256-bit, 192-bit nonce)",
            CipherKind::Aes256Gcm => "AES-256-GCM (AEAD)",
            CipherKind::Aes128Gcm => "AES-128-GCM (AEAD)",
            CipherKind::Xor => "XOR keystream (obfuscation only, NOT confidential)",
            CipherKind::None => "none (plaintext passthrough)",
        }
    }
}

/// A ready-to-use cipher instance holding the derived key material.
pub enum Cipher {
    ChaCha(Box<ChaCha20Poly1305>),
    XChaCha(Box<XChaCha20Poly1305>),
    Aes256(Box<Aes256Gcm>),
    Aes128(Box<Aes128Gcm>),
    /// 32-byte key stretched into a keystream per frame.
    Xor([u8; 32]),
    None,
}

impl Cipher {
    /// Build a cipher from the configuration.
    ///
    /// The 32-byte master key is either the decoded `key_hex` (when provided) or
    /// `SHA-256(pre_shared_key)`. AES-128 uses the first 16 bytes.
    pub fn new(kind: CipherKind, psk: &str, key_hex: &Option<String>) -> Result<Cipher> {
        let key = derive_key(psk, key_hex)?;
        Ok(match kind {
            CipherKind::ChaCha20Poly1305 => {
                Cipher::ChaCha(Box::new(ChaCha20Poly1305::new((&key).into())))
            }
            CipherKind::XChaCha20Poly1305 => {
                Cipher::XChaCha(Box::new(XChaCha20Poly1305::new((&key).into())))
            }
            CipherKind::Aes256Gcm => Cipher::Aes256(Box::new(Aes256Gcm::new((&key).into()))),
            CipherKind::Aes128Gcm => {
                let k16: [u8; 16] = key[..16].try_into().unwrap();
                Cipher::Aes128(Box::new(Aes128Gcm::new((&k16).into())))
            }
            CipherKind::Xor => Cipher::Xor(key),
            CipherKind::None => Cipher::None,
        })
    }

    /// Encrypt `plaintext` into a fresh wire frame. The nonce (when any) is
    /// prepended to the returned bytes so the peer can decrypt without shared
    /// counters.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::ChaCha(c) => {
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ct = c
                    .encrypt(
                        (&nonce).into(),
                        Payload { msg: plaintext, aad: AAD },
                    )
                    .map_err(|_| anyhow!("chacha20poly1305 encrypt failed"))?;
                Ok(prepend(&nonce, &ct))
            }
            Cipher::XChaCha(c) => {
                let mut nonce = [0u8; 24];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ct = c
                    .encrypt(
                        (&nonce).into(),
                        Payload { msg: plaintext, aad: AAD },
                    )
                    .map_err(|_| anyhow!("xchacha20poly1305 encrypt failed"))?;
                Ok(prepend(&nonce, &ct))
            }
            Cipher::Aes256(c) => {
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ct = c
                    .encrypt(
                        (&nonce).into(),
                        Payload { msg: plaintext, aad: AAD },
                    )
                    .map_err(|_| anyhow!("aes-256-gcm encrypt failed"))?;
                Ok(prepend(&nonce, &ct))
            }
            Cipher::Aes128(c) => {
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ct = c
                    .encrypt(
                        (&nonce).into(),
                        Payload { msg: plaintext, aad: AAD },
                    )
                    .map_err(|_| anyhow!("aes-128-gcm encrypt failed"))?;
                Ok(prepend(&nonce, &ct))
            }
            Cipher::Xor(key) => {
                // A per-frame random 8-byte salt makes identical packets differ
                // on the wire. Keystream = SHA-256(key || salt || counter).
                let mut salt = [0u8; 8];
                rand::thread_rng().fill_bytes(&mut salt);
                let mut out = Vec::with_capacity(8 + plaintext.len());
                out.extend_from_slice(&salt);
                let mut body = plaintext.to_vec();
                xor_keystream(key, &salt, &mut body);
                out.extend_from_slice(&body);
                Ok(out)
            }
            Cipher::None => Ok(plaintext.to_vec()),
        }
    }

    /// Decrypt a wire frame back into the original plaintext. Returns an error
    /// (which the caller silently drops) for anything that fails authentication
    /// or is too short — this is the gate that keeps spoofed/garbage traffic off
    /// the TUN.
    pub fn open(&self, frame: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::ChaCha(c) => {
                let (nonce, ct) = split(frame, 12)?;
                c.decrypt(nonce.into(), Payload { msg: ct, aad: AAD })
                    .map_err(|_| anyhow!("chacha20poly1305 auth failed"))
            }
            Cipher::XChaCha(c) => {
                let (nonce, ct) = split(frame, 24)?;
                c.decrypt(nonce.into(), Payload { msg: ct, aad: AAD })
                    .map_err(|_| anyhow!("xchacha20poly1305 auth failed"))
            }
            Cipher::Aes256(c) => {
                let (nonce, ct) = split(frame, 12)?;
                c.decrypt(nonce.into(), Payload { msg: ct, aad: AAD })
                    .map_err(|_| anyhow!("aes-256-gcm auth failed"))
            }
            Cipher::Aes128(c) => {
                let (nonce, ct) = split(frame, 12)?;
                c.decrypt(nonce.into(), Payload { msg: ct, aad: AAD })
                    .map_err(|_| anyhow!("aes-128-gcm auth failed"))
            }
            Cipher::Xor(key) => {
                let (salt, body) = split(frame, 8)?;
                let salt: [u8; 8] = salt.try_into().unwrap();
                let mut out = body.to_vec();
                xor_keystream(key, &salt, &mut out);
                Ok(out)
            }
            Cipher::None => Ok(frame.to_vec()),
        }
    }
}

/// Derive the 32-byte master key.
fn derive_key(psk: &str, key_hex: &Option<String>) -> Result<[u8; 32]> {
    if let Some(h) = key_hex {
        let raw = hex::decode(h.trim())?;
        if raw.len() != 32 {
            bail!("key_hex must decode to 32 bytes");
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"copytunnel-kdf-v1");
    hasher.update(psk.as_bytes());
    Ok(hasher.finalize().into())
}

fn prepend(nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

fn split(frame: &[u8], n: usize) -> Result<(&[u8], &[u8])> {
    if frame.len() < n + 1 {
        bail!("frame too short");
    }
    Ok((&frame[..n], &frame[n..]))
}

/// SHA-256-based counter-mode keystream XOR'd over `data` in place.
fn xor_keystream(key: &[u8; 32], salt: &[u8; 8], data: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut offset = 0;
    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(salt);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        for b in block.iter() {
            if offset >= data.len() {
                break;
            }
            data[offset] ^= b;
            offset += 1;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Stateless whole-frame XOR obfuscation layer (applied after `seal`, before
/// `open`). Deterministic and self-inverse so both directions agree without any
/// extra header. `mask` is derived once from the PSK.
pub fn obfuscation_mask(psk: &str) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(b"copytunnel-obfs-v1");
    hasher.update(psk.as_bytes());
    let h1 = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update(b"copytunnel-obfs-v2");
    hasher.update(psk.as_bytes());
    let h2 = hasher.finalize();
    let mut mask = [0u8; 64];
    mask[..32].copy_from_slice(&h1);
    mask[32..].copy_from_slice(&h2);
    mask
}

pub fn obfuscate_inplace(data: &mut [u8], mask: &[u8; 64]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= mask[i % mask.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(kind: CipherKind) {
        let c = Cipher::new(kind, "test-pre-shared-key-1234", &None).unwrap();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let sealed = c.seal(msg).unwrap();
        let opened = c.open(&sealed).unwrap();
        assert_eq!(&opened, msg, "{:?}", kind);
    }

    #[test]
    fn all_ciphers_roundtrip() {
        roundtrip(CipherKind::ChaCha20Poly1305);
        roundtrip(CipherKind::XChaCha20Poly1305);
        roundtrip(CipherKind::Aes256Gcm);
        roundtrip(CipherKind::Aes128Gcm);
        roundtrip(CipherKind::Xor);
        roundtrip(CipherKind::None);
    }

    #[test]
    fn aead_rejects_tampering() {
        let c = Cipher::new(CipherKind::ChaCha20Poly1305, "test-pre-shared-key-1234", &None).unwrap();
        let mut sealed = c.seal(b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(c.open(&sealed).is_err());
    }

    #[test]
    fn obfuscation_is_self_inverse() {
        let mask = obfuscation_mask("test-pre-shared-key-1234");
        let original = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
        let mut buf = original.clone();
        obfuscate_inplace(&mut buf, &mask);
        assert_ne!(buf, original);
        obfuscate_inplace(&mut buf, &mask);
        assert_eq!(buf, original);
    }
}
