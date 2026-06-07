

 
// Constants

pub const X25519_KEY_SIZE: usize = 32;
pub const ML_KEM_768_PK_SIZE: usize = 1184;
pub const ML_KEM_768_SK_SIZE: usize = 2400;
pub const MLDSA_65_SIGNATURE_KEY_SIZE: usize = 3309;
pub const ML_KEM_768_CT_SIZE: usize = 1088;

 
// Key wrappers
 

// X25519 private key.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct X25519PrivateKey(pub [u8; X25519_KEY_SIZE]);

// X25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct X25519PublicKey(pub [u8; X25519_KEY_SIZE]);

// Root key
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct RootChainKey (pub [u8; 32]);

// Sending chain key
#[derive(Debug, Copy, Clone)]
pub struct ChainKey (pub [u8; 32]);  

// Sending message key
#[derive(Copy, Clone, Debug)]
pub struct MessageKey (pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct MLDSA65SigningKey (pub [u8; 4032]);

#[derive(Debug, Clone, PartialEq)]
pub struct MLDSA65VerificationKey (pub [u8; 1952]);

//  X25519 keypair.
// The user's long-term identity keypair for X25519 DH steps in PQXDH.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct X25519KeyPair {
    pub private_key: X25519PrivateKey,
    pub public_key:  X25519PublicKey,
}

// The output key from SCKA using ML-KEM 
#[derive(Debug)]
pub struct SCKAOutputKey {
    pub epoch: u64,
    pub key:   [u8; 32],
}

// ML-KEM-768 public key (1184 bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct EncapsulationKey(pub [u8; ML_KEM_768_PK_SIZE]);

// ML-KEM-768 secret key (2400 bytes).
#[derive(Clone)]
pub struct DecapsulationKey(pub [u8; ML_KEM_768_SK_SIZE]);

// ML-KEM-768 keypair.
#[derive(Clone)]
pub struct PQKeyPair {
    pub public_key: EncapsulationKey,
    pub secret_key: DecapsulationKey,
}

// The user's long-term ML-DSA-65 keypair for signing prekeys.
pub struct IdentityDSAKey {
    pub signing_key:      MLDSA65SigningKey,
    pub verification_key: MLDSA65VerificationKey,
}

// Combined long-term identity holds both DH and signing keys.
pub struct IdentityKeys {
    pub dh:  X25519KeyPair,
    pub dsa: IdentityDSAKey,
}

// X25519 signed prekey, authenticated by the identity DSA key.
#[derive(Clone)]
pub struct SignedPreKey {
    pub id:  u32,
    pub key: X25519KeyPair,
    pub sig: [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
}

// A post-quantum ML-KEM-768 signed prekey, authenticated by the identity DSA key.
#[derive(Clone)]
pub struct PQSignedPreKey {
    pub id:  u32,
    pub key: PQKeyPair,
    pub sig: [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
}
 

// X25519 one-time prekey. Consumed during session initiation.
#[derive(Clone)]
pub struct OneTimePreKey {
    pub id:  u32,
    pub key: X25519KeyPair,
}

// post-quantum ML-KEM-768 one-time prekey. Consumed during PQXDH encapsulation.
#[derive(Clone)]
pub struct PQOneTimePreKey {
    pub id:  u32,
    pub key: PQKeyPair,
    pub sig: [u8; MLDSA_65_SIGNATURE_KEY_SIZE]
}

// Public prekey bundle uploaded to the server.
// Contains no private key material.
#[derive(Clone, Debug)]
pub struct PrekeyBundle {
    // Long-term X25519 identity public key (used in DH).
    pub ik_dh_pub:   X25519PublicKey,
    // Long-term ML-DSA-65 verification key (used to verify signatures below).
    pub ik_dsa_pub:  MLDSA65VerificationKey,

    // Signed X25519 prekey.
    pub spk_pub:     X25519PublicKey,
    pub spk_sig:     [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
    pub spk_id:      u32,

    // Signed ML-KEM-768 prekey.
    pub pqspk_pub:   EncapsulationKey,
    pub pqspk_sig:   [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
    pub pqspk_id:    u32,

    // One-time X25519 prekeys (public + id).
    pub opks:        Vec<(X25519PublicKey, u32)>,
    
    // One-time ML-KEM-768 signed prekeys (public + id + sig)
    pub pq_s_opks : Vec<(EncapsulationKey, u32, [u8; MLDSA_65_SIGNATURE_KEY_SIZE])>
}

// Prekey bundle fetched from the server when initiating a session with a peer.
#[derive(Debug, PartialEq)]
pub struct FetchedBundle {
    // Long-term X25519 identity public key (used in DH).
    pub ik_dh_pub:  X25519PublicKey,
    // Long-term ML-DSA-65 verification key (used to verify signatures below).
    pub ik_dsa_pub: MLDSA65VerificationKey,

    // Signed X25519 prekey.
    pub spk_pub:    X25519PublicKey,
    pub spk_sig:    [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
    pub spk_id:     u32,

    // Signed ML-KEM-768 prekey.
    pub pqspk_pub:  Option<EncapsulationKey>,
    pub pqspk_sig:  [u8; MLDSA_65_SIGNATURE_KEY_SIZE],
    pub pqspk_id:   Option<u32>,

    /// Optional — server may have run out of one-time prekeys.
    pub opk:        Option<(X25519PublicKey, u32)>,
    pub pq_opk:     Option<(EncapsulationKey, u32, [u8; MLDSA_65_SIGNATURE_KEY_SIZE])>,
}

// Everything a user holds locally.
pub struct UserKeyBundle {
    // Long-term identity keys — never leave the device.
    pub identity:    IdentityKeys,
    // Current signed X25519 prekey.
    pub spk:         SignedPreKey,
    // Previous signed X25519 prekey (kept briefly during rotation overlap).
    pub spk_prev:    Option<SignedPreKey>,
    // Current signed PQ prekey.
    pub pqspk:       PQSignedPreKey,
    // Previous signed PQ prekey (kept briefly during rotation overlap).
    pub pqspk_prev:  Option<PQSignedPreKey>,
    // Pool of unused one-time prekeys.
    pub opks:        Vec<OneTimePreKey>,
    // Pool of unused PQ one-time prekeys.
    pub pq_opks:     Vec<PQOneTimePreKey>,
}