use crate::{double_ratchet::{messages_ratchet::{ratchet_receive_key, ratchet_send_key}, ratchet_state::StateDHRatchet}};
use crate::spqr::spqr_impl::{SPQRState};
use crate::util::libcrux_wrap::libcrux_gen_kdf_hybrid;
use crate::util::{keys::{MessageKey, X25519PublicKey, X25519KeyPair}};
use crate::util::encrypt_decrypt::{encrypt, decrypt};
use crate::util::keys::RootChainKey;
use crate::util::messages::{SCKAMessageHeader, TRHeader, ECHeader};
use crate::util::constants::{SHARED_SECRET_SIZE, TR_PROTOCOL_INFO};

#[derive(Debug, Clone)]
pub struct TripleRatchetState {
    pub(crate) ec_state: StateDHRatchet,
    pub(crate) spqr_state: SPQRState
}
#[hax_lib::opaque]
fn kdf_hybrid(ec_mk: MessageKey, scka_mk: MessageKey) -> MessageKey {
    let mk = libcrux_gen_kdf_hybrid(&scka_mk.0, &ec_mk.0, TR_PROTOCOL_INFO);

    MessageKey(mk)
}
#[hax_lib::opaque]
fn concat_ad_with_tr_header (ad: [u8; 64], scka_header: &SCKAMessageHeader, ec_header: &ECHeader) -> Vec<u8>{
    let scka_header_bytes = SPQRState::scka_header_to_bytes(scka_header);
    let ec_header_bytes = ec_header.header_to_bytes();
    let mut ad_header = Vec::with_capacity(ad.len() + scka_header_bytes.len() + ec_header_bytes.len());
    ad_header.extend_from_slice(&ad);
    ad_header.extend_from_slice(&scka_header_bytes);
    ad_header.extend_from_slice(&ec_header_bytes);

    ad_header
}

#[hax_lib::attributes]
impl TripleRatchetState {
    #[hax_lib::opaque]
    pub fn rathet_init_initiator_tr(ss_ec: [u8; SHARED_SECRET_SIZE], ss_scka: [u8; SHARED_SECRET_SIZE], bob_dh_public_key: X25519PublicKey) -> Self {
        
        let rk_for_ec_state = RootChainKey(ss_ec);
        
        let ec_state = StateDHRatchet::init_initiator(rk_for_ec_state, bob_dh_public_key)
            .expect("Couldn't create the ec_state for the triple ratchet initiator");
        
        let spqr_state = SPQRState::ratchet_init_initiator(&ss_scka);

        Self {
            ec_state,
            spqr_state
        }
    }
    #[hax_lib::opaque]
    pub(crate) fn rathet_init_responder_tr(ss_ec: [u8; SHARED_SECRET_SIZE], ss_scka: [u8; SHARED_SECRET_SIZE], bob_dh_key_pair: X25519KeyPair) -> Self {
        
        let rk_for_ec_state = RootChainKey(ss_ec);
        
        let ec_state = StateDHRatchet::init_responder(rk_for_ec_state, bob_dh_key_pair);
        
        let spqr_state = SPQRState::ratchet_init_responder(&ss_scka);

        Self {
            ec_state,
            spqr_state
        }
    }
    #[hax_lib::opaque]
    pub fn tr_encrypt<'a> (&mut self, plaintext: &String, ad: &[u8; 64]) -> Result<(TRHeader, Vec<u8>), &'a str> {
        let empty_message = "empty".to_string();
        let plaintext: &String = if plaintext.is_empty(){
                &empty_message
            } 
            else {
                plaintext
            };
                
        let (ec_mk, ec_ns) = ratchet_send_key(&mut self.ec_state)?;

        let (scka_msg, pq_n, pq_mk) = self.spqr_state.scka_ratchet_send_key()?;
        
        let mk = kdf_hybrid(ec_mk, pq_mk);

        let ec_header =  ECHeader::header(Some(self.ec_state.dhs), self.ec_state.pn, ec_ns)?;

        let scka_header = SPQRState::scka_header(scka_msg, pq_n);

        let tr_header = TRHeader{
            ec_header,
            scka_header
        };

        let ad_header = concat_ad_with_tr_header(*ad, &tr_header.scka_header, &tr_header.ec_header);

        let ct = encrypt(&mk, &plaintext, &ad_header);

        Ok((tr_header, ct))
    }
    #[hax_lib::opaque]
    pub fn tr_decrypt<'a> (&mut self, header: TRHeader, ct: Vec<u8>, ad: [u8; 64]) -> Result<String, &'a str>{
        let ad_header = concat_ad_with_tr_header(ad, &header.scka_header, &header.ec_header);
        let TRHeader {ec_header, scka_header} = header;
        
        let ec_mk = ratchet_receive_key(&mut self.ec_state, &ec_header);
        let pq_mk = self.spqr_state.scka_ratchet_receive_key(scka_header)?;
        let mk = kdf_hybrid(ec_mk, pq_mk);
        
        let plaintext = decrypt(&mk, &ct, &ad_header)?;
        
        let plaintext = if plaintext == "empty".to_string() {
                "".to_string()
            }else{
                plaintext
            };

        Ok(plaintext)
    }

    #[hax_lib::opaque]
    pub fn state_size (&self) -> usize {
        let ec_header_size = self.ec_state.state_size();
        let scka_header_size = self.spqr_state.state_size();

        ec_header_size + scka_header_size
    }
}

#[cfg(test)]
mod tests {
    use crate::pqxdh::pqxdh_impl;
    use crate::util::helper_func;
    use super::*;

    #[test]
    fn encrypt_and_decrypt () {
        let plaintext = "Hello from this universe";
        let ad_header = helper_func::make_randomness::<96>();
        let mk = helper_func::make_randomness::<32>();

        let ct = encrypt(&MessageKey(mk), plaintext, &ad_header.to_vec());

        let res_plaintext = decrypt(&MessageKey(mk), &ct, &ad_header.to_vec()).unwrap();

        assert_eq!(plaintext.to_string(), res_plaintext);
    }

    #[test]
    fn encrypt_and_decrypt_tampered () {
        let plaintext = "Hello from this universe";
        let ad_header = helper_func::make_randomness::<96>();
        let mk = helper_func::make_randomness::<32>();

        let ct = encrypt(&MessageKey(mk), plaintext, &ad_header.to_vec());

        let mut tampered = ct.clone();
        tampered[ct.len() / 2] ^= 0xFF;


        let res_plaintext = decrypt(&MessageKey(mk), &tampered, &ad_header.to_vec());

        assert!(res_plaintext.is_err());
    }
    
    #[test]
    fn encrypt_creates_longer_ct () {
        let plaintexts = ["".to_string(), "11".to_string(), "Hello from this universe".to_string(), "a".repeat(100), "a".repeat(1000)];
        let ad_header = helper_func::make_randomness::<96>();
        let mk = helper_func::make_randomness::<32>();
        
        println!("--------- Ciphertexts vs Plaintext lengths ---------");
        for plaintext in plaintexts {
            let ct = encrypt(&MessageKey(mk), plaintext.as_str(), &ad_header.to_vec());
            println!("Plaintext length: {}", plaintext.len());
            println!("Ciphertext length: {:?}", ct.len());
            println!("------------------------------------------------------")
        }
    }


    #[test]
    fn test_concat_ad_header_consistency() {
        let ad = [0u8; 64];
        let scka_header = SCKAMessageHeader::default(); // Assumes Default is implemented
        let ec_header = ECHeader::default();
        
        let result1 = concat_ad_with_tr_header(ad, &scka_header, &ec_header);
        let result2 = concat_ad_with_tr_header(ad, &scka_header, &ec_header);
        
        assert_eq!(result1, result2, "AD concatenation must be deterministic");
        assert!(result1.len() > 64, "Header must include AD and serialized headers");
    }

    #[test]
    fn test_kdf_hybrid_differentiation() {
        let mk_ec = MessageKey([1u8; 32]);
        let mk_pq = MessageKey([2u8; 32]);
        let mk_pq_alt = MessageKey([3u8; 32]);

        let key1 = kdf_hybrid(mk_ec, mk_pq);
        let key2 = kdf_hybrid(mk_ec, mk_pq_alt);

        assert_ne!(key1.0, key2.0, "Hybrid KDF must produce different keys for different inputs");
    }

    #[test]
    fn test_triple_ratchet_full_roundtrip() {
        // 1. Setup Keys/Shared Secrets (Mocking the result of an X3DH/PQXDH)
        let ss_ec = [0u8; SHARED_SECRET_SIZE];
        let ss_scka = [0u8; SHARED_SECRET_SIZE];
        
        

        // Generate Bob's DH Keypair for EC state init
        let bob_keypair = pqxdh_impl::gen_curve_key_pair(); 
        let bob_pub = bob_keypair.public_key;

        // 2. Initialize Alice and Bob
        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss_ec, ss_scka, bob_pub);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss_ec, ss_scka, bob_keypair);

        // 3. Alice Encrypts
        let plaintext = "Hello, Triple Ratchet!".to_string();
        let ad = [0u8; 64];
        
        let (tr_header, ciphertext) = alice.tr_encrypt(&plaintext, &ad)
            .expect("Encryption failed");

        // 4. Bob Decrypts
        let decrypted = bob.tr_decrypt( tr_header, ciphertext, ad)
            .expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    use proptest::prelude::*;
    

    proptest! {
    #[test]
    fn test_decryption_fails_with_bit_flip(
        plaintext in any::<String>(),
        ad in any::<[u8; 64]>()
    ) {
        
        use super::*;

        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_pk = pqxdh_impl::gen_curve_key_pair();
        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_pk.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_pk);

        
        let (header, mut ciphertext) = alice.tr_encrypt(&plaintext, &ad).unwrap();
        

        // Flip a bit in the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = bob.tr_decrypt(header, ciphertext, ad);
        assert!(result.is_err(), "Decryption should fail if ciphertext is tampered with");
    }

    #[test]
    fn test_always_decrypts_valid_data(
        plaintext in any::<String>(),
        ad in any::<[u8; 64]>()
    ) {
        
        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_kp = pqxdh_impl::gen_curve_key_pair();

        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_kp.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_kp);

        // Execute encryption
        let (header, ciphertext) = alice.tr_encrypt(&plaintext, &ad)
            .expect("Encryption should never fail on valid inputs");

        // Execute decryption
        let decrypted = bob.tr_decrypt(header, ciphertext, ad)
            .expect("Decryption should always succeed for valid, untampered data");
        assert_eq!(plaintext, decrypted);
    }
    }
    
    #[test]
    fn test_for_encrypting_with_empty_string() {
        let ad = [0u8; 64];
        let plaintext = "".to_string();

        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_pk = pqxdh_impl::gen_curve_key_pair();
        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_pk.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_pk);

        let (header, mut ciphertext) = alice.tr_encrypt(&plaintext, &ad).unwrap();
        

        // Flip a bit in the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = bob.tr_decrypt(header, ciphertext, ad);
        assert!(result.is_err(), "Decryption should fail if ciphertext is tampered with");

    }

    #[test]
    fn test_ad_mismatch_fails_decryption() {
        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_kp = pqxdh_impl::gen_curve_key_pair();

        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_kp.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_kp);

        let plaintext = "Top secret data".to_string();
        let correct_ad = [0xAA; 64];
        let wrong_ad = [0xBB; 64]; // Different AD

        let (header, ciphertext) = alice.tr_encrypt(&plaintext, &correct_ad).unwrap();

        // Bob attempts to decrypt with the wrong AD
        let result = bob.tr_decrypt(header, ciphertext, wrong_ad);
        
        assert!(result.is_err(), "Decryption MUST fail if the Associated Data does not match");
    }

    #[test]
    fn test_empty_plaintext_success() {
        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_kp = pqxdh_impl::gen_curve_key_pair();

        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_kp.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_kp);

        // Edge case: 0-byte message
        let plaintext: String = "".to_string(); 
        let ad = [0u8; 64];

        let (header, ciphertext) = alice.tr_encrypt(&plaintext.clone(), &ad).unwrap();
        let decrypted = bob.tr_decrypt(header, ciphertext, ad).unwrap();

        assert_eq!(plaintext, decrypted, "Should successfully encrypt and decrypt an empty plaintext");
    }

    #[test]
    fn test_multiple_sequential_messages() {
        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_kp = pqxdh_impl::gen_curve_key_pair();

        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_kp.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_kp);

        let ad = [0u8; 64];

        // Alice sends 3 messages consecutively (advances send chain without DH ratchet)
        for i in 1..=3 {
            let plaintext = format!("Message {}", i);
            let (header, ciphertext) = alice.tr_encrypt(&plaintext, &ad).unwrap();
            
            let decrypted = bob.tr_decrypt(header, ciphertext, ad).unwrap();
            assert_eq!(plaintext, decrypted, "Sequential message {} failed", i);
        }
    }

    #[test]
    fn test_ping_pong_bidirectional() {
        let ss = [0u8; SHARED_SECRET_SIZE];
        let bob_kp = pqxdh_impl::gen_curve_key_pair();

        let mut alice = TripleRatchetState::rathet_init_initiator_tr(ss, ss, bob_kp.public_key);
        let mut bob = TripleRatchetState::rathet_init_responder_tr(ss, ss, bob_kp);

        let ad = [0u8; 64];

        // Alice -> Bob
        let p1 = "Alice to Bob 1".to_string();
        let (h1, c1) = alice.tr_encrypt(&p1, &ad).unwrap();
        let d1 = bob.tr_decrypt(h1, c1, ad).unwrap();
        assert_eq!(p1, d1);

        // Bob -> Alice (Triggers DH Ratchet on Bob's side)
        let p2 = "Bob to Alice 1".to_string();
        let (h2, c2) = bob.tr_encrypt(&p2, &ad).unwrap();
        let d2 = alice.tr_decrypt(h2, c2, ad).unwrap();
        assert_eq!(p2, d2);

        // Alice -> Bob (Triggers DH Ratchet on Alice's side)
        let p3 = "Alice to Bob 2".to_string();
        let (h3, c3) = alice.tr_encrypt(&p3, &ad).unwrap();
        let d3 = bob.tr_decrypt(h3, c3, ad).unwrap();
        assert_eq!(p3, d3);
    }
}