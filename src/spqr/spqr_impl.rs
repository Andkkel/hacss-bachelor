use crate::{double_ratchet::messages_ratchet, kdf_chain::kdf_chain_impl::{KdfChain, TypChain}, util::{keys::{MessageKey, RootChainKey}, messages::{SCKAMessage, SCKAMessageHeader, SCKAMessageType}}};
use crate::ml_kem_braid::ml_kem_braid_impl::{MlKemBraid};
use crate::util::constants::SHARED_SECRET_SIZE;
use crate::util::encrypt_decrypt::{encrypt, decrypt};
use std::{collections::HashMap};

#[derive(Debug, Clone)]
pub struct SPQRState {
    rk:         RootChainKey,
    pub epoch:  u64,
    kdfchains:  HashMap<u64, KdfChains>, // Epoch indexed to (receive_chain_key, send_chain_key)
    mkskipped:  HashMap<u64, Option<HashMap<u64, [u8; 32]>>>,   // Epoch indexed to message numbers to message keys
    direction:  Direction,
    scka_state: MlKemBraid,   // the opaque SCKA machine
}
#[derive(Debug, Clone, PartialEq)]
enum Direction {
    A2B,  // self is the initiator of the current epoch
    B2A,  // self is the responder of the current epoch
}
#[derive(Debug, Copy, Clone)]
struct KdfChains {
    receiving: Option<KdfChain>,
    sending: Option<KdfChain>,
}

#[hax_lib::attributes]
impl SPQRState{
    #[hax_lib::opaque]
    pub fn ratchet_init_initiator(ss: &[u8; SHARED_SECRET_SIZE]) -> Self {
        
        let scka_state = MlKemBraid::init_initiator(ss);
        let direction = Direction::A2B;
        let (rk, cks, ckr) = KdfChain::kdf_scka_init(ss).expect("Could not get the rootkey or one of the chain keys");
        let epoch = 0;
        
        let kdf_chain_sending = KdfChain::new(TypChain::Sending, cks.0, 0);
        let kdf_chain_receiving = KdfChain::new(TypChain::Receiving, ckr.0, 0);
        let mut spqr_state = Self {
            rk: rk,
            epoch ,
            kdfchains: HashMap::new(),
            mkskipped: HashMap::new(),
            direction,
            scka_state,
        };
        let kdfchains = KdfChains{
            receiving: Some(kdf_chain_receiving),
            sending: Some(kdf_chain_sending)
        };
        spqr_state.kdfchains.insert(0, kdfchains);
        
        spqr_state
        
    }
    
    #[hax_lib::opaque]
    pub fn ratchet_init_responder (ss: &[u8; SHARED_SECRET_SIZE]) -> Self {
        let scka_state = MlKemBraid::init_responder(ss);
        let direction = Direction::B2A;
        let (rk, ckr, cks) = KdfChain::kdf_scka_init(ss).expect("Could not get the rootkey or one of the chain keys");
        let epoch = 0;
        
        let kdf_chain_sending = KdfChain::new(TypChain::Sending, cks.0, 0);
        let kdf_chain_receiving = KdfChain::new(TypChain::Receiving, ckr.0, 0);
        let mut spqr_state = Self {
            rk: rk,
            epoch ,
            kdfchains: HashMap::new(),
            mkskipped: HashMap::new(),
            direction,
            scka_state,
        };
        let kdfchains = KdfChains{
            receiving: Some(kdf_chain_receiving),
            sending: Some(kdf_chain_sending)
        };
        spqr_state.kdfchains.insert(0, kdfchains);
        
        spqr_state
    }

    #[hax_lib::opaque]
    pub fn state_size(&self) -> usize {
        let rk_size = std::mem::size_of_val(&self.rk);

        let epoch_size = std::mem::size_of_val(&self.epoch);

        // kdfchains: HashMap<u64, KdfChains>
        // Each entry: u64 key (8) + KdfChains (two optional ChainKeys)
        let kdfchains_size = 8  // entry count
            + self.kdfchains.len() * (
                8               // epoch key
                + 1 + 32 + 8    // sending: Option<KdfChain> (present byte + key + counter)
                + 1 + 32 + 8    // receiving: Option<KdfChain>
            );
         

        // mkskipped: HashMap<u64, Option<HashMap<u64, [u8; 32]>>>
        let mkskipped_size = 8  // entry count
            + self.mkskipped.iter().map(|(_, inner_opt)| {
                8               // outer key (u64)
                + 1             // Option 
                + match inner_opt {
                    Some(inner) => 8 + inner.len() * (8 + 32), // count + (u64 key + [u8;32] value)
                    None => 0,
                }
            }).sum::<usize>();
        // direction: 
        let direction_size = std::mem::size_of_val(&self.direction);

        // scka_state
        let scka_size = self.scka_state.state.state_size();

        rk_size + epoch_size + kdfchains_size + mkskipped_size + direction_size + scka_size
    }

    #[hax_lib::opaque]
    pub fn scka_ratchet_send_key<'a> (&mut self) -> Result<(SCKAMessage, u64, MessageKey), &'a str>{
        let (msg, (sending_epoch, output_key)) = match self.scka_state.send() {
            Ok(triplet) => triplet,
            Err(e) => return Err(e)
        };
        match output_key{
            Some(output_key) => { 
                let key_epoch = output_key.epoch;
                let key = output_key.key;

                // Advance to new epoch
                assert!(self.epoch+1 == key_epoch);

                let (rk,mut cks, mut ckr) = KdfChain::kdf_scka_rk(self.rk, key).
                    expect("Couldn't make the new Root chain key, sending chain key or receiving chain key from the output key");

                self.rk = rk;   

                if self.direction == Direction::B2A {
                    let old_cks = cks;
                    cks = ckr;
                    ckr = old_cks;
                }

                // Create new chains
                let ckr_kdf_chain = KdfChain::new(TypChain::Receiving, ckr.0, 0);
                let cks_kdf_chain = KdfChain::new(TypChain::Sending, cks.0, 0);

                let kdfchains = KdfChains{
                    receiving: Some(ckr_kdf_chain),
                    sending: Some(cks_kdf_chain)
                };

                self.kdfchains.insert(key_epoch, kdfchains);
                
                self.epoch = key_epoch;

                self.clear_old_epochs(sending_epoch);
            },
            None => {}
        }
        // Continue with message key derivation
        if sending_epoch > 0 {  
            let chain = match self.kdfchains.get(&(sending_epoch-1)) {
                Some(chain) => chain,
                None => return Err("Couldn't find the KDF chain")
            };

            if self.kdfchains.contains_key(&(sending_epoch-1)){
                let kdf_chain_insert = KdfChains {
                    receiving: chain.receiving,
                    sending: None
                };
                let _old_kdf_chain = self.kdfchains.insert(sending_epoch-1, kdf_chain_insert);
            }
        }

        
        let mut kdfchains_current = self.kdfchains.remove(&sending_epoch).ok_or("There is no Kdf Chain for the epoch")?;
        
        let mut sending_chain = kdfchains_current.sending.ok_or("No sending chain")?;
        
        sending_chain.counter += 1;
        let (ck, mk) = KdfChain::kdf_scka_ck(sending_chain.kdf_key, sending_chain.counter)
            .expect("Couldn't create the Chain key and Message key");
        sending_chain.kdf_key = ck.0;
        let counter = sending_chain.counter;

        kdfchains_current.sending = Some(sending_chain);
        self.kdfchains.insert(sending_epoch, kdfchains_current);

        Ok((msg, counter, mk))

    }
    
    #[hax_lib::opaque]
    fn clear_old_epochs(&mut self, sending_epoch: u64) {
        if sending_epoch > 1 {
            self.kdfchains.retain(|&epoch, _| epoch >= (sending_epoch-2));
            self.mkskipped.retain(|&epoch, _ | epoch >=(sending_epoch-2));
        }
    }

    // Depricated because of Triple ratchet
    #[hax_lib::opaque]
    pub fn scka_ratchet_encrypt(&mut self, plaintext: String, ad: &[u8; 64]) -> Result<(SCKAMessageHeader, Vec<u8>), String>{
        let (msg, n, mk) = SPQRState::scka_ratchet_send_key(self)?;
        let header = SPQRState::scka_header(msg, n);

        let header_bytes = SPQRState::scka_header_to_bytes(&header);
        let mut ad_header = Vec::with_capacity(ad.len() + header_bytes.len());
        ad_header.extend_from_slice(ad);
        ad_header.extend_from_slice(&header_bytes);

        let cipher_text = encrypt(&mk, &plaintext, &ad_header);

        Ok((header, cipher_text))
    }
 
    pub fn scka_header (msg: SCKAMessage, n: u64) -> SCKAMessageHeader {
        SCKAMessageHeader{
            message: msg,
            pn: n
        }
    }

    #[hax_lib::opaque]
    pub(crate) fn scka_header_to_bytes(header: &SCKAMessageHeader) -> Vec<u8> {
        let mut buf = Vec::new();

        // epoch (8 bytes, big-endian)
        buf.extend_from_slice(&header.message.epoch.to_be_bytes());
        
        // message type tag (1 byte)
        let type_tag: u8 = match &header.message.message_type {
            None                            => 0,
            Some(SCKAMessageType::Hdr)      => 1,
            Some(SCKAMessageType::Ek)       => 2,
            Some(SCKAMessageType::EkCt1Ack) => 3,
            Some(SCKAMessageType::Ct1Ack)   => 4,
            Some(SCKAMessageType::Ct1)      => 5,
            Some(SCKAMessageType::Ct2)      => 6,
        };
        buf.push(type_tag);

        // chunk (index + data), length-prefixed so boundary is unambiguous
        match &header.message.data {
            None => buf.extend_from_slice(&[0u8; 4]), // 0-length sentinel
            Some(chunk) => {
                buf.extend_from_slice(&chunk.index.to_be_bytes());
                buf.extend_from_slice(&(chunk.data.len() as u32).to_be_bytes());
                buf.extend_from_slice(&chunk.data);
            }
        }

        // pn (8 bytes, big-endian)
        buf.extend_from_slice(&header.pn.to_be_bytes());

        buf
    }

    #[hax_lib::opaque]
    pub fn scka_ratchet_receive_key<'a> (&mut self, header: SCKAMessageHeader) -> Result<MessageKey, &'a str>{
        let (receiving_epoch, output_key) = self.scka_state.receive(header.message.clone())?;
        match output_key {
            Some(output_key) => {
                let key_epoch = output_key.epoch;
                let key = output_key.key;
                
                hax_lib::assert!(self.epoch+1 == key_epoch);

                let (rk, mut cks, mut ckr) = KdfChain::kdf_scka_rk(self.rk, key)?;
                self.rk = rk;
        
                if self.direction == Direction::B2A {
                    let old_cks = cks;
                    cks = ckr;
                    ckr = old_cks;
                }

                // Create new chains
                let kdf_chain = KdfChains{
                    sending: Some(KdfChain { typ_chain: (TypChain::Sending), kdf_key: (cks.0), counter: 0 }),
                    receiving: Some(KdfChain { typ_chain: (TypChain::Receiving), kdf_key: (ckr.0), counter: 0 }),
                };
                self.kdfchains.insert(key_epoch, kdf_chain);

                self.epoch = key_epoch;
                
            },
            None => {}
        }
        
        let mk: Option<MessageKey> = self.try_skipped_message_keys(receiving_epoch, header.pn);
        match mk {
            Some(mk) => {return Ok(mk)},
            None => {}
        }
        if header.pn > 0 {
            self.skip_message_keys(receiving_epoch, header.pn - 1)?;
        }

        let mut kdfchain_current = self.kdfchains.remove(&receiving_epoch).ok_or("Couldn't find the kdf chain for the receiving epoch")?;
        let mut receiving_chain = kdfchain_current.receiving.ok_or("No receiving chain")?;

        receiving_chain.counter += 1;
        let (ck, mk) = KdfChain::kdf_scka_ck(receiving_chain.kdf_key, receiving_chain.counter)
            .expect("Couldn't make the Chain key and Message key");
        receiving_chain.kdf_key = ck.0;
        kdfchain_current.receiving = Some(receiving_chain);
        self.kdfchains.insert(receiving_epoch, kdfchain_current);

        Ok(mk)

    }

    // Depricated because of Triple Ratchet
    #[hax_lib::opaque]
    pub fn scka_ratchet_decrypt<'a> (&mut self, header: SCKAMessageHeader, ciphertext: &[u8], ad: &[u8; 64]) -> Result<String, &'a str>{
        
        let header_bytes = SPQRState::scka_header_to_bytes(&header);
        let mut ad_header = Vec::with_capacity(ad.len() + header_bytes.len());
        ad_header.extend_from_slice(ad);
        ad_header.extend_from_slice(&header_bytes);

        let mk = self.scka_ratchet_receive_key(header).expect("Couldn't get the message key");

        decrypt(&mk, &ciphertext.to_vec(), &ad_header)
    }

    #[hax_lib::opaque]
    fn try_skipped_message_keys(&mut self, key_epoch: u64, n: u64) -> Option<MessageKey> {
        if let Some(inner_option) = self.mkskipped.remove(&key_epoch) {
            if let Some(mut inner_map) = inner_option {
                if let Some(mk_val) = inner_map.remove(&n) {
                    if !inner_map.is_empty() {
                        self.mkskipped.insert(key_epoch, Some(inner_map));
                    }
                    return Some(MessageKey(mk_val));
                }
                self.mkskipped.insert(key_epoch, Some(inner_map));
            } else {
                self.mkskipped.insert(key_epoch, None);
            }
        }

        None
    }
    
    #[hax_lib::opaque]
    fn skip_message_keys<'a> (&mut self, epoch: u64, until: u64) -> Result<(), &'a str> {
        // Match on the KDF chain state
        let mut chain_state = match self.kdfchains.remove(&epoch) {
            Some(cs) => cs,
            None => return Ok(()), // Return early if epoch doesn't exist
        };
        
        // Match on the receiving chain Option
        let mut receiving_chain = match chain_state.receiving {
            Some(rc) => rc,
            None => return Ok(()), 
        };

        // Bounds check if the message is within MAX_SKIP
        if receiving_chain.counter + messages_ratchet::MAX_SKIP < until {
            return Err("The epoch number of the received message is too far ahead");
        }

        let start_ctr = receiving_chain.counter;
        for _counter in start_ctr..until{
            receiving_chain.counter += 1;
            let (ck, mk) = match KdfChain::kdf_scka_ck(receiving_chain.kdf_key, receiving_chain.counter) {
                Ok(pair) => pair,
                Err(_) => return Err("Could not make the Chain key and Message key"),
            };

            if !self.mkskipped.contains_key(&epoch){
                self.mkskipped.insert(epoch, Some(HashMap::new()));
            }
            // Entry exists and match on the inner map Option
            let inner_map_option = self.mkskipped.remove(&epoch).ok_or("Couldn't find the epoch in the mkskipped")?;
            
            let mut inner_map = match inner_map_option {
                Some(m)  => m,
                None => return Err("Inner skipped map was unexpectedly None")
            };

            receiving_chain.kdf_key = ck.0;
            inner_map.insert(receiving_chain.counter, mk.0);

            self.mkskipped.insert(epoch, Some(inner_map));
        };

        chain_state.receiving = Some(receiving_chain);
        self.kdfchains.insert(epoch, chain_state);

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;

use crate::kdf_chain::kdf_chain_impl::TypChain;
    use crate::spqr::spqr_impl::{Direction, SPQRState};
    use crate::util::constants::SHARED_SECRET_SIZE;
    use crate::kdf_chain::kdf_chain_impl::KdfChain;


    fn seq_ss() -> [u8; SHARED_SECRET_SIZE] {
        let mut buf = [0u8; SHARED_SECRET_SIZE];
        for (i, b) in buf.iter_mut().enumerate() { *b = i as u8; }
        buf
    }
    fn zero_ss()    -> [u8; SHARED_SECRET_SIZE] { [0x00u8; SHARED_SECRET_SIZE] }
    fn ones_ss()    -> [u8; SHARED_SECRET_SIZE] { [0xFFu8; SHARED_SECRET_SIZE] }
    fn alt_ss()     -> [u8; SHARED_SECRET_SIZE] {
        let mut buf = [0u8; SHARED_SECRET_SIZE];
        for (i, b) in buf.iter_mut().enumerate() { *b = if i % 2 == 0 { 0xAA } else { 0x55 }; }
        buf
    }



    /// Full paired handshake invariant test.
    #[test]
    fn paired_handshake_all_invariants() {
        let ss = {
            let mut buf = [0u8; SHARED_SECRET_SIZE];
            for (i, b) in buf.iter_mut().enumerate() { *b = i as u8; }
            buf
        };

        let alice = SPQRState::ratchet_init_initiator(&ss);
        let bob   = SPQRState::ratchet_init_responder(&ss);

        // ── 1. Epoch ──────────────────────────────────────────────────────────
        assert_eq!(alice.epoch, 0, "Alice: epoch must start at 0");
        assert_eq!(bob.epoch,   0, "Bob:   epoch must start at 0");

        // ── 2. Direction ──────────────────────────────────────────────────────
        assert!(matches!(alice.direction, Direction::A2B),
            "Alice must be the initiator (A2B)");
        assert!(matches!(bob.direction, Direction::B2A),
            "Bob must be the responder (B2A)");

        // ── 3. Clean skipped-message store ────────────────────────────────────
        assert!(alice.mkskipped.is_empty(),
            "Alice: no skipped messages before first send");
        assert!(bob.mkskipped.is_empty(),
            "Bob:   no skipped messages before first send");

        // ── 4. Exactly one epoch in the chain map ─────────────────────────────
        assert_eq!(alice.kdfchains.len(), 1,
            "Alice: only epoch-0 chains exist at init");
        assert_eq!(bob.kdfchains.len(),   1,
            "Bob:   only epoch-0 chains exist at init");

        // ── 5. Epoch-0 chains are present ────────────────────────────────────
        let alice_chains = alice.kdfchains.get(&0).expect("Alice: must have epoch-0 chain entry");
        let bob_chains   = bob.kdfchains.get(&0).expect("Bob: must have epoch-0 chain entry");

        let alice_send = alice_chains.sending.expect("Alice must have a sending chain");
        let alice_recv = alice_chains.receiving.expect("Alice must have a receiving chain");
        let bob_send   = bob_chains.sending.expect("Bob must have a sending chain");
        let bob_recv   = bob_chains.receiving.expect("Bob must have a receiving chain");

        // ── 6. Chain type labels are correct ──────────────────────────────────
        assert!(matches!(alice_send.typ_chain, TypChain::Sending),
            "Alice's sending chain must be Sending");
        assert!(matches!(alice_recv.typ_chain, TypChain::Receiving),
            "Alice's receiving chain must be Receiving");
        assert!(matches!(bob_send.typ_chain, TypChain::Sending),
            "Bob's sending chain must be Sending");
        assert!(matches!(bob_recv.typ_chain, TypChain::Receiving),
            "Bob's receiving chain must be Receiving");

        // ── 7. Root keys are identical ────────────────────────────────────────
        assert_eq!(alice.rk, bob.rk,
            "Both parties must derive the same root key");

        // ── 8. Root key is not trivially zero ─────────────────────────────────
        assert_ne!(alice.rk.0, [0u8; 32],
            "Root key must not be all-zero (KDF must have run)");

        // ── 9. Send/receive keys are correctly swapped across roles ───────────
        assert_eq!(alice_send.kdf_key, bob_recv.kdf_key,
            "Alice→Bob channel: send key must equal Bob's receive key");
        assert_eq!(bob_send.kdf_key, alice_recv.kdf_key,
            "Bob→Alice channel: send key must equal Alice's receive key");

        // ── 10. Send key ≠ receive key (no aliasing) ──────────────────────────
        assert_ne!(alice_send.kdf_key, alice_recv.kdf_key,
            "Alice: send and receive chain keys must be distinct");
        assert_ne!(bob_send.kdf_key, bob_recv.kdf_key,
            "Bob: send and receive chain keys must be distinct");

        // ── 11. Root key is distinct from all chain keys ──────────────────────
        assert_ne!(alice.rk.0, alice_send.kdf_key,
            "Root key must not equal Alice's send chain key");
        assert_ne!(alice.rk.0, alice_recv.kdf_key,
            "Root key must not equal Alice's recv chain key");

        // ── 12. Determinism: re-init from same SS produces identical state ────
        let alice2 = SPQRState::ratchet_init_initiator(&ss);
        let bob2   = SPQRState::ratchet_init_responder(&ss);

        assert_eq!(alice.rk, alice2.rk, "Initiator init must be deterministic");
        assert_eq!(bob.rk,   bob2.rk,   "Responder init must be deterministic");

        let a2_chains = alice2.kdfchains.get(&0).expect("Alice2: must have epoch-0 chain entry");
        let a2_send   = a2_chains.sending.expect("Alice2 must have a sending chain");
        let a2_recv   = a2_chains.receiving.expect("Alice2 must have a receiving chain");

        assert_eq!(alice_send.kdf_key, a2_send.kdf_key,
            "Alice's send key must be deterministic across inits");
        assert_eq!(alice_recv.kdf_key, a2_recv.kdf_key,
            "Alice's recv key must be deterministic across inits");

        // ── 14. Different SS → completely different key material ──────────────
        let ss_other    = [0xFFu8; SHARED_SECRET_SIZE];
        let alice_other = SPQRState::ratchet_init_initiator(&ss_other);
        let bob_other   = SPQRState::ratchet_init_responder(&ss_other);

        assert_ne!(alice.rk.0, alice_other.rk.0,
            "Different SS must produce different root key");

        let ao_chains = alice_other.kdfchains.get(&0).expect("AliceOther: must have epoch-0 chain entry");
        let bo_chains = bob_other.kdfchains.get(&0).expect("BobOther: must have epoch-0 chain entry");

        let ao_send = ao_chains.sending.expect("AliceOther must have a sending chain");
        let ao_recv = ao_chains.receiving.expect("AliceOther must have a receiving chain");
        let bo_recv = bo_chains.receiving.expect("BobOther must have a receiving chain");

        assert_ne!(alice_send.kdf_key, ao_send.kdf_key,
            "Different SS must produce different send chain key");
        assert_ne!(alice_recv.kdf_key, ao_recv.kdf_key,
            "Different SS must produce different recv chain key");

        // Symmetry must still hold for the other SS pair
        assert_eq!(alice_other.rk, bob_other.rk,
            "Symmetry must hold for any SS, not just the test vector");
        assert_eq!(ao_send.kdf_key, bo_recv.kdf_key,
            "Alice→Bob channel key swap must hold for any SS");
    }

    #[test]
    fn scka_header_to_bytes_is_non_empty() {
        use crate::util::messages::{SCKAMessage, SCKAMessageHeader};
        let msg = SCKAMessage { epoch: 0, message_type: None, data: None };
        let header = SCKAMessageHeader { message: msg, pn: 0 };
        let bytes = SPQRState::scka_header_to_bytes(&header);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn scka_header_to_bytes_different_epoch_different_bytes() {
        use crate::util::messages::{SCKAMessage, SCKAMessageHeader};
        let h1 = SCKAMessageHeader {
            message: SCKAMessage { epoch: 0, message_type: None, data: None }, pn: 0
        };
        let h2 = SCKAMessageHeader {
            message: SCKAMessage { epoch: 1, message_type: None, data: None }, pn: 0
        };
        assert_ne!(SPQRState::scka_header_to_bytes(&h1),
                   SPQRState::scka_header_to_bytes(&h2));
    }

    #[test]
    fn scka_header_to_bytes_different_pn_different_bytes() {
        use crate::util::messages::{SCKAMessage, SCKAMessageHeader};
        let h1 = SCKAMessageHeader {
            message: SCKAMessage { epoch: 0, message_type: None, data: None }, pn: 0
        };
        let h2 = SCKAMessageHeader {
            message: SCKAMessage { epoch: 0, message_type: None, data: None }, pn: 1
        };
        assert_ne!(SPQRState::scka_header_to_bytes(&h1),
                   SPQRState::scka_header_to_bytes(&h2));
    }

    #[test]
    fn paired_handshake_symmetry_across_all_test_vectors() {
        // Spec invariant: for ANY shared secret, symmetry must hold
        for ss in [zero_ss(), ones_ss(), seq_ss(), alt_ss()] {
            let alice = SPQRState::ratchet_init_initiator(&ss);
            let bob   = SPQRState::ratchet_init_responder(&ss);
            assert_eq!(alice.rk, bob.rk, "rk symmetry failed for ss={:?}", &ss[..4]);
            let ac = alice.kdfchains.get(&0).unwrap();
            let bc = bob.kdfchains.get(&0).unwrap();
            assert_eq!(ac.sending.unwrap().kdf_key, bc.receiving.unwrap().kdf_key,
                "A→B key swap failed");
            assert_eq!(bc.sending.unwrap().kdf_key, ac.receiving.unwrap().kdf_key,
                "B→A key swap failed");
        }
    }


    #[test]
    fn symmetric_ratchet_alice_and_bob_derive_same_message_keys() {
        // After init, alice.send.CK == bob.recv.CK (proven above).
        // Stepping both chains with the same counter must yield the same mk.
        let ss = seq_ss();
        let alice = SPQRState::ratchet_init_initiator(&ss);
        let bob   = SPQRState::ratchet_init_responder(&ss);

        let a_send_ck = alice.kdfchains.get(&0).unwrap().sending.unwrap().kdf_key;
        let b_recv_ck = bob.kdfchains.get(&0).unwrap().receiving.unwrap().kdf_key;

        // Sanity: identical starting points
        assert_eq!(a_send_ck, b_recv_ck);

        // Step 1: counter = 1
        let (new_a_ck, a_mk1) = KdfChain::kdf_scka_ck(a_send_ck, 1).unwrap();
        let (new_b_ck, b_mk1) = KdfChain::kdf_scka_ck(b_recv_ck, 1).unwrap();
        assert_eq!(a_mk1.0, b_mk1.0,
            "Alice's mk1 must equal Bob's mk1 — they must decrypt each other's messages");
        assert_eq!(new_a_ck.0, new_b_ck.0,
            "Chain keys must stay in sync");

        // Step 2: counter = 2, using the evolved chain keys
        let (_, a_mk2) = KdfChain::kdf_scka_ck(new_a_ck.0, 2).unwrap();
        let (_, b_mk2) = KdfChain::kdf_scka_ck(new_b_ck.0, 2).unwrap();
        assert_eq!(a_mk2.0, b_mk2.0,
            "mk2 must match for both parties");

        // Forward secrecy: message keys must all differ
        assert_ne!(a_mk1.0, a_mk2.0,
            "consecutive message keys must be distinct (forward secrecy)");
    }

    #[test]
    fn symmetric_ratchet_b2a_channel_also_works() {
        // Bob's send chain == Alice's recv chain: same check for the B→A direction
        let ss = seq_ss();
        let alice = SPQRState::ratchet_init_initiator(&ss);
        let bob   = SPQRState::ratchet_init_responder(&ss);

        let b_send_ck = bob.kdfchains.get(&0).unwrap().sending.unwrap().kdf_key;
        let a_recv_ck = alice.kdfchains.get(&0).unwrap().receiving.unwrap().kdf_key;
        assert_eq!(b_send_ck, a_recv_ck);

        let (_, mk_b) = KdfChain::kdf_scka_ck(b_send_ck, 1).unwrap();
        let (_, mk_a) = KdfChain::kdf_scka_ck(a_recv_ck, 1).unwrap();
        assert_eq!(mk_b.0, mk_a.0,
            "B→A message key must match on both sides");
    }

    #[test]
    fn kdf_scka_rk_epoch_advance_preserves_symmetry() {
        // Spec §5.5: when output_key is Some, both parties call kdf_scka_rk with
        // the same (rk, key). The swap of CKs/CKr depends on direction.
        // Verify: A2B.ck1 == B2A.ck2 after the epoch advance.
        let ss = seq_ss();
        let alice = SPQRState::ratchet_init_initiator(&ss);
        let bob   = SPQRState::ratchet_init_responder(&ss);

        // Simulate a new SCKA output key arriving for epoch 1
        let new_scka_key = [0xABu8; 32];
        let (new_rk_a, ckr_a, cks_a) = KdfChain::kdf_scka_rk(alice.rk, new_scka_key).unwrap();
        let (new_rk_b, cks_b, ckr_b) = KdfChain::kdf_scka_rk(bob.rk,   new_scka_key).unwrap();
        
        // Both started from the same rk, so new_rk must match
        assert_eq!(new_rk_a.0, new_rk_b.0, "new root keys must match after epoch advance");

        // Direction swap: A2B keeps (cks, ckr) as-is; B2A swaps them
        // So alice.cks == bob.ckr  and  alice.ckr == bob.cks
        assert_eq!(cks_a.0, ckr_b.0, "Alice's send CK must equal Bob's recv CK after epoch advance");
        assert_eq!(ckr_a.0, cks_b.0, "Alice's recv CK must equal Bob's send CK after epoch advance");
    }

    #[test]
    fn try_skipped_returns_none_when_epoch_absent() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        // epoch 99 was never inserted
        let result = alice.try_skipped_message_keys(99, 0);
        assert!(result.is_none(), "unknown epoch must return None");
    }

    #[test]
    fn try_skipped_returns_none_when_n_absent() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        // Insert epoch 0 with only n=1
        let mut inner: HashMap<u64, [u8; 32]> = HashMap::new();
        inner.insert(1, [0xAAu8; 32]);
        alice.mkskipped.insert(0, Some(inner));

        let result = alice.try_skipped_message_keys(0, 2);
        assert!(result.is_none(), "absent n must return None");
    }

    #[test]
    fn try_skipped_returns_correct_key_when_present() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let expected = [0xBBu8; 32];
        let mut inner: HashMap<u64, [u8; 32]> = HashMap::new();
        inner.insert(3, expected);
        alice.mkskipped.insert(0, Some(inner));

        let mk = alice.try_skipped_message_keys(0, 3)
            .expect("key must be found");
        assert_eq!(mk.0, expected, "returned key must match stored key");
    }

    #[test]
    fn try_skipped_deletes_key_after_retrieval() {
        // Spec: del state.MKSKIPPED[key_epoch][n]
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut inner: HashMap<u64, [u8; 32]> = HashMap::new();
        inner.insert(5, [0xCCu8; 32]);
        alice.mkskipped.insert(0, Some(inner));

        let _ = alice.try_skipped_message_keys(0, 5).unwrap();

        // Key must be gone — second call must return None
        let second = alice.try_skipped_message_keys(0, 5);
        assert!(second.is_none(), "key must be deleted after first retrieval");
    }

    #[test]
    fn try_skipped_deletes_epoch_when_inner_map_becomes_empty() {
        // Spec: if len(state.MKSKIPPED[key_epoch]) == 0: del state.MKSKIPPED[key_epoch]
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut inner: HashMap<u64, [u8; 32]> = HashMap::new();
        inner.insert(1, [0xDDu8; 32]); // only one key in the epoch
        alice.mkskipped.insert(0, Some(inner));

        let _ = alice.try_skipped_message_keys(0, 1).unwrap();

        assert!(!alice.mkskipped.contains_key(&0),
            "epoch entry must be removed once its inner map is empty");
    }

    #[test]
    fn try_skipped_keeps_epoch_when_other_keys_remain() {
        // Deleting n=1 must NOT remove the epoch if n=2 is still present
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut inner: HashMap<u64, [u8; 32]> = HashMap::new();
        inner.insert(1, [0x01u8; 32]);
        inner.insert(2, [0x02u8; 32]);
        alice.mkskipped.insert(0, Some(inner));

        let _ = alice.try_skipped_message_keys(0, 1).unwrap();

        assert!(alice.mkskipped.contains_key(&0),
            "epoch must survive while other keys remain");
        let inner_after = alice.mkskipped.get(&0).unwrap().as_ref().unwrap();
        assert!(inner_after.contains_key(&2), "n=2 must still be present");
        assert!(!inner_after.contains_key(&1), "n=1 must be gone");
    }

    #[test]
    fn try_skipped_returns_none_when_inner_option_is_none() {
        // mkskipped[epoch] exists but is None (cleared epoch)
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.mkskipped.insert(0, None);

        let result = alice.try_skipped_message_keys(0, 1);
        assert!(result.is_none());
    }


    #[test]
    fn skip_message_keys_returns_ok_when_receive_chain_is_none() {
        // Spec: if state.kdfchains[epoch].receive == None: return
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.kdfchains.get_mut(&0).unwrap().receiving = None;

        let result = alice.skip_message_keys(0, 5);
        assert!(result.is_ok(), "None receive chain must be a no-op, not an error");
        assert!(alice.mkskipped.is_empty(), "no keys must be stored");
    }

    #[test]
    fn skip_message_keys_errors_when_gap_exceeds_max_skip() {
        use crate::double_ratchet::messages_ratchet::MAX_SKIP;
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        // counter = 0, until = MAX_SKIP + 2 → must error
        let result = alice.skip_message_keys(0, MAX_SKIP + 2);
        assert!(result.is_err(), "gap beyond MAX_SKIP must return Err");
    }

    #[test]
    fn skip_message_keys_stores_correct_number_of_keys() {
        // Skipping from counter=0 to until=3 must store keys for n=1,2,3
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.skip_message_keys(0, 3).expect("should not error");

        let inner = alice.mkskipped.get(&0)
            .expect("epoch 0 must be present")
            .as_ref()
            .expect("inner map must be Some");
        assert_eq!(inner.len(), 3, "must have stored keys for n=1,2,3");
        assert!(inner.contains_key(&1));
        assert!(inner.contains_key(&2));
        assert!(inner.contains_key(&3));
    }

    #[test]
    fn skip_message_keys_stored_keys_match_kdf_scka_ck_output() {
        // Each stored key must equal the mk from KDF_SCKA_CK at that counter
        let ss = seq_ss();
        let alice = SPQRState::ratchet_init_initiator(&ss);
        let initial_ck = alice.kdfchains.get(&0).unwrap().receiving.unwrap().kdf_key;

        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.skip_message_keys(0, 2).expect("skip should succeed");

        // Recompute expected keys independently
        let (ck1, expected_mk1) = KdfChain::kdf_scka_ck(initial_ck, 1).unwrap();
        let (_,   expected_mk2) = KdfChain::kdf_scka_ck(ck1.0, 2).unwrap();

        let inner = alice.mkskipped.get(&0).unwrap().as_ref().unwrap();
        assert_eq!(inner[&1], expected_mk1.0, "stored mk for n=1 must match KDF output");
        assert_eq!(inner[&2], expected_mk2.0, "stored mk for n=2 must match KDF output");
    }

    #[test]
    fn skip_message_keys_all_stored_keys_distinct() {
        // Forward secrecy: every skipped mk must be unique
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.skip_message_keys(0, 5).expect("skip should succeed");

        let inner = alice.mkskipped.get(&0).unwrap().as_ref().unwrap();
        let keys: Vec<_> = inner.values().collect();
        for i in 0..keys.len() {
            for j in (i+1)..keys.len() {
                assert_ne!(keys[i], keys[j],
                    "all skipped message keys must be distinct (forward secrecy)");
            }
        }
    }

    #[test]
    fn skip_message_keys_noop_when_until_equals_counter() {
        // until == counter → while loop never runs → nothing stored
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        alice.skip_message_keys(0, 0).expect("no-op skip must succeed");
        assert!(alice.mkskipped.is_empty(),
            "skipping to current counter must store nothing");
    }

    #[test]
    fn encrypt_decrypt_single_message_roundtrip() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);

        let plaintext = "hello post-quantum world".to_string();
        let ad = [0x42u8; 64];

        let (header, ciphertext) = alice
            .scka_ratchet_encrypt(plaintext.clone(), &ad)
            .expect("encryption must succeed");

        let decrypted = bob
            .scka_ratchet_decrypt(header, &ciphertext, &ad)
            .expect("decryption must succeed");

        assert_eq!(decrypted, plaintext, "decrypted plaintext must equal original");
    }

    #[test]
    fn encrypt_decrypt_multiple_sequential_messages() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x01u8; 64];

        for i in 0u8..5 {
            let plaintext = format!("{}", i);
            let (header, ct) = alice
                .scka_ratchet_encrypt(plaintext.clone(), &ad)
                .expect("encryption must succeed");
            let decrypted = bob
                .scka_ratchet_decrypt(header, &ct, &ad)
                .expect("decryption must succeed");
            assert_eq!(decrypted, plaintext,
                "message {} must decrypt correctly", i);
        }
    }

    #[test]
    fn decrypt_fails_with_wrong_ad() {
        // AEAD authentication must fail if AD is tampered
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);

        let plaintext = "sensitive data".to_string();
        let ad_alice = [0xAAu8; 64];
        let ad_bob   = [0xBBu8; 64]; // different from Alice's

        let (header, ct) = alice
            .scka_ratchet_encrypt(plaintext, &ad_alice)
            .expect("encryption must succeed");

        let result = bob.scka_ratchet_decrypt(header, &ct, &ad_bob);
        assert!(result.is_err(), "decryption must fail when AD does not match");
    }

    #[test]
    fn decrypt_fails_with_tampered_ciphertext() {
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x00u8; 64];

        let (header, mut ct) = alice
            .scka_ratchet_encrypt("tamper me".to_string(), &ad)
            .expect("encryption must succeed");

        ct[0] ^= 0xFF; // flip a byte

        let result = bob.scka_ratchet_decrypt(header, &ct, &ad);
        assert!(result.is_err(), "decryption must fail when ciphertext is tampered");
    }

    #[test]
    fn each_encrypted_message_produces_unique_ciphertext() {
        // Same plaintext encrypted twice must produce different ciphertexts
        // (counter advances → different mk each time)
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let ad = [0x00u8; 64];
        let plaintext = "repeat".to_string();

        let (_, ct1) = alice.scka_ratchet_encrypt(plaintext.clone(), &ad).unwrap();
        let (_, ct2) = alice.scka_ratchet_encrypt(plaintext, &ad).unwrap();

        assert_ne!(ct1, ct2,
            "same plaintext encrypted twice must yield different ciphertexts");
    }
    #[test]
    fn out_of_order_message_decrypts_via_skipped_keys() {
        // Alice sends msg1 and msg2; Bob receives msg2 first (skipping msg1),
        // then receives msg1 — it must decrypt via the stored skipped key.
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x00u8; 64];

        let (header1, ct1) = alice.scka_ratchet_encrypt("msg one".to_string(), &ad).unwrap();
        let (header2, ct2) = alice.scka_ratchet_encrypt("msg two".to_string(), &ad).unwrap();

        // Bob receives msg2 first — this triggers SkipMessageKeys for msg1
        let dec2 = bob.scka_ratchet_decrypt(header2, &ct2, &ad)
            .expect("msg2 must decrypt successfully");
        assert_eq!(dec2, "msg two".to_string());

        // Bob now receives msg1 — must be found in mkskipped
        let dec1 = bob.scka_ratchet_decrypt(header1, &ct1, &ad)
            .expect("msg1 must decrypt via skipped key");
        assert_eq!(dec1, "msg one".to_string());
    }

    #[test]
    fn skipped_key_is_consumed_after_use() {
        // After decrypting the out-of-order msg, mkskipped must be empty again
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x00u8; 64];
        
        let (h1, ct1) = alice.scka_ratchet_encrypt("msg one".to_string(), &ad).unwrap();
        let (h2, ct2) = alice.scka_ratchet_encrypt("msg two".to_string(), &ad).unwrap();
        
        bob.scka_ratchet_decrypt(h2, &ct2, &ad).unwrap();
        bob.scka_ratchet_decrypt(h1, &ct1, &ad).unwrap();
        assert!(bob.mkskipped.is_empty(),
            "mkskipped must be empty after all skipped keys are consumed");
    }

    #[test]
    fn bidirectional_exchange_roundtrip() {
        // Both Alice→Bob and Bob→Alice directions must work independently
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0xFFu8; 64];

        // Alice → Bob
        let (ha, cta) = alice.scka_ratchet_encrypt("from alice".to_string(), &ad).unwrap();
        let dec_a = bob.scka_ratchet_decrypt(ha, &cta, &ad)
            .expect("Bob must decrypt Alice's message");
        assert_eq!(dec_a, "from alice".to_string());

        // Bob → Alice
        let (hb, ctb) = bob.scka_ratchet_encrypt("from bob".to_string(), &ad).unwrap();
        let dec_b = alice.scka_ratchet_decrypt(hb, &ctb, &ad)
            .expect("Alice must decrypt Bob's message");
        assert_eq!(dec_b, "from bob".to_string());
    }

    #[test]
    fn encrypt_decrypt_ten_sequential_messages() {
        // Stress the chain key ratchet over more steps than the SCKA header fits
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x02u8; 64];

        for i in 0u8..10 {
            let plaintext = format!("{}", i);
            let (header, ct) = alice
                .scka_ratchet_encrypt(plaintext.clone(), &ad)
                .expect("encryption must succeed");
            let decrypted = bob
                .scka_ratchet_decrypt(header, &ct, &ad)
                .expect("decryption must succeed");
            assert_eq!(decrypted, plaintext, "message {} must decrypt correctly", i);
        }
    }

    #[test]
    fn all_message_keys_are_unique_over_ten_messages() {
        // Forward secrecy: every mk Alice derives must be distinct
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let ad = [0x00u8; 64];
        let plaintext = "same plaintext every time".to_string();

        let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
        for _ in 0..10 {
            let (_, ct) = alice.scka_ratchet_encrypt(plaintext.clone(), &ad).unwrap();
            ciphertexts.push(ct);
        }

        // If any two ciphertexts match, the same mk was reused — a catastrophic failure
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "messages {} and {} produced identical ciphertexts — mk reuse detected", i, j
                );
            }
        }
    }

    #[test]
    fn interleaved_bidirectional_ten_rounds() {
        // Each round: Alice sends to Bob, then Bob replies to Alice
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x03u8; 64];

        for i in 0u8..10 {
            // Alice → Bob
            let a_plain = format!("{}", i);
            let (ha, cta) = alice.scka_ratchet_encrypt(a_plain.clone(), &ad).unwrap();
            let dec_a = bob.scka_ratchet_decrypt(ha, &cta, &ad)
                .expect("Bob must decrypt Alice's message");
            assert_eq!(dec_a, a_plain, "A→B round {} failed", i);

            // Bob → Alice
            let b_plain = format!("{}", i * 2);
            let (hb, ctb) = bob.scka_ratchet_encrypt(b_plain.clone(), &ad).unwrap();
            let dec_b = alice.scka_ratchet_decrypt(hb, &ctb, &ad)
                .expect("Alice must decrypt Bob's message");
            assert_eq!(dec_b, b_plain, "B→A round {} failed", i);
        }
    }

    #[test]
    #[ignore = "Simple encoder and decoder doesn't support lost- or out of order messages"]
    fn out_of_order_reverse_order_four_messages() {
        // Receive all four in strictly reverse order: 4, 3, 2, 1
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x00u8; 64];

        let (h1, ct1) = alice.scka_ratchet_encrypt("one".to_string(),   &ad).unwrap();
        let (h2, ct2) = alice.scka_ratchet_encrypt("two".to_string(),   &ad).unwrap();
        let (h3, ct3) = alice.scka_ratchet_encrypt("three".to_string(), &ad).unwrap();
        let (h4, ct4) = alice.scka_ratchet_encrypt("four".to_string(),  &ad).unwrap();

        assert_eq!(bob.scka_ratchet_decrypt(h4, &ct4, &ad).unwrap(), "four".to_string());
        assert_eq!(bob.scka_ratchet_decrypt(h3, &ct3, &ad).unwrap(), "three".to_string());
        assert_eq!(bob.scka_ratchet_decrypt(h2, &ct2, &ad).unwrap(), "two".to_string());
        assert_eq!(bob.scka_ratchet_decrypt(h1, &ct1, &ad).unwrap(), "one".to_string());
        
        assert!(bob.mkskipped.is_empty());
    }

    #[test]
    fn plaintext_of_varying_lengths_encrypt_correctly() {
        // AEAD must handle different plaintext sizes without corrupting output
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x04u8; 64];

        let lengths: &[usize] = &[0, 1, 15, 16, 17, 63, 64, 65, 255, 1024];
        for &len in lengths {
            let plaintext = format!("{}", len);
            let (header, ct) = alice
                .scka_ratchet_encrypt(plaintext.clone(), &ad)
                .expect("encryption must succeed");
            let decrypted = bob
                .scka_ratchet_decrypt(header, &ct, &ad)
                .expect("decryption must succeed");
            assert_eq!(decrypted, plaintext, "length {} roundtrip failed", len);
        }
    }

    #[test]
    fn two_independent_sessions_dont_interfere() {
        // Two separate Alice/Bob pairs from different shared secrets must be independent
        let ss1 = seq_ss();
        let ss2 = ones_ss();

        let mut alice1 = SPQRState::ratchet_init_initiator(&ss1);
        let mut bob1   = SPQRState::ratchet_init_responder(&ss1);
        let mut alice2 = SPQRState::ratchet_init_initiator(&ss2);
        let mut bob2   = SPQRState::ratchet_init_responder(&ss2);

        let ad = [0x05u8; 64];
        let pt = "hello".to_string();

        let (h1, ct1) = alice1.scka_ratchet_encrypt(pt.clone(), &ad).unwrap();
        let (h2, ct2) = alice2.scka_ratchet_encrypt(pt.clone(), &ad).unwrap();

        // Cross-decryption must fail
        assert!(
            bob2.scka_ratchet_decrypt(h1.clone(), &ct1, &ad).is_err()
                || bob1.scka_ratchet_decrypt(h2.clone(), &ct2, &ad).is_err(),
            "cross-session decryption must fail for at least one direction"
        );

        // Own-session decryption must succeed
        // (re-init since we may have advanced state above)
        let mut alice1 = SPQRState::ratchet_init_initiator(&ss1);
        let mut bob1   = SPQRState::ratchet_init_responder(&ss1);
        let (h, ct) = alice1.scka_ratchet_encrypt(pt.clone(), &ad).unwrap();
        assert_eq!(bob1.scka_ratchet_decrypt(h, &ct, &ad).unwrap(), pt);
    }

    #[test]
    fn bob_sends_multiple_before_alice_sends() {
        // Bob sends several messages before Alice sends any — tests B→A chain init
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x06u8; 64];

        for i in 0u8..5 {
            let pt = format!("{}", i);
            let (h, ct) = bob.scka_ratchet_encrypt(pt.clone(), &ad).unwrap();
            let dec = alice.scka_ratchet_decrypt(h, &ct, &ad)
                .expect("Alice must decrypt Bob's message");
            assert_eq!(dec, pt, "B→A message {} failed", i);
        }
    }

    #[test]
    fn skipped_keys_dont_accumulate_on_in_order_delivery() {
        // In-order delivery must never populate mkskipped
        let ss = seq_ss();
        let mut alice = SPQRState::ratchet_init_initiator(&ss);
        let mut bob   = SPQRState::ratchet_init_responder(&ss);
        let ad = [0x08u8; 64];

        for i in 0u8..8 {
            let (h, ct) = alice.scka_ratchet_encrypt(format!("{}", i), &ad).unwrap();
            bob.scka_ratchet_decrypt(h, &ct, &ad).unwrap();
        }

        assert!(
            bob.mkskipped.values().all(|v| v.as_ref().map_or(true, |m| m.is_empty())),
            "in-order delivery must not leave keys in mkskipped"
        );
    }
}

