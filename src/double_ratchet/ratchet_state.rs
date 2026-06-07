use std::collections::HashMap;
use crate::{kdf_chain::kdf_chain_impl::KdfChain, util::{keys::{ChainKey, MessageKey, RootChainKey, X25519KeyPair, X25519PublicKey}, libcrux_wrap}};
use crate::pqxdh::pqxdh_impl;
use std::fmt;

#[derive(Debug, Clone)]
pub struct StateDHRatchet {
    pub(crate) dhs: X25519KeyPair,     // Own DH Ratchet key pair
    pub(crate) dhr: Option<X25519PublicKey>,   // DH Ratchet public key, received from other party

    pub(crate) rk: RootChainKey,
    pub(crate) ckr: Option<ChainKey>,
    pub(crate) cks: Option<ChainKey>,
    pub(crate) ns: u64,    // Number of sent messages in current sending chain
    pub(crate) nr: u64,    // Number of received messages in current receiving chain
    pub(crate) pn: u64,    // Number of messages in previous sending chain
    
    // Dictionary of skipped-over-messages, indexed by rachet public key and message number. Raises an exception if too many elements are stored
    pub(crate) mk_skipped: HashMap<(X25519PublicKey, u64), MessageKey>,  
    /*
    // Support for header encryption with header keys for sending and receiving
    hks: Option<[u8; 32]>,
    nhks: Option<[u8; 32]>,
    hkr: Option<[u8; 32]>,
    nhkr: Option<[u8; 32]>
     */

}
#[hax_lib::opaque]
impl fmt::Display for StateDHRatchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StateDHRatchet {{\n")?;
        write!(f, "  dhs.public:  {:?}\n", self.dhs.public_key)?;
        write!(f, "  dhr:         {:?}\n", self.dhr)?;
        write!(f, "  rk:          {:?}\n", self.rk)?;
        write!(f, "  cks:         {}\n", if self.cks.is_some() { "Some(...)" } else { "None" })?;
        write!(f, "  ckr:         {}\n", if self.ckr.is_some() { "Some(...)" } else { "None" })?;
        write!(f, "  ns:          {}\n", self.ns)?;
        write!(f, "  nr:          {}\n", self.nr)?;
        write!(f, "  pn:          {}\n", self.pn)?;
        write!(f, "  mk_skipped:  {} entries\n", self.mk_skipped.len())?;
        write!(f, "}}")
    }
}


#[hax_lib::attributes]
impl StateDHRatchet {

    pub fn init_initiator<'a> (sk: RootChainKey, peer_spk_pub: X25519PublicKey) -> Result<Self, &'a str> {
        let dhs = pqxdh_impl::gen_curve_key_pair();

        let mut self_ratchet = Self {
            dhs,
            dhr: Some(peer_spk_pub),
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0, nr: 0, pn: 0,
            mk_skipped: HashMap::new(),
            /* 
            hks: Some(shared_hka),
            nhks: Some(nhks),
            hkr: None,
            nhkr: Some(shared_nhkb)
            */
        };
        
        let dh_out = self_ratchet.make_dh_out(peer_spk_pub)?;
        
        let (rk, cks) = KdfChain::kdf_rk(self_ratchet.rk, dh_out); 
        self_ratchet.rk = rk;
        self_ratchet.cks = Some(cks);
        
        Ok(self_ratchet)
    }

    pub fn init_responder(sk: RootChainKey, own_spk_keypair: X25519KeyPair) -> Self {
        let init_responder_dh_state = Self {
            dhs: own_spk_keypair,
            dhr: None,
            rk: sk,
            cks: None,
            ckr: None,
            ns: 0, nr: 0, pn: 0,
            mk_skipped: HashMap::new(),
        };
        init_responder_dh_state
    }

    pub(crate) fn get_rk(&self) -> &RootChainKey {
        &self.rk
    }

    pub(crate) fn set_cks (&mut self, new_cks: Option<ChainKey>) {
        self.cks = new_cks
    }

    #[hax_lib::requires(self.ns <= u64::MAX -1)]
    pub(crate) fn add_ns(&mut self) {
        self.ns += 1;
    }

    pub(crate) fn make_dh_out<'a> (&mut self, peer_spk_pub: X25519PublicKey) -> Result<[u8; 32], &'a str>{
        let dh_out = libcrux_wrap::libcrux_ecdh_x25519_derive(peer_spk_pub, self.dhs.private_key)?;  
        Ok(dh_out)
    }

    #[hax_lib::opaque]
    pub fn state_size (&self) -> usize {
        32 + 32                          // dhs keypair
        + 1 + self.dhr.map_or(0, |_| 32) // dhr option
        + 32                             // rk
        + 1 + self.cks.map_or(0, |_| 32) // cks option
        + 1 + self.ckr.map_or(0, |_| 32) // ckr option
        + 8 + 8 + 8                      // ns, nr, pn
        + 8                              // mk_skipped entry count
        + self.mk_skipped.len() * (32 + 8 + 32) // each entry
    }
}

#[cfg(test)]
mod tests {
    use crate::kdf_chain::kdf_chain_impl::KdfChain;
    use crate::util::keys::{RootChainKey, X25519PublicKey, X25519PrivateKey, X25519KeyPair};
    use crate::double_ratchet::ratchet_state::{StateDHRatchet};

    #[test]
    fn can_make_initiator_state(){
        let dummy_sk = RootChainKey([123u8; 32]);
        let dummy_peer_spk_pub =  X25519PublicKey([123u8; 32]);

        let state = StateDHRatchet::init_initiator(dummy_sk, dummy_peer_spk_pub)
            .expect("Tried to make initial state");

        assert_ne!(state.rk, dummy_sk);
        assert!(state.dhr.is_some());
        assert!(state.cks.is_some());
        assert!(state.ckr.is_none());
        assert_eq!(state.ns, 0);
        assert_eq!(state.nr, 0);
        assert_eq!(state.pn, 0);
        assert!(state.mk_skipped.is_empty());

        assert_ne!(state.rk.0, state.cks.expect("Should have a sending chain key").0);
    }

    #[test]
    fn can_make_responder_state(){
        let dummy_sk = RootChainKey([123u8; 32]);
        let dummy_peer_spk_pub =  X25519PublicKey([123u8; 32]);
        let dummy_peer_spk_pri =  X25519PrivateKey([123u8; 32]);
        let dummy_peer_spk_key_pair = X25519KeyPair{
            public_key: dummy_peer_spk_pub,
            private_key: dummy_peer_spk_pri
        };

        let state = StateDHRatchet::init_responder(dummy_sk, dummy_peer_spk_key_pair);

        assert_eq!(state.dhs, dummy_peer_spk_key_pair);
        assert_eq!(state.rk, dummy_sk);
        assert!(state.dhr.is_none());
        assert!(state.cks.is_none());
        assert!(state.ckr.is_none());
        assert_eq!(state.ns, 0);
        assert_eq!(state.nr, 0);
        assert_eq!(state.pn, 0);
        assert!(state.mk_skipped.is_empty());
    }

    #[test]
    fn does_kdf_ck_work_initiator(){
        let dummy_sk = RootChainKey([123u8; 32]);
        let dummy_peer_spk_pub =  X25519PublicKey([123u8; 32]);

        let state = StateDHRatchet::init_initiator(dummy_sk, dummy_peer_spk_pub)
            .expect("Tried to make initial state");

        let (mk, ck) = KdfChain::kdf_ck(state.cks)
            .expect("Could not do the sending key chain ratchet");

        assert_ne!(mk.0, ck.0);
        assert_ne!(mk.0, [0u8; 32]);
        assert_ne!(ck.0, [0u8; 32]);
    }
}