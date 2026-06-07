use std::{collections::HashMap};
use crate::util::{keys, messages::MessageType};
use crate::triple_ratchet::triple_ratchet_impl::TripleRatchetState;
use crate::util::expand_pqxdh_keys::expand_pqxdh_sk;

#[derive(Clone)]
pub struct Session {
    pub state: TripleRatchetState,
    pub(crate) ad: [u8; 64],
    pub(crate) messages: Vec<((String, [u8; 1]), String)>,
    received_initial_message: bool,
    pub(crate) initial_message: Option<MessageType>
}

pub struct SessionStore {
    sessions: HashMap<(String, [u8; 1]), Session>, // The name id, is the peer you're having a session with
}

#[hax_lib::attributes]
impl SessionStore{ 
    #[hax_lib::opaque]
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new()
        }
    }
    
    #[hax_lib::opaque]
    pub(crate) fn insert_session<'a> (&mut self, peer_id: (String, [u8; 1]), session: Session){
        self.sessions.insert(peer_id.clone(), session);
    }
    
    #[hax_lib::opaque]
    pub fn get_session<'a> (&self, peer_id: &(String, [u8; 1])) -> Result<Session, &'a str> {
        let session = self.sessions.get(peer_id);
        match session {
            Some(session) => return Ok(session.clone()),
            None =>  return Err("Couldn't get the session")
        }
    }


}

#[hax_lib::attributes]
impl Session {
    #[hax_lib::opaque]
    pub fn new_initiator(initiator_id: &(String, [u8; 1]), 
                sk: keys::RootChainKey, 
                peer_spk_pub: keys::X25519PublicKey, 
                session_store: &mut SessionStore,
                ad: [u8; 64]) {
        // Expand the sk from PQXDH
        let (ec_sk, scka_sk) = expand_pqxdh_sk(sk.0);
        let init_ses = Session { state: TripleRatchetState::rathet_init_initiator_tr(ec_sk, scka_sk, peer_spk_pub),
                    ad: ad,
                    messages: Vec::new(),
                    received_initial_message: false,
                    initial_message: None};

        session_store.insert_session(initiator_id.clone(), init_ses);
    }
    #[hax_lib::opaque]
    pub(crate) fn new_responder(responder_id: &(String, [u8; 1]), 
                sk: keys::RootChainKey, 
                own_spk_keypair: keys::X25519KeyPair, 
                session_store: &mut SessionStore,
                ad: [u8; 64]) {
        let (ec_sk, scka_sk) = expand_pqxdh_sk(sk.0);

        let init_res_ses = Session { 
                state: TripleRatchetState::rathet_init_responder_tr(ec_sk, scka_sk, own_spk_keypair),
                ad: ad, 
                messages: Vec::new(),
                received_initial_message: false,
                initial_message: None};
        
        session_store.insert_session(responder_id.clone(), init_res_ses);
    }
    
    #[hax_lib::opaque]
    pub(crate) fn get_received_initial_message(&mut self) -> bool{
        self.received_initial_message
    }

    #[hax_lib::opaque]
    pub(crate) fn set_received_initial_message(&mut self, have_received: bool){
        self.received_initial_message = have_received;
    }
    
    #[hax_lib::opaque]
    pub fn session_size(&self) -> usize {
        self.state.state_size()
        + 64                    
        + 1                     
        + 1 + match &self.initial_message {
            Some(msg) => std::mem::size_of_val(msg),
            None => 0,
        }
    }
    
}