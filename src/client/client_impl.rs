use crate::client::session::SessionStore;
use crate::server::server_impl::Server;
use crate::util::keys::{FetchedBundle};
use crate::{pqxdh::pqxdh_impl, util::keys, server::server_impl};
use crate::util::messages::{MessageType, IDUseNameKey, TRHeader};
use crate::util::helper_func::{make_randomness};

pub struct Client {
    pub name: (String, [u8; 1]),    // Name with a random bytes to avoid collision between two equal names
    pub(crate) pqxdh_state: pqxdh_impl::PQXDHState, // State to keep track of PQXDH
    pub sessions: SessionStore
}

/* 
Generates id to keys as one byte.
*/
#[hax_lib::opaque]
fn gen_name_id() -> [u8; 1] {
    let id = make_randomness::<1>();
    id
}

#[hax_lib::attributes]
impl Client {
    #[hax_lib::opaque]
    pub fn new(name: &str, name_id: Option<[u8; 1]>, server: &mut Server) -> Self{
        // Creating the name for Client
        let name_id = match name_id {
            Some(name_id) => name_id,
            None          => gen_name_id(),
        };
        let user_id = (name.to_string(), name_id);

        // Creates the state that keeps track of user key bundle and one time keys
        let pqxdh_state = pqxdh_impl::PQXDHState::new();

        // PreKeyBundle to be sent to Server
        let pre_key_bundle = pqxdh_impl::setup_pre_key_bundle(&pqxdh_state.keybundle);
        server.register_bundle(user_id.clone(), pre_key_bundle);
        
        // Holds sessions with different users
        let sessions_store = SessionStore::new();

        Self {
            name: user_id,
            pqxdh_state,
            sessions: sessions_store
        }
    }
    #[hax_lib::opaque]
    pub(crate)fn initial_message<'a>(&mut self, server: &mut Server, fetched_bundle: &FetchedBundle, target_user_id: &(String, [u8; 1])) -> Result<() , &'a str> {
        // Makes the initial message which is the first message between responder and initiator - after creation of Shared Secret
        let init_message = pqxdh_impl::make_initial_message_and_init_session(&self.pqxdh_state, fetched_bundle, &self.name, target_user_id, &mut self.sessions);
        let init_message = match init_message {
            Ok(MessageType::InitialMessage { ik_pub, ek, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id, ad }) => MessageType::InitialMessage { ik_pub, ek, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id, ad },
            Ok(_) => return Err("Should be an MessageType::IntitialMessage"),
            Err(e) => return Err(e)
        };
        let _ = server.register_message(target_user_id, init_message.clone());

        // Gets the session and inserts the initialmessage
        let mut session = match self.sessions.get_session(&target_user_id) {
            Ok(session) => session,
            Err(e) => return Err(e)
        };
        session.initial_message = Some(init_message);
        self.sessions.insert_session(target_user_id.clone(), session);

        Ok(())
    }
    #[hax_lib::opaque]
    fn receive_init_message(&mut self, 
                            ik_initiator_pub: keys::X25519PublicKey, 
                            ek_initiator: keys::X25519PublicKey, 
                            pq_ct: [u8; keys::ML_KEM_768_CT_SIZE], 
                            pre_key_ids: Vec<IDUseNameKey>, 
                            init_ct: [u8; 32], 
                            init_ct_tag: [u8; 16], 
                            init_ct_nonce: [u8; 12], 
                            salt: [u8; 32], 
                            initiator_id: (String, [u8; 1]), 
                            ad: [u8; 64]){
        pqxdh_impl::handle_receive_init_message_make_session_on_success(&mut self.sessions, &mut self.pqxdh_state, ik_initiator_pub, ek_initiator, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id, ad);
    }

    // Fetch the prekey bundle from the server
    #[hax_lib::opaque]
    pub(crate) fn fetch_bundle_from_server<'a> (&mut self, server: &mut server_impl::Server, target_user_id: (String, [u8; 1])) -> Result<keys::FetchedBundle, &'a str> {
        server.fetch_bundle(target_user_id)
    }
    
    #[hax_lib::opaque]
    pub fn receive (&mut self, server: &mut server_impl::Server, target_user_id: &(String, [u8; 1])) -> Result<Vec<(String, String)>, String> {
        self.fetch_message_from_server(server)?;

        let mut session = match self.sessions.get_session(&target_user_id) {
            Ok(session) => session,
            Err(e) => return Err(e.to_string())
        };

        let mut matched_messages: Vec<(String, String)> = Vec::new();
        let mut indices_to_remove: Vec<usize> = Vec::new();

        for (i, message) in session.messages.iter().enumerate(){
            if message.0 == *target_user_id {
                matched_messages.push((message.0.0.clone(), message.1.clone()));
                indices_to_remove.push(i);
            }
        }
        for (offset, i) in indices_to_remove.into_iter().enumerate() {
                session.messages.remove(i - offset);
        }

        if matched_messages.is_empty() {
           return Err(format!("No messages found for user {}", target_user_id.0));
        }

        for _message in &matched_messages {
            //println!("Message from {} to {}: {}", message.0, self.name.0, message.1);
        }

        self.sessions.insert_session(target_user_id.clone(), session);

        Ok(matched_messages)
    }

    // Fetch the message queue from the server
    #[hax_lib::opaque]
    pub(crate) fn fetch_message_from_server<'a> (&mut self, server: &mut server_impl::Server) -> Result<(), &'a str>{
        // Fetches the messages from the server's message queue
        let message_queue = server.user_fetch_messages(self.name.clone());
        for message in message_queue{
            match message {
                MessageType::MakeOneTimePreKey => self.add_20_opk_and_send(server),
                MessageType::MakePQOneTimePreKey => self.add_20_pqs_opk_and_send(server),
                MessageType::NewMessage {from, payload, retry_init} => {
                                            
                                            // Check if a session already exists
                                            let session_exists = self.sessions.get_session(&from).is_ok();
                                            
                                            if !session_exists {    // No session tries to look for the appended intial message
                                                match retry_init {
                                                    Some(inner_msg) => {
                                                        if let MessageType::InitialMessage { 
                                                            ik_pub, ek, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id, ad 
                                                        } = *inner_msg {
                                                            self.receive_init_message(ik_pub, ek, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id, ad);
                                                            let mut session = match self.sessions.get_session(&from) {
                                                                Ok(session) => session,
                                                                Err(e) => return Err(e)
                                                            };
                                                            session.set_received_initial_message(true);
                                                            self.sessions.insert_session(from.clone(), session);
                                                            self.handle_new_message(from, payload)?;
                                                        } else {
                                                            return Err("retry_init is not an InitialMessage");
                                                        }
                                                    },
                                                    None => {
                                                        return Err("NewMessage arrived with no session and no retry_init");
                                                    }
                                                }
                                            } else {
                                                let mut session = match self.sessions.get_session(&from) {
                                                    Ok(session) => session,
                                                    Err(e) => return Err(e)
                                                };
                                            if session.get_received_initial_message() {
                                                self.handle_new_message(from.clone(), payload)?;
                                            } else {
                                                self.handle_new_message(from.clone(), payload)?;
                                                // Re-fetch AFTER handle_new_message has updated the ratchet state
                                                let mut session = match self.sessions.get_session(&from) {
                                                    Ok(session) => session,
                                                    Err(e) => return Err(e)
                                                };
                                                session.set_received_initial_message(true);
                                                self.sessions.insert_session(from, session);
                                            }
                                        }                                        
                                    }                  
                MessageType::UploadOpks {..}=> return Err("User can't receive a UploadOpks message"),
                MessageType::UploadPQOpks{..} => return Err("User can't receive a UploadPqOpks message"),
                MessageType::InitialMessage{ik_pub, 
                                            ek, 
                                            pq_ct, 
                                            pre_key_ids, 
                                            init_ct, 
                                            init_ct_tag,
                                            init_ct_nonce,  
                                            salt, 
                                            initiator_id,
                                            ad} => {
                                        self.receive_init_message(ik_pub, ek, pq_ct, pre_key_ids, init_ct, init_ct_tag, init_ct_nonce, salt, initiator_id.clone(), ad);
                                        let mut session = match self.sessions.get_session(&initiator_id) {
                                            Ok(session) => session,
                                            Err(e) => return Err(e)
                                        };
                                        session.set_received_initial_message(true);
                                        self.sessions.insert_session(initiator_id, session);
                }

            } 
            
        }
        return Ok(());
    }

    /*
    Adds 20 new pq signed one-time prekeys to the pqxdh_state
    */
    #[hax_lib::opaque]
    fn add_20_pqs_opk_and_send(&mut self, server: &mut server_impl::Server){
        let new_pq_opks = self.pqxdh_state.add_20_pqs_opk();
        let message_to_register: MessageType = MessageType::UploadPQOpks { 
            upload_pqopks_user_id: self.name.clone(), pq_opks: new_pq_opks};
        let _ = server.register_message(&self.name, message_to_register); 
    }

    /* 
    Adds 20 new one-time prekeys to the pqxdh_state
    */
    #[hax_lib::opaque]
    fn add_20_opk_and_send(&mut self, server: &mut server_impl::Server){
        let new_opks = self.pqxdh_state.add_20_opk();
        let message_to_register = MessageType::UploadOpks { 
            upload_opks_user_id: self.name.clone(), 
            opks: new_opks, 
        };

        let _ = server.register_message(&self.name, message_to_register); 
    }

    #[hax_lib::opaque]
    fn handle_new_message<'a> (&mut self, from: (String, [u8; 1]), payload: (TRHeader, Vec<u8>)) -> Result<(), &'a str>{
        let mut session = match self.sessions.get_session(&from) {
            Ok(session) => session,
            Err(e) => return Err(e)
        };
        //      
        let plaintext = match session.state.tr_decrypt(payload.0, payload.1, session.ad){
            Ok(plaintext) => plaintext,
            Err(e) => return Err(e)
        };

        session.messages.push((from.clone(), plaintext));
        
        self.sessions.insert_session(from, session);
        Ok(())
    }

    #[hax_lib::opaque]
    pub fn send_new_message<'a> (&mut self, to: &(String, [u8; 1]), plaintext: String, server: &mut Server) -> Result<(), &'a str> {
        let res_session = self.sessions.get_session(to);
        
        let mut session = match res_session {
            Ok(session) => session,
            Err(_) => {
                let fetched_bundle_option = self.fetch_bundle_from_server(server, to.clone());
                let fetched_bundle = match fetched_bundle_option {
                    Ok(fb) => fb,
                    Err(e) => return Err(e)
                };
                self.initial_message(server, &fetched_bundle, to)?;
                let session = self.sessions.get_session(to)?;
                session
            }
        };

        let payload = session.state.tr_encrypt(&plaintext, &session.ad)?;

        let new_message = 
            if session.get_received_initial_message() {
                MessageType::NewMessage {  
                    from: self.name.clone(), 
                    payload,
                    retry_init: None
                        }
                    }
            else {
                MessageType::NewMessage { 
                    from: self.name.clone(), 
                    payload,
                    retry_init: session.initial_message.clone().map(Box::new)
                }
            };

        session.messages.push((self.name.clone(), plaintext));
        
        let _ = self.sessions.insert_session(to.clone(), session);
        server.register_message(to, new_message)?;
        Ok(())
    }

}


#[cfg(test)]
mod tests{
    use core::panic;
    use crate::server::server_impl::Server;
    use crate::client::client_impl::Client;
    use crate::pqxdh::pqxdh_impl;
    use crate::util::keys::{self, FetchedBundle};
    use crate::util::libcrux_wrap::{libcrux_aead_encrypts_ad_initial_message};
    use zeroize::Zeroize;
    use crate::util::messages::MessageType;
    use crate::client::session::Session;
    use crate::util::expand_pqxdh_keys::expand_pqxdh_sk;
    #[test]
    fn setup () {
        let mut server = Server::new();
        let _ = Client::new("Alice", None, &mut server);
        let _ = Client::new("Bob", None, &mut server);
    }
    
    
    #[test]
    fn fetch_key_bundle(){
        let mut server = Server::new();
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None, &mut server);
        let bob = Client::new("Bob", None, &mut server);
        // Alice fetches Bob's key bundle
        let bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name);
        assert_eq!(bob_pk_bundle.expect("Should fetch the bundle").ik_dh_pub, bob.pqxdh_state.keybundle.identity.dh.public_key, "Identity Key doesn't match");
    }
    #[test]
    fn verify_keys_from_bundle(){
        let mut server = Server::new();
        
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None, &mut server);
        let bob = Client::new("Bob", None, &mut server);
        // Alice fetches Bob's key bundle
        let bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name);
        
        // Alice verifies Bob signature
        assert_eq!(pqxdh_impl::verify_pre_keys(&bob_pk_bundle.expect("Should fetch the bundle")), Ok(()));
    }

    #[test]
    fn cannot_verify_keys_from_bundle(){
        let mut server = Server::new();
        
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None,  &mut server);
        let bob = Client::new("Bob", None, &mut server);
        // Alice fetches Bob's key bundle
        let mut bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name).expect("Should fetch the bundle");

        // Changes one of the signatures to mess up
        let pqopk = alice.pqxdh_state.keybundle.pq_opks.last().expect("Can't find the key in Alice's bundle");
        bob_pk_bundle.pq_opk = Some((pqopk.key.public_key.clone(), pqopk.id, pqopk.sig));


        
        // Alice verifies Bob signature
        assert_ne!(pqxdh_impl::verify_pre_keys(&bob_pk_bundle), Ok(()));
    }

    /*Make test for last resort (empty pqopk) */
    #[test]
    fn verifying_last_resort_key(){
        let mut server = Server::new();
        
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None, &mut server);
        let bob = Client::new("Bob", None, &mut server);


        // Alice fetches Bob's key bundle
        let mut bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name).expect("Should fetch the bundle");
        
        // Empties the pq opk, such that the verifying will be on the last resort key
        bob_pk_bundle.pq_opk = None;

        bob_pk_bundle.pqspk_id = Some(bob.pqxdh_state.keybundle.pqspk.id);
        bob_pk_bundle.pqspk_pub = Some(bob.pqxdh_state.keybundle.pqspk.key.public_key);      
        

        assert_eq!(pqxdh_impl::verify_pre_keys(&bob_pk_bundle), Ok(()))

    }

    /*Make test for last resort (empty pqopk) */
    #[test]
    fn emptying_opk_verifying_for_last_resort(){
        let mut server = Server::new();
        
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None, &mut server);
        let bob = Client::new("Bob", None, &mut server);

        let mut bob_pk_bundle: FetchedBundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone())
            .expect("Should fetch the bundle");
        // Alice fetches Bob's key bundle 20 times
        // Empties the pq opk, such that the verifying will be on the last resort key
        
        for _ in 0..20{
            bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone())
                .expect("Should fetch the bundle");
        }

        let pqspk_pub = bob_pk_bundle.pqspk_pub.clone()
            .expect("This should work when emptying");

        assert_eq!(pqxdh_impl::verify_pre_keys(&bob_pk_bundle), Ok(()));
        assert_eq!(pqspk_pub.0, bob.pqxdh_state.keybundle.pqspk.key.public_key.0);
    }

    /*Make test for last resort (empty pqopk) */
    #[test]
    fn emptying_opk_verifying_for_last_resort_after_multiple_fetches(){
        let mut server = Server::new();
        
        // The prekey is uploaded when a new pqxdh_state is made
        let mut alice = Client::new("Alice", None, &mut server);
        let bob = Client::new("Bob", None, &mut server);

        let mut bob_pk_bundle:Result<FetchedBundle, &str>   = alice.fetch_bundle_from_server(&mut server, bob.name.clone());
        // Alice fetches Bob's key bundle 20 times
        // Empties the pq opk, such that the verifying will be on the last resort key
        for _ in 0..40{
            bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone());
        }
        let bob_pk_bundle = bob_pk_bundle.expect("Should fetch the bundle");
        let pqspk_pub = bob_pk_bundle.pqspk_pub.clone().expect("This should work when emptying and multiple fetches");

        assert_eq!(pqxdh_impl::verify_pre_keys(&bob_pk_bundle), Ok(()));
        assert_eq!(pqspk_pub.0, bob.pqxdh_state.keybundle.pqspk.key.public_key.0);
    }

    #[test]
    fn checks_two_sk(){
        let mut server = Server::new();
                
        let mut alice = Client::new("Alice", None, &mut server);
        let mut bob = Client::new("Bob", None, &mut server);

        let fetched_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone());
        let fetched_bundle = fetched_bundle.expect("Should fetch the bundle");


        let (salt, mut concat_dh_final_alice, ek_alice, mut ct_alice, id_pk_alice) = pqxdh_impl::
                initiator_create_salt_concat_dh(&alice.pqxdh_state, &fetched_bundle)
                    .expect("Couldn't make salt or concatted dh");
        let alice_sk = pqxdh_impl::create_sk(salt, concat_dh_final_alice, b"HACSS_CURVE25519_SHA256_ML-KEM-768");

        let mut ek_private_bytes: [u8; 32] = ek_alice.private_key.0;
        ek_private_bytes.zeroize();
        concat_dh_final_alice.zeroize();
        
        let mut ad = [0u8; 64];
        ad[0..32].copy_from_slice(alice.pqxdh_state.keybundle.identity.dh.public_key.0.as_ref());
        ad[32..64].copy_from_slice(fetched_bundle.ik_dh_pub.0.as_ref());

        let (mut init_ct, mut init_ct_tag, init_ct_nonce) = libcrux_aead_encrypts_ad_initial_message(&alice_sk, &ad, b"Initial for our post-PQXDH KL,AM")
            .expect("Could not make the initial ciphertext for the initial message");

        let init_message = MessageType::InitialMessage {
            ik_pub: alice.pqxdh_state.keybundle.identity.dh.public_key, 
            ek: ek_alice.public_key, 
            pq_ct: ct_alice, 
            pre_key_ids: id_pk_alice, 
            init_ct,
            init_ct_tag,
            init_ct_nonce,
            salt,
            initiator_id: alice.name.clone(),
            ad
        };

        let _ = server.register_message(&bob.name, init_message);

        ct_alice.zeroize();
        init_ct.zeroize();
        init_ct_tag.zeroize();

        // Use the SPK (not IK) to match what Session::new_initiator does internally
        let spk_pub_target = fetched_bundle.spk_pub;
        Session::new_initiator(
            &bob.name, 
            keys::RootChainKey(alice_sk), 
            spk_pub_target,   // ← was ik_pub_target, now correctly spk_pub
            &mut alice.sessions, 
            ad
        );
        
        // Bob fetches and processes the initial message
        bob.fetch_message_from_server(&mut server)
            .expect("Bob couldn't collect the initial message from Alice");

        let bob_side_session = bob.sessions
            .get_session(&alice.name)
            .expect("Could not find the session between Alice and Bob");

        // Both sides expand the same SK — compare the raw SK before expansion, 
        // not the EC ratchet's rk (which is already the expanded ec_sk portion)
        let (alice_ec_sk, _) = expand_pqxdh_sk(alice_sk);
        let bob_ec_sk = bob_side_session.state.ec_state.get_rk();

        assert_eq!(bob_ec_sk.0, alice_ec_sk);
    }


    #[test]
    fn can_send_a_message_between_two_pqxdh_states(){
        let mut server = Server::new();
                
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]), &mut server);

        
        let bob_fetched_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        
        let _ = alice.initial_message(&mut server, &bob_fetched_bundle, &bob.name);
        
        let _ = alice.send_new_message(&bob.name, "Hey, Bob (from Alice)".to_string(), &mut server);
        
        let _ = bob.fetch_message_from_server(&mut server);

        let _ = bob.send_new_message(&alice.name, "Hey, Alice".to_string(), &mut server);

        let _ = alice.fetch_message_from_server(&mut server);

        let mut alice_session = match alice.sessions.get_session(&bob.name) {
            Ok(a_session) => a_session,
            Err(_) => panic!()
        };
        let _bob_session = bob.sessions.get_session(&alice.name).expect("Should get the session between Bob and Alice");
        
        assert_eq!(alice_session.messages.len(), 2);

        let message_one = alice_session.messages.pop().expect("Should have the message: Hey, Alice").1;        

        assert_eq!(message_one, "Hey, Alice".to_string());

        let message_two = alice_session.messages.pop().expect("Should have the message: Hey, Bob (from Alice)").1;        

        assert_eq!(message_two, "Hey, Bob (from Alice)".to_string());

        assert_eq!(alice_session.messages.len(), 0);
    }    

    #[test]
    fn bob_can_receive_message_from_alice() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]), &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "Hey Bob".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();

        let session = bob.sessions.get_session(&alice.name).unwrap();
        let msg = session.messages.last().unwrap().1.clone();
        assert_eq!(msg, "Hey Bob".to_string());
    }

    #[test]
    fn alice_can_receive_message_from_bob() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]), &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "Hey Bob".to_string(), &mut server).unwrap();
        bob.fetch_message_from_server(&mut server).unwrap();

        bob.send_new_message(&alice.name, "Hey Alice".to_string(), &mut server).unwrap();
        alice.fetch_message_from_server(&mut server).unwrap();

        let session = alice.sessions.get_session(&bob.name).unwrap();
        let msg = session.messages.last().unwrap().1.clone();
        assert_eq!(msg, "Hey Alice".to_string());
    }

    #[test]
    fn multiple_messages_are_stored_in_order() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]), &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "Message 1".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "Message 2".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "Message 3".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();

        let session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(session.messages.len(), 3);
        assert_eq!(session.messages[0].1, "Message 1");
        assert_eq!(session.messages[1].1, "Message 2");
        assert_eq!(session.messages[2].1, "Message 3");
    }

    #[test]
    fn session_exists_after_initial_message() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]), &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        // Alice has a session with Bob immediately after initial_message
        assert!(alice.sessions.get_session(&bob.name).is_ok());

        // Bob gets a session only after fetching
        //assert!(bob.sessions.get_session(&alice.name).is_err());
        bob.fetch_message_from_server(&mut server).unwrap();
        assert!(bob.sessions.get_session(&alice.name).is_ok());
    }

    #[test]
    fn session_does_not_exists_after_before_initial_message() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "First message to send today, good morning".to_string(), &mut server)
            .expect("Should send new message");

        // Alice has a session with Bob immediately after initial_message
        assert!(alice.sessions.get_session(&bob.name).is_ok());

        // Bob gets a session only after fetching
        assert!(bob.sessions.get_session(&alice.name).is_err());
    }

    #[test]
    fn ratchet_advances_after_send() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        let ns_before = alice.sessions.get_session(&bob.name).unwrap().state.ec_state.ns;
        alice.send_new_message(&bob.name, "Hello".to_string(), &mut server).unwrap();
        let ns_after = alice.sessions.get_session(&bob.name).unwrap().state.ec_state.ns;

        assert_eq!(ns_after, ns_before + 1);
    }

    #[test]
    fn sending_empty_string_works() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();

        let session = bob.sessions.get_session(&alice.name).unwrap();
        let msg = session.messages.last().unwrap().1.clone();
        assert_eq!(msg, "".to_string());
    }



    #[test]
    fn extended_conversation_alice_and_bob() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        // Round 1: Alice sends 3, Bob receives
        alice.send_new_message(&bob.name, "A1".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "A2".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "A3".to_string(), &mut server).unwrap();
        bob.fetch_message_from_server(&mut server).unwrap();

        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.len(), 3);
        assert_eq!(bob_session.messages[0].1, "A1");
        assert_eq!(bob_session.messages[1].1, "A2");
        assert_eq!(bob_session.messages[2].1, "A3");

        // Round 2: Bob replies 3, Alice receives
        bob.send_new_message(&alice.name, "B1".to_string(), &mut server).unwrap();
        bob.send_new_message(&alice.name, "B2".to_string(), &mut server).unwrap();
        bob.send_new_message(&alice.name, "B3".to_string(), &mut server).unwrap();
        alice.fetch_message_from_server(&mut server).unwrap();

        let alice_session = alice.sessions.get_session(&bob.name).unwrap();
        assert_eq!(alice_session.messages[3].1, "B1");
        assert_eq!(alice_session.messages[4].1, "B2");
        assert_eq!(alice_session.messages[5].1, "B3");

        // Round 3: Alice replies, Bob receives — ratchet has stepped again
        alice.send_new_message(&bob.name, "A4".to_string(), &mut server).unwrap();
        bob.fetch_message_from_server(&mut server).unwrap();
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.last().unwrap().1, "A4");

        // Round 4: Bob replies, Alice receives — full 4-way ratchet cycle complete
        bob.send_new_message(&alice.name, "B4".to_string(), &mut server).unwrap();
        alice.fetch_message_from_server(&mut server).unwrap();
        let alice_session = alice.sessions.get_session(&bob.name).unwrap();
        assert_eq!(alice_session.messages.last().unwrap().1, "B4");
    }

    #[test]
    fn ratchet_state_advances_correctly_over_multiple_sends() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        // Send 10 messages and verify ns advances correctly each time
        for i in 1..=10 {
            let ns_before = alice.sessions.get_session(&bob.name).unwrap().state.ec_state.ns;
            alice.send_new_message(&bob.name, format!("msg {}", i), &mut server).unwrap();
            let ns_after = alice.sessions.get_session(&bob.name).unwrap().state.ec_state.ns;
            assert_eq!(ns_after, ns_before + 1, "ns should advance by 1 after each send");
        }

        // Bob receives all 10
        bob.fetch_message_from_server(&mut server).unwrap();
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.len(), 10);
        for i in 1..=10 {
            assert_eq!(bob_session.messages[i - 1].1, format!("msg {}", i));
        }
    }

    #[test]
    fn messages_with_special_characters_and_long_content() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        let messages = vec![
            "".to_string(),                                          // empty
            "Hello, World!".to_string(),                            // basic ASCII
            "こんにちは世界".to_string(),                             // Japanese
            "!@#$%^&*()_+-=[]{}|;':\",./<>?".to_string(),          // special chars
            "a".repeat(10_000),                                     // long message
        ];

        for msg in &messages {
            alice.send_new_message(&bob.name, msg.clone(), &mut server).unwrap();
        }

        bob.fetch_message_from_server(&mut server).unwrap();
        let session = bob.sessions.get_session(&alice.name).unwrap();

        assert_eq!(session.messages.len(), messages.len());
        for (i, expected) in messages.iter().enumerate() {
            assert_eq!(&session.messages[i].1, expected, "Message {} did not match", i);
        }
    }

    #[test]
    fn alternating_send_receive_ratchets_correctly() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        // Strictly alternating: Alice → Bob → Alice → Bob, 5 rounds
        for i in 1..=5 {
            let alice_msg = format!("Alice round {}", i);
            let bob_msg = format!("Bob round {}", i);

            alice.send_new_message(&bob.name, alice_msg.clone(), &mut server).unwrap();
            bob.fetch_message_from_server(&mut server).unwrap();
            assert_eq!(
                bob.sessions.get_session(&alice.name).unwrap().messages.last().unwrap().1,
                alice_msg
            );

            bob.send_new_message(&alice.name, bob_msg.clone(), &mut server).unwrap();
            alice.fetch_message_from_server(&mut server).unwrap();
            assert_eq!(
                alice.sessions.get_session(&bob.name).unwrap().messages.last().unwrap().1,
                bob_msg
            );
        }

        // After 5 full rounds, verify ratchet has stepped: nr and ns should reflect history
        let alice_session = alice.sessions.get_session(&bob.name).unwrap();
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();

        // Each side sent 5 messages total
        assert_eq!(alice_session.messages.len(), 10); // 5 sent + 5 received
        assert_eq!(bob_session.messages.len(), 10);
    }

    #[test]
    fn three_pqxdh_states_no_cross_interference() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);
        let mut charlie = Client::new("Charlie", Some([3u8; 1]),  &mut server);

        // Alice → Bob session
        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        // Alice → Charlie session
        let charlie_bundle = alice.fetch_bundle_from_server(&mut server, charlie.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &charlie_bundle, &charlie.name).unwrap();

        alice.send_new_message(&bob.name, "Hey Bob, secret".to_string(), &mut server).unwrap();
        alice.send_new_message(&charlie.name, "Hey Charlie, secret".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();
        charlie.fetch_message_from_server(&mut server).unwrap();

        // Bob got Alice's message to Bob, not Charlie's
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.len(), 1);
        assert_eq!(bob_session.messages[0].1, "Hey Bob, secret");

        // Charlie got Alice's message to Charlie, not Bob's
        let charlie_session = charlie.sessions.get_session(&alice.name).unwrap();
        assert_eq!(charlie_session.messages.len(), 1);
        assert_eq!(charlie_session.messages[0].1, "Hey Charlie, secret");
    }

    #[test]
    fn three_pqxdh_states_no_cross_interference_should_panic() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);
        let mut charlie = Client::new("Charlie", Some([3u8; 1]),  &mut server);

        // Alice → Bob session
        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        // Alice → Charlie session
        let charlie_bundle = alice.fetch_bundle_from_server(&mut server, charlie.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &charlie_bundle, &charlie.name).unwrap();

        alice.send_new_message(&bob.name, "Hey Bob, secret".to_string(), &mut server).unwrap();
        alice.send_new_message(&charlie.name, "Hey Charlie, secret".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();
        charlie.fetch_message_from_server(&mut server).unwrap();

        // Bob got Alice's message to Bob, not Charlie's
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.len(), 1);
        assert_eq!(bob_session.messages[0].1, "Hey Bob, secret");

        // Bob and Charlie cannot read each other's messages - they have no session
        assert!(bob.sessions.get_session(&charlie.name).is_err(), "There is no session between Bob and Charlie");
    }

    #[test]
    fn three_pqxdh_states_bob_and_charlie_both_reply_to_alice() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);
        let mut charlie = Client::new("Charlie", Some([3u8; 1]),  &mut server);

        // Establish Alice→Bob and Alice→Charlie sessions
        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();
        let charlie_bundle = alice.fetch_bundle_from_server(&mut server, charlie.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &charlie_bundle, &charlie.name).unwrap();

        alice.send_new_message(&bob.name, "Hi Bob".to_string(), &mut server).unwrap();
        alice.send_new_message(&charlie.name, "Hi Charlie".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();
        charlie.fetch_message_from_server(&mut server).unwrap();

        // Both reply to Alice
        bob.send_new_message(&alice.name, "Hi Alice from Bob".to_string(), &mut server).unwrap();
        charlie.send_new_message(&alice.name, "Hi Alice from Charlie".to_string(), &mut server).unwrap();

        alice.fetch_message_from_server(&mut server).unwrap();

        // Alice receives both replies in separate sessions
        let alice_bob_session = alice.sessions.get_session(&bob.name).unwrap();
        assert_eq!(alice_bob_session.messages.last().unwrap().1, "Hi Alice from Bob");

        let alice_charlie_session = alice.sessions.get_session(&charlie.name).unwrap();
        assert_eq!(alice_charlie_session.messages.last().unwrap().1, "Hi Alice from Charlie");
    }

    #[test]
    fn independent_sessions_have_different_ratchet_states() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let bob = Client::new("Bob", Some([2u8; 1]),  &mut server);
        let charlie = Client::new("Charlie", Some([3u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        let charlie_bundle = alice.fetch_bundle_from_server(&mut server, charlie.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &charlie_bundle, &charlie.name).unwrap();

        let alice_bob_rk = alice.sessions.get_session(&bob.name).unwrap().state.ec_state.rk;
        let alice_charlie_rk = alice.sessions.get_session(&charlie.name).unwrap().state.ec_state.rk;

        // Different sessions must have different root keys
        assert_ne!(alice_bob_rk.0, alice_charlie_rk.0,
            "Sessions with different peers must have different ratchet states");
    }

    #[test]
    fn message_queue_remains_intact_after_fetch() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "Test".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();

        // After fetching, Bob's queue should be empty but still exist in the server
        let remaining = server.user_fetch_messages(bob.name.clone());
        assert!(remaining.is_empty(), "Queue should be empty after fetch, but the entry should still exist");

        // Alice can still send a new message to Bob — queue entry was not deleted
        alice.send_new_message(&bob.name, "Second message".to_string(), &mut server).unwrap();
        bob.fetch_message_from_server(&mut server).unwrap();

        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.messages.last().unwrap().1, "Second message");
    }

    #[test]
    fn nr_advances_on_receive() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        alice.send_new_message(&bob.name, "M1".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "M2".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "M3".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();

        // Bob received 3 messages so nr should be 3
        let bob_session = bob.sessions.get_session(&alice.name).unwrap();
        assert_eq!(bob_session.state.ec_state.nr, 3,
            "nr should equal the number of messages received in the current chain");
    }

    #[test]
    fn pn_is_set_correctly_after_dh_ratchet_step() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bundle, &bob.name).unwrap();

        // Alice sends 3 messages (ns advances to 3)
        alice.send_new_message(&bob.name, "A1".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "A2".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "A3".to_string(), &mut server).unwrap();
        bob.fetch_message_from_server(&mut server).unwrap();

        // Bob replies — triggers a DH ratchet step on Alice's side when she receives
        bob.send_new_message(&alice.name, "B1".to_string(), &mut server).unwrap();
        alice.fetch_message_from_server(&mut server).unwrap();

        // Alice now sends again — her pn should reflect ns from the previous sending chain (3)
        alice.send_new_message(&bob.name, "A4".to_string(), &mut server).unwrap();
        let alice_session = alice.sessions.get_session(&bob.name).unwrap();
        assert_eq!(alice_session.state.ec_state.pn, 3,
            "pn should be set to ns from the previous sending chain after a DH ratchet step");
    }

    #[test]
    fn bob_receives_new_message_before_initial_message_with_retry() {
        // Tests the case where a NewMessage arrives with a bundled InitialMessage (retry_init),
        // because Bob hasn't received the InitialMessage yet
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        // Alice sends a message immediately — Bob has not fetched the InitialMessage yet
        alice.send_new_message(&bob.name, "First message with retry".to_string(), &mut server).unwrap();

        // Bob fetches — queue has both InitialMessage and NewMessage (with retry_init bundled)
        bob.fetch_message_from_server(&mut server).unwrap();

        let mut session = match bob.sessions.get_session(&alice.name) {
            Ok(session) => session,
            Err(_) => panic!()
        };
        assert!(session.get_received_initial_message(), 
            "Bob should have received the initial message flag set");
        assert_eq!(session.messages.last().unwrap().1, "First message with retry");
    }

    #[test]
    fn received_initial_message_flag_is_false_before_fetch() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        // Alice has a session — but has not received Bob's initial message yet
        let mut alice_session = match alice.sessions.get_session(&bob.name){
            Ok(session) => session,
            Err(_) => panic!()
        };
        assert!(!alice_session.get_received_initial_message(),
            "Alice should not have received_initial_message set before Bob replies");
    }

    #[test]
    fn received_initial_message_flag_set_after_bob_replies() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();
        alice.send_new_message(&bob.name, "Hey Bob".to_string(), &mut server).unwrap();

        bob.fetch_message_from_server(&mut server).unwrap();
        bob.send_new_message(&alice.name, "Hey Alice".to_string(), &mut server).unwrap();

        alice.fetch_message_from_server(&mut server).unwrap();

        // Now Alice has received Bob's first message — flag should be set
        let mut alice_session = match alice.sessions.get_session(&bob.name) {
            Ok(ses) => ses,
            Err(_) => panic!()
        };
        assert!(alice_session.get_received_initial_message(),
            "Alice should have received_initial_message set after Bob's first reply");
    }

    #[test]
    fn bob_flag_set_after_receiving_initial_message_directly() {
        // Tests the normal flow: Bob receives InitialMessage first, then NewMessage
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        // Bob fetches only the InitialMessage first
        bob.fetch_message_from_server(&mut server).unwrap();

        let mut bob_session = match bob.sessions.get_session(&alice.name) {
            Ok(ses) => ses,
            Err(_) => panic!()
        };
        assert!(bob_session.get_received_initial_message(),
            "Bob should have received_initial_message set after receiving InitialMessage");
    }

    #[test]
    fn full_flow_with_retry_init_three_rounds() {
        // Alice sends multiple messages before Bob has fetched InitialMessage
        // All should be decryptable via retry_init mechanism
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        alice.send_new_message(&bob.name, "Msg 1".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "Msg 2".to_string(), &mut server).unwrap();
        alice.send_new_message(&bob.name, "Msg 3".to_string(), &mut server).unwrap();

        // Bob fetches everything at once
        bob.fetch_message_from_server(&mut server).unwrap();

        let mut bob_session = match bob.sessions.get_session(&alice.name) {
            Ok(ses) => ses,
            Err(_) => panic!()
        };
        assert!(bob_session.get_received_initial_message());
        assert_eq!(bob_session.messages.len(), 3);
        assert_eq!(bob_session.messages[0].1, "Msg 1");
        assert_eq!(bob_session.messages[1].1, "Msg 2");
        assert_eq!(bob_session.messages[2].1, "Msg 3");

        // Conversation continues normally after
        bob.send_new_message(&alice.name, "Got them all".to_string(), &mut server).unwrap();
        alice.fetch_message_from_server(&mut server).unwrap();

        let alice_session = alice.sessions.get_session(&bob.name).unwrap();
        assert_eq!(alice_session.messages.last().unwrap().1, "Got them all");
    }

    // Make a test with +max size messages (+10), which tests that the initial message isn't in the queue and the optional initial message in the newest send messag is working as we thought
    #[test]
    fn actually_use_optional_init_message () {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let bob_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");
        alice.initial_message(&mut server, &bob_bundle, &bob.name).unwrap();

        for i in 0..12 {
            alice.send_new_message(&bob.name, format!("Msg {}", i).to_string(), &mut server).unwrap();
        }

        bob.fetch_message_from_server(&mut server).unwrap();

        let mut bob_session = match bob.sessions.get_session(&alice.name) {
            Ok(ses) => ses,
            Err(_) => panic!()
        };

        assert!(bob_session.get_received_initial_message(),
            "Bob should have received_initial_message set after receiving InitialMessage");
    }

    #[test]
    fn can_send_message_without_established_session(){
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "This is the message to send".to_string(), &mut server).expect("Should send the message");

        bob.fetch_message_from_server(&mut server).expect("Should fetch messages from server");
        
        let bob_session = bob.sessions.get_session(&alice.name).expect("Should get the session");
        
        let message_from_alice = bob_session.messages[0].clone();

        assert_eq!(message_from_alice.1, "This is the message to send".to_string(), "The messages doesn't match...");

    }

    #[test]
    fn receive_returns_all_messages_from_sender() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "First message from Alice".to_string(), &mut server).expect("Should send");
        alice.send_new_message(&bob.name, "Second message from Alice".to_string(), &mut server).expect("Should send");

        let messages = bob.receive(&mut server, &alice.name).expect("Should receive messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].1, "First message from Alice");
        assert_eq!(messages[1].1, "Second message from Alice");
    }

    #[test]
    fn receive_drains_messages_on_second_call() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "Hello".to_string(), &mut server).expect("Should send");

        bob.receive(&mut server, &alice.name).expect("Should receive");
        let second = bob.receive(&mut server, &alice.name);
        assert!(second.is_err(), "Second receive should return Err since messages were drained");
    }

    #[test]
    fn receive_returns_err_when_no_messages() {
        let mut server = Server::new();
        let alice = Client::new("Alice", Some([1u8; 1]), &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        let result = bob.receive(&mut server, &alice.name);
        assert!(result.is_err());
    }

    #[test]
    fn receive_only_drains_target_sender_messages() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);
        let mut charlie = Client::new("Charlie", Some([3u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "From Alice".to_string(), &mut server).expect("Should send");
        charlie.send_new_message(&bob.name, "From Charlie".to_string(), &mut server).expect("Should send");

        let alice_messages = bob.receive(&mut server, &alice.name).expect("Should receive Alice's messages");
        assert_eq!(alice_messages.len(), 1);

        // Charlie's message is still receivable
        let charlie_messages = bob.receive(&mut server, &charlie.name).expect("Should receive Charlie's messages");
        assert_eq!(charlie_messages.len(), 1);
    }

    #[test]
    fn messagez_are_removed_from_session_after_receiving() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", Some([1u8; 1]),  &mut server);
        let mut bob = Client::new("Bob", Some([2u8; 1]),  &mut server);

        alice.send_new_message(&bob.name, "From Alice".to_string(), &mut server).expect("Should send");
        let _alice_messages = bob.receive(&mut server, &alice.name).expect("Should receive Alice's messages");
        alice.send_new_message(&bob.name, "From Alice again".to_string(), &mut server).expect("Should send");
        
        _ = bob.fetch_message_from_server(&mut server);

        let session = bob.sessions.get_session(&alice.name.clone()).expect("Should get the session");
        assert_eq!(session.messages.len(), 1);
    }
    
}