use crate::util::keys::{FetchedBundle, PrekeyBundle};
use crate::util::messages::MessageType;
use std::collections::HashMap;

pub struct Server {
    names_keybundles: HashMap<(String, [u8; 1]), PrekeyBundle>,
    user_message_queue: HashMap<(String, [u8; 1]), Vec<MessageType>>,
    server_internal_queue: Vec<MessageType>
}
#[hax_lib::attributes]
impl Server {
    pub fn new() -> Self {
        Self {
            names_keybundles: HashMap::new(),
            user_message_queue: HashMap::new(),
            server_internal_queue: Vec::new(),
        }
    }
    
    // Bob calls this once on registration
    #[hax_lib::opaque]
    pub fn register_bundle(&mut self, user_id: (String, [u8; 1]), bundle: PrekeyBundle) {
        // Inserts the user's bundle in the server's map
        // Checks if the user id already is in the map
         if self.names_keybundles.contains_key(&user_id) {
            return;
        }
        // otherwise initializes
        self.names_keybundles.insert(user_id.clone(), bundle);
        //KRISTIAN CHANGED THE SYNTAX OF MUTABLES
        if !self.user_message_queue.contains_key(&user_id){
            self.user_message_queue.insert(user_id, Vec::new());
        }
     }
    
    
    // Request the messages for a user
    #[hax_lib::opaque]
    pub(crate) fn user_fetch_messages(&mut self, my_id: (String, [u8; 1])) -> Vec<MessageType> {
        // Iterates through the messages in the message queue and checks for matching id's
        if self.user_message_queue.contains_key(&my_id){
            let messages = self.user_message_queue.remove(&my_id).unwrap_or(Vec::new());
            self.user_message_queue.insert(my_id, Vec::new());
            messages
        } else{
            Vec::new()
        }
    }


    // Fetches a pre key bundle to the initiator
    #[hax_lib::opaque]
    pub fn fetch_bundle<'a> (&mut self, responder_id: (String, [u8; 1])) -> Result<FetchedBundle, &'a str>{
         if !self.names_keybundles.contains_key(&responder_id) {
            return Err("No matching responder ID");
        }

        // Makes a mutable clone of the responders pre key bundle
        let mut resp_pkb = self.names_keybundles.remove(&responder_id).unwrap();


        // Gets the pq one time prekey, and deletes it from the list of pq_s_opks
        let pq_s_opk = resp_pkb.pq_s_opks.pop();
        
        // Get the message queue of the user
        let message_queue_option = self.user_message_queue.remove(&responder_id);
        let mut message_queue = match message_queue_option {
            Some (mq) => mq,
            None => return Err("Could not find the user in the message queue when fetching the bundle")
        };

        // Checks whether the popped pq opk exists. If it doesn't exists, then the initiator should 
        // use the last resort prekey instead
        let (pqspk_pub, pqspk_id) = match pq_s_opk.clone() {
            Some((pq_s_opk_pub, pq_s_opk_id, _pq_s_opk_sig)) => (Some(pq_s_opk_pub), Some(pq_s_opk_id)),
            None => {
                message_queue.push(MessageType::MakePQOneTimePreKey);
                (Some(resp_pkb.pqspk_pub.clone()), Some(resp_pkb.pqspk_id))
            }
        };
        // Checks wehther the popped opk exists if it doesn't then the initiator should make more opk
        let opk  = match resp_pkb.opks.pop() {
            Some(opk) => Some(opk),
            None => {
                message_queue.push(MessageType::MakeOneTimePreKey);
                None
            }

        };
        
        // Makes the fetched bundle 
        let resp_fetch_bundle = FetchedBundle{
            ik_dh_pub: resp_pkb.ik_dh_pub,
            ik_dsa_pub: resp_pkb.ik_dsa_pub.clone(),
            spk_pub:   resp_pkb.spk_pub,
            spk_sig:   resp_pkb.spk_sig,   
            spk_id:    resp_pkb.spk_id,    
            pqspk_pub: pqspk_pub, 
            pqspk_sig: resp_pkb.pqspk_sig, 
            pqspk_id:  pqspk_id,  
            opk:       opk,       
            pq_opk:    pq_s_opk,    
        };

        self.user_message_queue.insert(responder_id.clone(), message_queue);
        self.names_keybundles.insert(responder_id, resp_pkb);

        return Ok(resp_fetch_bundle);        
    }

    #[hax_lib::opaque]
    pub(crate) fn register_message<'a>(&mut self, user_id: &(String, [u8; 1]), message: MessageType) -> Result<(), &'a str> {
        // Matches messages and sorts on server side or user side
        match message {
            MessageType::UploadOpks {..} | 
                    MessageType::UploadPQOpks {..} => {
                        self.server_internal_queue.push(message.clone());
                    },
            MessageType::NewMessage {..}| MessageType::InitialMessage {..}| MessageType::MakeOneTimePreKey | MessageType::MakePQOneTimePreKey => {
                let message_queue_option = self.user_message_queue.remove(user_id);
                let mut message_queue = match message_queue_option{
                    Some(mq) => mq,
                    None => return Err("Could not find the user in the message queue when fetching the bundle")
                };
                message_queue.push(message.clone());
                self.user_message_queue.insert(user_id.clone(), message_queue);                
            },
        }
        let _ = self.server_fetch_internal_queue()?;
        Ok(())
    }

    #[hax_lib::opaque]
    fn server_fetch_internal_queue<'a> (&mut self) -> Result<(), &'a str>{
        let message_queue = &self.server_internal_queue;
        for message in message_queue {
            match message{
                MessageType::MakeOneTimePreKey => return Err("Server should not make One Time Prekeys"),
                MessageType::MakePQOneTimePreKey => return Err("Server should not make PQ One Time Prekeys"),
                MessageType::NewMessage {..} => return Err("Server should get new messages but redirect them"),
                MessageType::UploadOpks {upload_opks_user_id: user_id, opks} => {
                    let pkb_option = self.names_keybundles.remove(&user_id);
                    let mut pkb = match pkb_option{
                        Some(pkb) => pkb,
                        None => return Err("Could not find the prekey")
                    };
                    for opk in opks{
                        pkb.opks.push(*opk);
                    }
                    self.names_keybundles.insert(user_id.clone(), pkb);
                }
                MessageType::UploadPQOpks {upload_pqopks_user_id: user_id, pq_opks} =>{
                    let pkb_option = self.names_keybundles.remove(&user_id);
                    let mut pkb = match pkb_option {
                        Some(pkb) => pkb,
                        None => return Err("Could not find the prekey")
                    };

                    for pq_opk in pq_opks{
                        // Inserts the id and public key in the servers keybundle of the specific user
                        let (pk, id, sig) = pq_opk;
                        
                        // Inserts the public key, id and signature in the servers keybundle of the specific user
                        pkb.pq_s_opks.push((pk.clone(), *id, *sig));
                    }
                    self.names_keybundles.insert(user_id.clone(), pkb);
                }
                MessageType::InitialMessage{..} => return Err("Server should not get initial messages, but redirect them")
            }
        }
        self.server_internal_queue = Vec::new();
        Ok(())

    }

}

#[cfg(test)]
mod tests {
    use crate::client::client_impl::{Client};
    use crate::server::server_impl::Server; 
    use std::collections::HashMap;

    fn make_server() -> Server{
            return Server::new();
    }

    #[test]
    fn register_key_bundle(){
        let mut server = make_server();
        // the prekey is uploaded when a new account is made
        let alice = Client::new("Alice", None,  &mut server);
        // let bob = Client::new("Bob", None, None, &mut server);
        let extracted: HashMap<_, _> = server.names_keybundles.extract_if(|id, _v| *id == alice.name).collect();
        let has_pre_key_for_alice = extracted.contains_key(&alice.name);
        assert!(has_pre_key_for_alice, "ERROR: Did not find Alice's keybundle in server's list");
    }
    #[test]
    fn register_multiple_messages_in_queue_same_user(){
        let mut server = make_server();
        let mut alice = Client::new("Alice", None,  &mut server);
        let bob = Client::new("Bob", None,  &mut server);
        
        let _ = alice.send_new_message(&bob.name, "plaintext".to_string(), &mut server);
        let _ = alice.send_new_message(&bob.name, "plaintext2".to_string(), &mut server);
        
        // Counts the messages in the message queue
        let count = server.user_message_queue
            .get(&bob.name)
            .map(|messages| messages.len())
            .unwrap_or(0);
        // There should be two messages in the queue
        assert_eq!(count, 3);
    }

    #[test]
    fn fetch_bundle_removes_pq_opk_and_opk() {
        let mut server = Server::new();
        let _alice = Client::new("Alice", None,  &mut server);
        let bob = Client::new("Bob", None,  &mut server);
        
        let before_pq_opk = server.names_keybundles[&bob.name].pq_s_opks.len();
        let _ = server.fetch_bundle(bob.name.clone());
        let after_pq_opk = server.names_keybundles[&bob.name].pq_s_opks.len();
        
        assert_eq!(after_pq_opk, before_pq_opk - 1);

        let before_opk = server.names_keybundles[&bob.name].pq_s_opks.len();
        let _ = server.fetch_bundle(bob.name.clone());
        let after_opk = server.names_keybundles[&bob.name].pq_s_opks.len();
        
        assert_eq!(after_opk, before_opk - 1);
    }
    #[test]
    fn unknown_user_panics(){
        let mut server = Server::new();
        let _alice = Client::new("Alice", None,  &mut server);
        let _bob = Client::new("Bob", None,  &mut server);
        let eve_id = ("Eve".to_string(), [0u8;1]);
        let result_fetched_bundle = server.fetch_bundle(eve_id);
        assert_eq!(result_fetched_bundle, Err("No matching responder ID"));
    }
    #[test]
    fn fetch_messages_clears_queue(){
        let mut server = Server::new();
        let mut alice = Client::new("Alice", None,  &mut server);
        let mut bob = Client::new("Bob", None,  &mut server);

        let bob_fetched_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone()).expect("Should fetch the bundle");

        let _ = alice.initial_message(&mut server, &bob_fetched_bundle, &bob.name);
        
        let _ = bob.fetch_message_from_server(&mut server);

        let _ = alice.send_new_message(&bob.name, "Hello mister".to_string(), &mut server);
        let _ = alice.send_new_message(&bob.name, "Hello mister two times".to_string(), &mut server);

        // Checks the sizes before and after a fetch
        let size_before = server.user_message_queue.get_mut(&bob.name).expect("Can't get bob from in the message queue").len();
        let _messages_of_bob = server.user_fetch_messages(bob.name.clone());
        let size_after = server.user_message_queue.get_mut(&bob.name).expect("Can't get bob from in the message queue").len();

        assert_eq!(size_before, size_after+2);
    }

    
    #[test]
    fn register_bundle_duplicate_ignored(){
        let mut server = Server::new();
        let alice_one = Client::new("Alice", Some(*b"1"),  &mut server);
        let alice_one_ik = server.fetch_bundle(alice_one.name.clone()).expect("Should fetch the bundle").ik_dh_pub;
        let alice_two = Client::new("Alice", Some(*b"1"),  &mut server);
        
        // makes sure there is still 1 account
        assert_eq!(server.names_keybundles.len(), 1);

        // makes sure, the key for Alice is the same as before the Alice-two instance
        let alice_two_ik = server.fetch_bundle(alice_two.name.clone()).expect("Should fetch the bundle").ik_dh_pub;
        assert_eq!(alice_one_ik, alice_two_ik);


    }
    // more_opk_message_in_queue
    #[test]
    fn messages_from_user_are_registered(){
        let mut server = Server::new();
        let mut alice = Client::new("Alice", None,  &mut server);
        let mut bob = Client::new("Bob", None,  &mut server);

        let a_fetched_bundle = bob.fetch_bundle_from_server(&mut server, alice.name.clone()).expect("Should fetch the bundle");

        let _ = bob.initial_message(&mut server, &a_fetched_bundle, &alice.name);

        let _ = bob.send_new_message(&alice.name, "plaintext".to_string(), &mut server);
        let _ = bob.send_new_message(&alice.name, "plaintext2".to_string(), &mut server);
    
        let _ = alice.fetch_message_from_server(&mut server);
        let len_queue = server.server_internal_queue.len();
        assert_eq!(len_queue, 0);
    }
    #[test]
    fn added_20_pq_opk_and_opk_when_empty(){
        let mut server = Server::new();
                
        let mut alice = Client::new("Alice", None,  &mut server);
        let mut bob = Client::new("Bob", None,  &mut server);

        let _bob_pk_bundle = alice.fetch_bundle_from_server(&mut server, bob.name.clone());
        // Alice fetches Bob's key bundle 20 times
        // Empties the pq opk, such that the verifying will be on the last resort key
        for _ in 0..20{
            let _ = alice.fetch_bundle_from_server(&mut server, bob.name.clone());
        }

        let _bob_pkb = server.names_keybundles.get(&bob.name).expect("Couldn't find the prekey bundle for Bob");

        // Bob fetches messages, and uploads the new opk and pqopk to the server
        let _ = bob.fetch_message_from_server(&mut server).expect("Can't find messages for Bob");
        
        // The server fetches the new opks and pq opks and inserts in Bob's prekey bundle
        let _ = server.server_fetch_internal_queue();


        let bob_pkb = server.names_keybundles.get(&bob.name).expect("Couldn't find the prekey bundle for Bob");
        let len_opk_after_fetching = bob_pkb.opks.len();

        assert_eq!(len_opk_after_fetching, 19)
    }

    // Eve tries to upload new opk in Alice's name (which should not be legal)
}