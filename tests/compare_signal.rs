#[cfg(test)] 
mod signal_compare {
    use std::time::{SystemTime, Duration};
    use hacss::spqr::spqr_impl::SPQRState;
    use hacss::triple_ratchet::triple_ratchet_impl::TripleRatchetState;
    use hacss::client::client_impl::Client;
    use hacss::server::server_impl::Server;
    use hacss::util::keys;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use spqr::{send, recv, initial_state, Version, Direction, ChainParams, Params};
    use futures_util::FutureExt as _;
    use libsignal_protocol::{
        DeviceId, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeyStore, ProtocolAddress, SessionStore, SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt, process_prekey_bundle
    };

    const AUTH_KEY: &[u8; 32] = &[0x42u8; 32];

    fn signal_states_spqr() -> (spqr::SerializedState, spqr::SerializedState) {
        let alice = initial_state(Params {
            version:     Version::V1,
            min_version: Version::V1,
            direction:   Direction::A2B,
            auth_key:    AUTH_KEY,
            chain_params: ChainParams::default(),
        }).expect("Signal alice init failed");

        let bob = initial_state(Params {
            version:     Version::V1,
            min_version: Version::V1,
            direction:   Direction::B2A,
            auth_key:    AUTH_KEY,
            chain_params: ChainParams::default(),
        }).expect("Signal bob init failed");

        (alice, bob)
    }
    struct SignalSession {
        alice_store: InMemSignalProtocolStore,
        bob_store: InMemSignalProtocolStore,
        alice_address: ProtocolAddress,
        bob_address: ProtocolAddress,
    }

    fn setup_signal_session() -> SignalSession {
        let mut csprng = StdRng::from_os_rng();

        let alice_address = ProtocolAddress::new("+14151111111".to_owned(), DeviceId::new(1).unwrap());
        let bob_address   = ProtocolAddress::new("+14151111112".to_owned(), DeviceId::new(1).unwrap());
        let bob_device_id = DeviceId::new(1).unwrap();

        // Stores
        let alice_identity = IdentityKeyPair::generate(&mut csprng);
        let mut alice_store = InMemSignalProtocolStore::new(alice_identity, csprng.random::<u8>() as u32).unwrap();

        let bob_identity = IdentityKeyPair::generate(&mut csprng);
        let mut bob_store = InMemSignalProtocolStore::new(bob_identity, csprng.random::<u8>() as u32).unwrap();

        // Bob's one-time pre-key
        let pre_key_pair = KeyPair::generate(&mut csprng);
        let pre_key_id: u32 = csprng.random();
        bob_store.save_pre_key(pre_key_id.into(), &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair))
            .now_or_never().expect("sync").unwrap();

        // Bob's signed pre-key
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);
        let signed_pre_key_id: u32 = csprng.random();
        let spk_public    = signed_pre_key_pair.public_key.serialize();
        let spk_signature = bob_identity.private_key().calculate_signature(&spk_public, &mut csprng).unwrap();
        bob_store.save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(signed_pre_key_id.into(), Timestamp::from_epoch_millis(42), &signed_pre_key_pair, &spk_signature),
        ).now_or_never().expect("sync").unwrap();

        // Bob's Kyber pre-key
        let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
        let kyber_pre_key_id: u32 = csprng.random();
        let kpk_public    = kyber_pre_key_pair.public_key.serialize();
        let kpk_signature = bob_identity.private_key().calculate_signature(&kpk_public, &mut csprng).unwrap();
        bob_store.save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(kyber_pre_key_id.into(), Timestamp::from_epoch_millis(43), &kyber_pre_key_pair, &kpk_signature),
        ).now_or_never().expect("sync").unwrap();

        // Bundle + session establishment
        let bob_bundle = PreKeyBundle::new(
            bob_store.get_local_registration_id().now_or_never().expect("sync").unwrap(),
            bob_device_id,
            Some((pre_key_id.into(), pre_key_pair.public_key)),
            signed_pre_key_id.into(),
            signed_pre_key_pair.public_key,
            spk_signature.to_vec(),
            kyber_pre_key_id.into(),
            kyber_pre_key_pair.public_key.clone(),
            kpk_signature.to_vec(),
            *bob_identity.identity_key(),
        ).unwrap();

        process_prekey_bundle(
            &bob_address, &alice_address,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bob_bundle,
            SystemTime::now(),
            &mut csprng,
        ).now_or_never().expect("sync").unwrap();

        SignalSession { alice_store, bob_store, alice_address, bob_address }
    }

    /* 
    Compare the time it takes for 80 messages between two parties for SIGNAL Triple Ratchet and HACSS Triple Ratchet
    */
    #[test]
    fn benchmark_triple_ratchet_compare() {
        const RUNS: i64 = 250;

        let mut hacss_loop_times: Vec<std::time::Duration> = Vec::new();
        let mut hacss_init_times: Vec<std::time::Duration> = Vec::new();
        let mut signal_loop_times: Vec<std::time::Duration> = Vec::new();
        let mut signal_init_times: Vec<std::time::Duration> = Vec::new();

        // HACSS implmentation
        for _ in 0..RUNS {
            let now_hacss_init = SystemTime::now();
    
            let server = &mut Server::new();
            let mut alice = Client::new("Alice", None, server);
            let mut bob = Client::new("Bob", None, server);

            if let Ok(init_el) = now_hacss_init.elapsed() {
                hacss_init_times.push(init_el);
            }
            
            let now_hacss = SystemTime::now();
            for i in 0..80 {
                let plaintext= format!("{}", i);
                alice.send_new_message(&bob.name, plaintext.clone(), server).unwrap();
                bob.receive(server, &alice.name).unwrap();
                bob.send_new_message(&alice.name, plaintext, server).unwrap();
                alice.receive(server, &bob.name).unwrap();
            }
            
            if let Ok(loop_el) = now_hacss.elapsed() {
                hacss_loop_times.push(loop_el);
            }
        }

        // Signal implementation
        for _ in 0..RUNS {
            let now_signal_init = SystemTime::now();
            
            let SignalSession { mut alice_store, mut bob_store, alice_address, bob_address }
                = setup_signal_session();

            let mut csprng = StdRng::from_os_rng();

            if let Ok(loop_el) = now_signal_init.elapsed() {
                signal_init_times.push(loop_el);
            }

            // Messages to be sent
            let now_signal = SystemTime::now();

            for i in 0..80 {
                let plaintext = format!("{}", i);

                // Alice → Bob
                let alice_ct = message_encrypt(
                    plaintext.as_bytes(),
                    &bob_address,
                    &alice_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    SystemTime::now(),
                    &mut csprng,
                )
                .now_or_never()
                .expect("sync")
                .unwrap();

                message_decrypt(
                    &alice_ct,
                    &alice_address,
                    &bob_address,
                    &mut bob_store.session_store,
                    &mut bob_store.identity_store,
                    &mut bob_store.pre_key_store,
                    &bob_store.signed_pre_key_store,
                    &mut bob_store.kyber_pre_key_store,
                    &mut csprng,
                )
                .now_or_never()
                .expect("sync")
                .unwrap();

                // Bob → Alice
                let bob_ct = message_encrypt(
                    plaintext.as_bytes(),
                    &alice_address,
                    &bob_address,
                    &mut bob_store.session_store,
                    &mut bob_store.identity_store,
                    SystemTime::now(),
                    &mut csprng,
                )
                .now_or_never()
                .expect("sync")
                .unwrap();

                message_decrypt(
                    &bob_ct,
                    &bob_address,
                    &alice_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    &mut alice_store.pre_key_store,
                    &alice_store.signed_pre_key_store,
                    &mut alice_store.kyber_pre_key_store,
                    &mut csprng,
                )
                .now_or_never()
                .expect("sync")
                .unwrap();
            }

            if let Ok(loop_el) = now_signal.elapsed() {
                signal_loop_times.push(loop_el);
            }
        }
        let avg_ms = |durations: &Vec<Duration>| -> f64 {
            let total_micros: u128 = durations.iter().map(|d: &std::time::Duration| d.as_micros()).sum();
            (total_micros as f64 / durations.len() as f64) / 1000.0
        };
        println!("------------------------------------------------------");
        println!("Average times for Triple Ratchet init and message loop");
        println!("250 runs, with each sending and receiving 160 messages");
        println!("Time is microseconds");
        println!("------------------------------------------------------");
        println!("HACSS Triple Ratchet");
        println!("Avg time init: {}", avg_ms(&hacss_init_times));
        println!("Avg time: {}", avg_ms(&hacss_loop_times));
        println!("------------------------------------------------------");
        println!("Signal Triple Ratchet");
        println!("Avg time init: {}", avg_ms(&signal_init_times));
        println!("Avg time: {}", avg_ms(&signal_loop_times));
        println!("------------------------------------------------------");
    }

    /* 
    Compare the time it takes for 80 messages between two parties for SIGNAL SPQR and HACSS SPQR
    */
    #[test]
    fn benchmark_spqr_compare() {
        const RUNS: i64 = 250;

        let mut hacss_loop_times: Vec<std::time::Duration> = Vec::new();
        let mut hacss_init_times: Vec<std::time::Duration> = Vec::new();
        let mut signal_loop_times: Vec<std::time::Duration> = Vec::new();
        let mut signal_init_times: Vec<std::time::Duration> = Vec::new();

        // HACSS implmentation
        for _ in 0..RUNS {
            let now_hacss_init = SystemTime::now();
            let mut alice = SPQRState::ratchet_init_initiator(AUTH_KEY);
            let mut bob   = SPQRState::ratchet_init_responder(AUTH_KEY);
            let ad = [0x01u8; 64];
            if let Ok(init_el) = now_hacss_init.elapsed() {
                hacss_init_times.push(init_el);
            }
            
            let now_hacss = SystemTime::now();
            for i in 0..80 {
                let i: i32 = i;
                let alice_msg = alice.scka_ratchet_encrypt(format!("{}",i), &ad)
                    .expect("Should send msg for Alice");
                bob.scka_ratchet_decrypt(alice_msg.0, &alice_msg.1, &ad).unwrap();
                let bob_msg = bob.scka_ratchet_encrypt(format!("{}",i*2), &ad)
                    .expect("Should send msg for Alice");
                alice.scka_ratchet_decrypt(bob_msg.0, &bob_msg.1, &ad).unwrap();
            }
            
            if let Ok(loop_el) = now_hacss.elapsed() {
                hacss_loop_times.push(loop_el);
            }
        }

        // Signal implmentation
        for _ in 0..RUNS {
            let mut rng = StdRng::from_os_rng();
            let now_signal_init = SystemTime::now();
            let (mut alice_state, mut bob_state) = signal_states_spqr();

            if let Ok(init_el) = now_signal_init.elapsed() {
                signal_init_times.push(init_el);
            }

            let now_signal = SystemTime::now();
            for _ in 0..80 {
                let spqr::Send { state, msg, key: _alice_key_1 } = send(&alice_state, &mut rng).unwrap();
                alice_state = state;
                let spqr::Recv { state, key: _bob_key_1 } = recv(&bob_state, &msg).unwrap();
                bob_state = state;

                let spqr::Send { state, msg, key: _bob_key_2 } = send(&bob_state, &mut rng).unwrap();
                bob_state = state;
                let spqr::Recv { state, key: _alice_key_2 } = recv(&alice_state, &msg).unwrap();
                alice_state = state;       
            }
            if let Ok(loop_el) = now_signal.elapsed() {
                signal_loop_times.push(loop_el);
            }
        }
        let avg_ms = |durations: &Vec<Duration>| -> f64 {
            let total_micros: u128 = durations.iter().map(|d: &std::time::Duration| d.as_micros()).sum();
            (total_micros as f64 / durations.len() as f64) / 1000.0
        };
        println!("------------------------------------------------------");
        println!("Average times for SPQR init and message loop");
        println!("250 runs, with each sending and receiving 160 messages");
        println!("Time is microseconds");
        println!("------------------------------------------------------");
        println!("HACSS SPQR");
        println!("Avg time init: {}", avg_ms(&hacss_init_times));
        println!("Avg time: {}", avg_ms(&hacss_loop_times));
        println!("------------------------------------------------------");
        println!("Signal SPQR");
        println!("Avg time init: {}", avg_ms(&signal_init_times));
        println!("Avg time: {}", avg_ms(&signal_loop_times));
        println!("------------------------------------------------------");
    }

    // Testing whether we get same message keys
    // Testing for KDF and send receive in SPQR with ML-KEM Braid
    #[test]
    #[should_panic]
    fn kdf_init_structure_comparison_spqr() {

        let mut rng = StdRng::from_os_rng();
        let (mut signal_alice, mut signal_bob) = signal_states_spqr();

        // Send atleast twice to get messagekeys
        let spqr::Send { state, msg, .. } = send(&signal_alice, &mut rng).unwrap();
        signal_alice = state;
        let spqr::Recv { state, .. } = recv(&signal_bob, &msg).unwrap();
        signal_bob = state;
        let spqr::Send { state: _, msg, key: _ } = send(&signal_bob, &mut rng).unwrap();
        
        let spqr::Recv { state, .. } = recv(&signal_alice, &msg).unwrap();
        signal_alice = state;
        let spqr::Send { state: _, msg: _, key: signal_key_3 } = send(&signal_alice, &mut rng).unwrap();
        

        // Also sends atleast two messages with HACSS SPQR
        let mut hacss_alice = SPQRState::ratchet_init_initiator(AUTH_KEY);
        let mut hacss_bob   = SPQRState::ratchet_init_responder(AUTH_KEY);

        let (msg1, ctr1, _) = hacss_alice.scka_ratchet_send_key().unwrap();
        hacss_bob.scka_ratchet_receive_key(SPQRState::scka_header(msg1, ctr1)).unwrap();
        let (msg2, ctr2, _) = hacss_bob.scka_ratchet_send_key().unwrap();
        hacss_alice.scka_ratchet_receive_key(SPQRState::scka_header(msg2, ctr2)).unwrap();
        let (_, _, your_key_3) = hacss_alice.scka_ratchet_send_key().unwrap();

        // Prints for inspection
        eprintln!("Signal key (round 3): {:?}",
            signal_key_3.as_deref().map(hex::encode));
        eprintln!("Your   key (round 3): {}",
            hex::encode(your_key_3.0));

        // Checking whether message keys for both SPQR is the same
        assert_eq!(
            signal_key_3.as_deref(),
            Some(your_key_3.0.as_slice()),
            "KDF mismatch: key derivation differ from Signal's. \
            kdf_scka_init vs Signal's Chain::new"
        );
    }

    /*
    Testing for sizes of ciphertexts in either implementation of Triple Ratchet
    */
    #[test]
    fn compare_ct_size () {
        // Setup HACSS
        let mut tr_state = TripleRatchetState::rathet_init_initiator_tr(*AUTH_KEY, *AUTH_KEY, keys::X25519PublicKey([12u8; 32]));
        let ad = [123u8; 64];
        
        // Setup Signal Session
        let SignalSession { mut alice_store, bob_store: _, alice_address, bob_address }
            = setup_signal_session();
        let mut csprng = StdRng::from_os_rng();



        let plaintexts = ["".to_string(), "hello".to_string(), "a".repeat(100), "a".repeat(1000)];
        println!("-------- Signal and HACSS ciphertexts lengths --------");
        for pt in &plaintexts {
            // HACSS encrypt
            let payload = tr_state.tr_encrypt(pt, &ad).unwrap();
            let ct_hacss = payload.1;



            // Signal encrypt
            let ct_signal = message_encrypt(
                    pt.as_bytes(),
                    &bob_address,
                    &alice_address,
                    &mut alice_store.session_store,
                    &mut alice_store.identity_store,
                    SystemTime::now(),
                    &mut csprng,
                )
                .now_or_never()
                .expect("sync")
                .unwrap();
            
            // Print both
            println!("Plaintext length: {}", pt.len());
            println!("HACSS ciphertext: {:?}", ct_hacss.len());
            println!("Signal ciphertext: {:?}", ct_signal.serialize().len());
            println!("------------------------------------------------------")
        }
    }

    /*  
    Testing the size of sessions to before and after messages to reason for the long initialization time.
    */
    #[test]
    fn compare_session_size() {
        let mut server = Server::new();
        let mut alice = Client::new("Alice", None, &mut server);
        let mut bob = Client::new("Bob", None, &mut server);
        let _ = alice.send_new_message(&bob.name, "".to_string(), &mut server);
        let _ = bob.receive(&mut server, &alice.name);

        let SignalSession { mut alice_store, mut bob_store, alice_address, bob_address }
            = setup_signal_session();
        let mut csprng = StdRng::from_os_rng();

        // Print CSV header
        println!("messages,signal_bytes,hacss_bytes");

        // Log initial sizes
        let signal_size = alice_store.session_store
            .load_session(&bob_address)
            .now_or_never().expect("sync").unwrap()
            .map(|s| s.serialize().unwrap().len()).unwrap_or(0);
        let hacss_size = alice.sessions.get_session(&bob.name).unwrap().session_size();
        println!("0,{},{}", signal_size, hacss_size);

        for i in 0..2500 {
            let pt = format!("{}", i);

            // HACSS
            alice.send_new_message(&bob.name, pt.clone(), &mut server).unwrap();
            bob.receive(&mut server, &alice.name).unwrap();
            bob.send_new_message(&alice.name, pt.clone(), &mut server).unwrap();
            alice.receive(&mut server, &bob.name).unwrap();

            // Signal Alice -> Bob
            let ct = message_encrypt(
                pt.as_bytes(), &bob_address, &alice_address,
                &mut alice_store.session_store, &mut alice_store.identity_store,
                SystemTime::now(), &mut csprng,
            ).now_or_never().expect("sync").unwrap();
            message_decrypt(
                &ct, &alice_address, &bob_address,
                &mut bob_store.session_store, &mut bob_store.identity_store,
                &mut bob_store.pre_key_store, &bob_store.signed_pre_key_store,
                &mut bob_store.kyber_pre_key_store, &mut csprng,
            ).now_or_never().expect("sync").unwrap();

            // Signal Bob -> Alice
            let ct = message_encrypt(
                pt.as_bytes(), &alice_address, &bob_address,
                &mut bob_store.session_store, &mut bob_store.identity_store,
                SystemTime::now(), &mut csprng,
            ).now_or_never().expect("sync").unwrap();
            message_decrypt(
                &ct, &bob_address, &alice_address,
                &mut alice_store.session_store, &mut alice_store.identity_store,
                &mut alice_store.pre_key_store, &alice_store.signed_pre_key_store,
                &mut alice_store.kyber_pre_key_store, &mut csprng,
            ).now_or_never().expect("sync").unwrap();

            // Log every 50 message rounds
            if (i + 1) % 20 == 0 {
                let signal_size = alice_store.session_store
                    .load_session(&bob_address)
                    .now_or_never().expect("sync").unwrap()
                    .map(|s| s.serialize().unwrap().len()).unwrap_or(0);
                let hacss_size = alice.sessions.get_session(&bob.name).unwrap().session_size();
                println!("{},{},{}", (i + 1) * 2, signal_size, hacss_size);
            }
        }
    }
   

}