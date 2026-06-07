use crate::{client::session::{Session, SessionStore}, util::{
    helper_func::make_randomness, 
    keys::{self, ML_KEM_768_CT_SIZE, X25519KeyPair}, 
    libcrux_wrap::{
        libcrux_aead_decrypts_ad_initial_message, libcrux_aead_encrypts_ad_initial_message, libcrux_ecdh_x25519_derive, libcrux_gen_kdf_key, libcrux_ml_dsa_generate_key_pair, libcrux_ml_dsa_sign, libcrux_ml_dsa_verify, libcrux_ml_kem_768_encaps, libcrux_ml_kem_decapsulate, libcrux_ml_kem_generate_key_pair
    }, messages::{
        IDUseNameKey, 
        MessageType
    } 
    }};


pub enum TypeCounter {
    SpkCounter,    
    PqspkCounter,  
    OpkCounter,  
    PqOpkCounter,
}

pub struct PQXDHState {
    // Key bundle used for PQXDH
    pub(crate) keybundle: keys::UserKeyBundle,

    // Counters for PQXDH
    pub(crate) spk_counter:    u32,
    pub(crate) pqspk_counter:  u32,
    pub(crate) opk_counter:    u32,
    pub(crate) pq_opk_counter: u32,
}

#[hax_lib::attributes]
impl PQXDHState {
    #[hax_lib::opaque]
    pub fn new() -> Self {
        let user_key_bundle = setup_user_key_bundle();

        Self { 
            keybundle: user_key_bundle, 
            spk_counter: 0, 
            pqspk_counter: 0, 
            opk_counter: 20, 
            pq_opk_counter: 20 
        }
    }

    
    
    /* 
    Adds 20 new one-time prekeys to the PQXDHState
    */
    #[hax_lib::opaque]
    pub fn add_20_opk(&mut self) ->  Vec<(keys::X25519PublicKey, u32)>{
        let mut new_opks: Vec<(keys::X25519PublicKey, u32)> = Vec::new();
        for _ in 0..19{
            let opk_key_pair = gen_curve_key_pair();
            let opk_ot_pair = keys::OneTimePreKey {
                id: self.get_and_add_counter(TypeCounter::OpkCounter),
                key: opk_key_pair   
            };
            let opk_ot_pub: (keys::X25519PublicKey, u32) = (opk_ot_pair.key.public_key, opk_ot_pair.id);
            self.keybundle.opks.push(opk_ot_pair);
            new_opks.push(opk_ot_pub);
        }
        new_opks
    }

    /* 
    Adds 20 new one-time pq signed prekeys to the PQXDHState
    */
    #[hax_lib::opaque]
    pub fn add_20_pqs_opk(&mut self) -> Vec<(keys::EncapsulationKey, u32, [u8; keys::MLDSA_65_SIGNATURE_KEY_SIZE])>{
        let mut new_pq_opks: Vec<(keys::EncapsulationKey, u32, [u8; keys::MLDSA_65_SIGNATURE_KEY_SIZE])> = Vec::new();
        
        
        let pq_context = b"Signed PQOPK";
        for _ in 0..20{
            let pq_ml_key_pair = libcrux_ml_kem_generate_key_pair();
            // Signing each of the one-time prekeys
            let pq_opk_signature = libcrux_ml_dsa_sign(&self.keybundle.identity.dsa.signing_key, &pq_ml_key_pair.1, pq_context);
            let pq_opk = keys::PQOneTimePreKey{
                id: self.get_and_add_counter(TypeCounter::PqOpkCounter),
                key:  keys::PQKeyPair {
                        public_key: keys::EncapsulationKey (pq_ml_key_pair.1),
                        secret_key: keys::DecapsulationKey (pq_ml_key_pair.0)
                    },
                sig: pq_opk_signature
            };
            let pq_opk_pub: (keys::EncapsulationKey, u32, [u8; keys::MLDSA_65_SIGNATURE_KEY_SIZE]) = (pq_opk.key.public_key.clone(), pq_opk.id, pq_opk_signature);
            self.keybundle.pq_opks.push(pq_opk);

            new_pq_opks.push(pq_opk_pub);  
        } 
        new_pq_opks
        
    }

    /*
    Get's and add to the counter of accounts
    */
    #[hax_lib::opaque]
    #[hax_lib::ensures(|res| res <= u32::MAX)]
    fn get_and_add_counter(&mut self, type_of_counter: TypeCounter) -> u32{
        match type_of_counter {
            TypeCounter::SpkCounter => {
                self.spk_counter += 1;
                return self.spk_counter; 
            } 
            TypeCounter::PqspkCounter => { 
                self.pqspk_counter += 1;
                return self.pqspk_counter;
            }
            TypeCounter::OpkCounter =>  { 
                self.opk_counter += 1;
                return self.opk_counter;
            }
            TypeCounter::PqOpkCounter => {
                self.pq_opk_counter += 1;
                return self.pq_opk_counter;
            }
        }
    }

}

/* 
Generates key pair with curve25519
Uses Libcrux library
*/
#[hax_lib::ensures(|res| 
     res.private_key.0.len() == 32
    && res.public_key.0.len() == 32)]
pub fn gen_curve_key_pair() -> keys::X25519KeyPair{
    let (private_key, public_key) = libcrux_ecdh_key_gen_to_bytes();
    let private_key_refac: keys::X25519PrivateKey = keys::X25519PrivateKey (private_key);
    let public_key_refac: keys::X25519PublicKey = keys::X25519PublicKey (public_key);
    let key_pair = keys::X25519KeyPair {
        private_key: private_key_refac,
        public_key: public_key_refac,
    };
    key_pair
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.0.len() == 32 && res.1.len() == 32)]
fn libcrux_ecdh_key_gen_to_bytes() -> ([u8; 32], [u8; 32]) {
    #[cfg(not(hax))]{
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let mut rng = StdRng::from_os_rng();
    let (private_key, public_key)= libcrux_ecdh::x25519_key_gen(&mut rng).expect("Key generation failed");
    (private_key.0, public_key.0)
    }
    #[cfg(hax)]{
        ([0u8; 32], [0u8; 32])
    }
}

pub(crate) fn create_sk<const N: usize>(salt: [u8; 32], concat_dh_final: [u8; 160], info: &[u8; N]) -> [u8; 32] {
    libcrux_gen_kdf_key(&salt, &concat_dh_final, info)
}
#[hax_lib::opaque]
pub(crate) fn setup_user_key_bundle() -> keys::UserKeyBundle {
    // Generating the identity key pair (X25519)
        let id_key_pair = gen_curve_key_pair();

        // Generating the signing key pair using ML-DSA from libcrux library (part of identity key struct)
        let (signing_key, verification_key) = libcrux_ml_dsa_generate_key_pair(); // 4032 , 1952
        let id_signing_key_pair = keys::IdentityDSAKey {
            signing_key: keys::MLDSA65SigningKey(signing_key),
            verification_key: keys::MLDSA65VerificationKey(verification_key)
        };

        // --------------------------------------------------------------------

        // Generating pre-key key pair, where we want to sign the public key
        let pre_key_pair = gen_curve_key_pair();
        
        // Sign the raw bytes of the pre-key public key
        let zero_context = b"Sig(IK, EncodeEC(SPK), Z_SPK)";
        let spk_signature_byte = libcrux_ml_dsa_sign(&id_signing_key_pair.signing_key, &pre_key_pair.public_key.0, zero_context);

        // Creating struct SPK
        let signed_pre_key = keys::SignedPreKey {
            id: 0,
            key: pre_key_pair,
            sig: spk_signature_byte
        };

        // Generating the post-quantum last-resort prekey
        let pq_keypair = libcrux_ml_kem_generate_key_pair();
        
        // Creating PQ key pair struct
        let pq_last_resort_pair = keys::PQKeyPair {
            public_key: keys::EncapsulationKey(pq_keypair.1),
            secret_key: keys::DecapsulationKey (pq_keypair.0)
        };

        // Signing the post-quantum last-resort prekey
        let pq_zero_context = b"Sig(IK, EncodeKEM(PQSPK), ZPQSPK)";
        let pq_spk_signature = libcrux_ml_dsa_sign(&id_signing_key_pair.signing_key, &pq_last_resort_pair.public_key.0, pq_zero_context);

        // Creating struct PQSPK
        let pq_signed_pre_key = keys::PQSignedPreKey {
            id: 0,
            key: pq_last_resort_pair,
            sig: pq_spk_signature
        };

        // --------------------------------------------------------------------


        // One-time prekeys bundle for use 
        let mut one_pre_keys: Vec<keys::OneTimePreKey> = Vec::new();
        for i in 0..20{
            let opk_key_pair = gen_curve_key_pair();
            let opk_ot_pair = keys::OneTimePreKey {
                id: i as u32,
                key: opk_key_pair   
            };
            one_pre_keys.push(opk_ot_pair);
        }

        // --------------------------------------------------------------------

        // PQ one-time prekeys bundle for use 
        let mut pq_one_pre_keys: Vec<keys::PQOneTimePreKey> = Vec::new();
        let pq_zero_context = b"(PQOPK, id, Sig(IK, EncodeKEM(PQOPK), Z))";
        for i in 0..20{
            let pq_ml_key_pair = libcrux_ml_kem_generate_key_pair();
            // Signing each of the one-time prekeys
            let pq_opk_signature = libcrux_ml_dsa_sign(&id_signing_key_pair.signing_key, &pq_ml_key_pair.1, pq_zero_context);
            let pq_opk = keys::PQOneTimePreKey{
                id: i as u32,
                key:  keys::PQKeyPair {
                        public_key: keys::EncapsulationKey (pq_ml_key_pair.1),
                        secret_key: keys::DecapsulationKey (pq_ml_key_pair.0)
                    },
                sig: pq_opk_signature
            };
            pq_one_pre_keys.push(pq_opk);
        }

        // --------------------------------------------------------------------

        let iden_key_pair = keys::IdentityKeys {
            dh: id_key_pair,
            dsa: id_signing_key_pair
        };

        let user_key_bundle = keys::UserKeyBundle {
            identity: iden_key_pair,
            spk: signed_pre_key,
            spk_prev: None,
            pqspk: pq_signed_pre_key,
            pqspk_prev: None, 
            opks: one_pre_keys,
            pq_opks: pq_one_pre_keys,
        };

        user_key_bundle
}

#[hax_lib::opaque]
pub(crate) fn setup_pre_key_bundle(user_key_bundle: &keys::UserKeyBundle) -> keys::PrekeyBundle {
    let opks_for_prekey: Vec<(keys::X25519PublicKey, u32)> = user_key_bundle.opks
            .iter()
            .map(|opk| (opk.key.public_key, opk.id))
            .collect();

    let pq_s_opks_for_prekey: Vec<(keys::EncapsulationKey, u32, [u8; keys::MLDSA_65_SIGNATURE_KEY_SIZE])> = user_key_bundle.pq_opks
        .iter()
        .map(|pq_opk| (pq_opk.key.public_key.clone(), pq_opk.id,pq_opk.sig))
        .collect();


    let pre_key_bundle = keys::PrekeyBundle {
        ik_dh_pub: user_key_bundle.identity.dh.public_key.clone(),
        ik_dsa_pub: user_key_bundle.identity.dsa.verification_key.clone(),
        spk_pub: user_key_bundle.spk.key.public_key.clone(),
        spk_sig: user_key_bundle.spk.sig.clone(),
        spk_id: user_key_bundle.spk.id.clone(),
        pqspk_pub: user_key_bundle.pqspk.key.public_key.clone(),
        pqspk_sig: user_key_bundle.pqspk.sig.clone(),
        pqspk_id: user_key_bundle.pqspk.id.clone(),
        opks: opks_for_prekey,
        pq_s_opks: pq_s_opks_for_prekey
    };

    pre_key_bundle
}

// Verify the signatures from the prekey bundle
#[hax_lib::opaque]
pub(crate) fn verify_pre_keys<'a> (fetched_bundle: &keys::FetchedBundle) -> Result<(), &'a str> {   
    let spk_context    = b"Sig(IK, EncodeEC(SPK), Z_SPK)";
    let pqspk_context  = b"Sig(IK, EncodeKEM(PQSPK), ZPQSPK)";
    let pq_opk_context = b"(PQOPK, id, Sig(IK, EncodeKEM(PQOPK), Z))";    

    // Setup the signatures for spk and pqpk
    let spk_sig  = fetched_bundle.spk_sig;
    
    
    match &fetched_bundle.pq_opk{
        // Checks if going to use the pq_opk or the last resort prekey
        Some((pk, _id, sig)) => {
            let pq_opk_sig = *sig;
            libcrux_ml_dsa_verify(&fetched_bundle.ik_dsa_pub, &pk.0, pq_opk_context, &pq_opk_sig)?;
        },
        None => {
            let pqspk_pub = fetched_bundle.pqspk_pub.as_ref().expect("Missing last resort pqkem and pq opk");
            let last_resort_sig = fetched_bundle.pqspk_sig;
            libcrux_ml_dsa_verify(&fetched_bundle.ik_dsa_pub, &pqspk_pub.0, pqspk_context, &last_resort_sig)?;
        }
    };
    
    libcrux_ml_dsa_verify(&fetched_bundle.ik_dsa_pub, &fetched_bundle.spk_pub.0, spk_context, &spk_sig)?;
    Ok(())

}

#[hax_lib::opaque]
pub(crate) fn make_initial_message_and_init_session<'a> (pqxdh_state: &PQXDHState, 
        fetched_bundle: &keys::FetchedBundle, 
        initiator_id: &(String, [u8; 1]),
        target_id: &(String, [u8; 1]),
        sessions: &mut SessionStore) -> Result<MessageType, &'a str> {
    #[cfg(not(hax))]{
        use zeroize::Zeroize;

        // Verifies the prekeys
        match verify_pre_keys(fetched_bundle){
            Ok(()) => {},
            Err(e) => return Err(e)
        }

        // Creates the salt and concatenated dh Diffie-Hellman ouputs
        let (salt, mut concat_dh_final, ek, mut ct, id_pk) = 
            initiator_create_salt_concat_dh(pqxdh_state, fetched_bundle)
                .expect("Couldn't make salt or concatted dh");

        // Returns the sk
        let sk = create_sk(salt, concat_dh_final, b"HACSS_CURVE25519_SHA256_ML-KEM-768");

        // Delete ephemeral, dh output, shared secret
        let mut ek_private_bytes: [u8; 32] = ek.private_key.0;
        ek_private_bytes.zeroize();
        concat_dh_final.zeroize();
        
        // Makes the associated data, by encoding IK both for target and self
        let mut ad =[0u8; 64];
        ad[0..32].copy_from_slice(pqxdh_state.keybundle.identity.dh.public_key.0.as_ref());
        ad[32..64].copy_from_slice(fetched_bundle.ik_dh_pub.0.as_ref());

        // Initialize the ciphertext encrypted with AEAD
        let (mut init_ct, mut init_ct_tag, init_ct_nonce) = libcrux_aead_encrypts_ad_initial_message(&sk, &ad, b"Initial for our post-PQXDH KL,AM").
                expect("Could not make the initial ciphertext for the initial message");

        let init_message = MessageType::InitialMessage {
            ik_pub: pqxdh_state.keybundle.identity.dh.public_key, 
            ek: ek.public_key, 
            pq_ct: ct, 
            pre_key_ids: id_pk, 
            init_ct: init_ct,
            init_ct_tag: init_ct_tag,
            init_ct_nonce: init_ct_nonce,
            salt: salt,
            initiator_id: initiator_id.clone(),
            ad
        };

        ct.zeroize();
        init_ct.zeroize();
        init_ct_tag.zeroize();

        // Makes initiator session 
        Session::new_initiator(target_id, keys::RootChainKey(sk), fetched_bundle.spk_pub, sessions, ad);

        Ok(init_message)
    }
    #[cfg(hax)]{
        let msg = MessageType::MakeOneTimePreKey;
        Ok(msg)  // Just a dummy message for hax
    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res|
    match res {
        Ok((salt, concat_dh, ek, ct, ids)) => 
            salt.len() == 32
            && concat_dh.len() == 160
            && ek.private_key.0.len() == 32
            && ek.public_key.0.len() == 32
            && ct.len() == 1088,
        Err(_) => true
    })]
pub fn initiator_create_salt_concat_dh(
    pqxdh_state: &PQXDHState, 
    fetched_bundle: &keys::FetchedBundle) -> 
        Result<([u8; 32], [u8; 160], 
            keys::X25519KeyPair, [u8; ML_KEM_768_CT_SIZE], 
            Vec<IDUseNameKey>), String> 
            {
    #[cfg(not(hax))]{
        use zeroize::Zeroize;
        // Identifiers stating which of Bob's prekeys Alice used
        let mut id_pk = Vec::new();

        // Initializes the ephemeral key
        let ek = gen_curve_key_pair();
        let pqpk = match &fetched_bundle.pq_opk{
            // There is a pq opk
            Some((pk, id, _sig)) => {
                // Adds the id to the list
                id_pk.push(IDUseNameKey::PQOPK { pqopk_id: id.clone() });
                pk
            },
            
            // There is a last resort pre key
            None => {
                // Adds the id to the list
                let pqspk_id = fetched_bundle.pqspk_id.clone().expect("Missing id for the pqspk of the target");
                id_pk.push(IDUseNameKey::PQSPK { pqspk_id});
                fetched_bundle.pqspk_pub.as_ref().expect("Error")
            }
        };
        
        let (ct, mut ss) = libcrux_ml_kem_768_encaps(&pqpk.0);
        
        // Adds the id to the list
        id_pk.push(IDUseNameKey::SPK { spk_id: fetched_bundle.spk_id.clone()});
        let spk_pub_target = fetched_bundle.spk_pub;
        let ik_self = pqxdh_state.keybundle.identity.dh.private_key;
        


        let mut dh1 = libcrux_ecdh_x25519_derive(spk_pub_target, ik_self)
            .expect("Could not derive dh1 from spk and ik");
        
        let ik_pub_target = fetched_bundle.ik_dh_pub;
        let ek_private_self = ek.private_key;
        let mut dh2 = libcrux_ecdh_x25519_derive(ik_pub_target, ek_private_self)
            .expect("Could not derive dh2 from ik and ek");

        let mut dh3 = libcrux_ecdh_x25519_derive(spk_pub_target, ek_private_self)
            .expect("Could not derive dh3 from spk and ek");

        // Concatenate the dh from above
        let mut concat_dh = [0u8; 160];
        concat_dh[0..32].copy_from_slice(dh1.as_ref());
        concat_dh[32..64].copy_from_slice(dh2.as_ref());
        concat_dh[64..96].copy_from_slice(dh3.as_ref());


        let concat_dh_final = match fetched_bundle.opk{
            Some((pk, id)) => {
                id_pk.push(IDUseNameKey::OPK { opk_id: id.clone() });
                let mut dh4 = libcrux_ecdh_x25519_derive(pk, ek_private_self)
                    .expect("Could not derive dh4 from opk and ek");
                concat_dh[96..128].copy_from_slice(dh4.as_ref());
                concat_dh[128..160].copy_from_slice(ss.as_ref());
                dh4.zeroize();
                concat_dh
            },
            None => {            
                concat_dh[96..128].copy_from_slice(ss.as_ref());
                concat_dh
            }
        };
        // Makes some salt
        let salt: [u8; 32] = make_randomness::<32>();

        
        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        concat_dh.zeroize();
        ss.zeroize();

        Ok((salt, concat_dh_final, ek, ct, id_pk))
    }
    #[cfg(hax)]{
        Ok(([0u8; 32], [0u8; 160], X25519KeyPair::default(), [0u8; 1088], Vec::new()))
    }
}
#[hax_lib::opaque]
pub(crate) fn handle_receive_init_message_make_session_on_success(
        sessions: &mut SessionStore,
        pqxdh_state: &mut PQXDHState,
        ik_initiator_pub: keys::X25519PublicKey, 
        ek_initiator: keys::X25519PublicKey, 
        pq_ct: [u8; keys::ML_KEM_768_CT_SIZE], 
        pre_key_ids: Vec<IDUseNameKey>, 
        mut init_ct: [u8; 32], 
        init_ct_tag: [u8; 16], 
        init_ct_nonce: [u8; 12],
        salt: [u8; 32], 
        initiator_id: (String, [u8; 1]), 
        ad: [u8; 64])
    {
    #[cfg(not(hax))]{
        use zeroize::Zeroize;
        let mut pqpk = [0u8; keys::ML_KEM_768_SK_SIZE];
        let mut opk: Option<keys::X25519PrivateKey> = None;
        let mut spk = [0u8; keys::X25519_KEY_SIZE];

        // Finding the private/secret pre keys associated with the public pre keys other pqxdh_states used for initial message
        for pre_key_id in pre_key_ids {
            match pre_key_id {
                IDUseNameKey::PQOPK {pqopk_id: id} => {
                    let temp_pqpk = pqxdh_state.keybundle.pq_opks
                        .iter()
                        .find(|pq| pq.id == id);
                    pqpk = temp_pqpk.expect("Could not find the pqopk used").key.secret_key.0;
                },
                IDUseNameKey::PQSPK {pqspk_id: id} => {
                    if pqxdh_state.keybundle.pqspk.id == id {
                        pqpk = pqxdh_state.keybundle.pqspk.key.secret_key.0;
                    }
                }
                IDUseNameKey::OPK {opk_id: id} => {
                    // Removes the opk for the user key bundle
                        let pos = pqxdh_state.keybundle.opks
                        .iter()
                        .position(|opk| opk.id == id);
                    
                    if let Some(idx) = pos {
                        let extracted = pqxdh_state.keybundle.opks.remove(idx);
                        opk = Some(extracted.key.private_key);
                    }
                },
                IDUseNameKey::SPK {spk_id: id} => {
                    if pqxdh_state.keybundle.spk.id == id {
                        spk = pqxdh_state.keybundle.spk.key.private_key.0;
                    }
                }
            }
        }

        let mut ss = libcrux_ml_kem_decapsulate(&pqpk, pq_ct);

        // Calculates the secret key with the DH steps

        // Extract the key bytes before any mutable borrow of self
        let spk_private = pqxdh_state.keybundle.spk.key.private_key;
        let spk_public  = pqxdh_state.keybundle.spk.key.public_key;
        let spk_keypair = keys::X25519KeyPair { private_key: spk_private, public_key: spk_public };
        let mut dh1 = libcrux_ecdh_x25519_derive(ik_initiator_pub, spk_private).expect("Could not derive dh1 from spk and ik");
        
        let responder_ik = pqxdh_state.keybundle.identity.dh.private_key;
        let mut dh2 = libcrux_ecdh_x25519_derive(ek_initiator, responder_ik).expect("Could not derive dh2 from ik and ek");

        
        let mut dh3 = libcrux_ecdh_x25519_derive(ek_initiator, spk_private).expect("Could not derive dh3 from spk and ek");

        // concatenate the dh from above
        let mut concat_dh = [0u8; 160];
        concat_dh[0..32].copy_from_slice(dh1.as_ref());
        concat_dh[32..64].copy_from_slice(dh2.as_ref());
        concat_dh[64..96].copy_from_slice(dh3.as_ref());


        let mut concat_dh_final = match opk{
            Some(sk) => {

                let mut dh4 = libcrux_ecdh_x25519_derive(ek_initiator, sk).expect("Could not derive dh4 from opk and ek");
                concat_dh[96..128].copy_from_slice(dh4.as_ref());
                concat_dh[128..160].copy_from_slice(ss.as_ref());
                dh4.zeroize();
                concat_dh
            },
            None => {            
                concat_dh[96..128].copy_from_slice(ss.as_ref());
                concat_dh
            }
        };

        // Returns the sk
        let sk = libcrux_gen_kdf_key(&salt, &concat_dh_final, b"HACSS_CURVE25519_SHA256_ML-KEM-768");

        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        concat_dh.zeroize();
        concat_dh_final.zeroize();
        ss.zeroize();


        let mut ad =[0u8; 64];
        ad[0..32].copy_from_slice(ik_initiator_pub.0.as_ref());
        ad[32..64].copy_from_slice(pqxdh_state.keybundle.identity.dh.public_key.0.as_ref());

        let _plaintext = libcrux_aead_decrypts_ad_initial_message(&sk, &ad, &init_ct, &init_ct_tag, &init_ct_nonce).expect("Could not decrypt");

        init_ct.zeroize();

        // If everything was succesfull, create the session between initiator and responder
        Session::new_responder(&initiator_id, keys::RootChainKey(sk), spk_keypair, sessions, ad);
    }
    #[cfg(hax)]{
        let mut session_store = SessionStore::new();
        Session::new_responder(&("hax".to_string(), [0u8; 1]), keys::RootChainKey([0u8; 32]), X25519KeyPair::default(),&mut session_store, [0u8; 64]);
    }
}


#[cfg(test)]
mod tests {
    use rand::SeedableRng;  
    use rand::rngs::StdRng;
    use crate::pqxdh::pqxdh_impl::PQXDHState;

    #[test]
    fn initialize_two_different_accounts() {
        let acc1 = PQXDHState::new();
        let acc2 = PQXDHState::new();

        // Identity key pairs differ (compare public keys)
        assert_ne!(acc1.keybundle.identity.dh.public_key, acc2.keybundle.identity.dh.public_key);

        // Identity signing key pairs differ
        assert_ne!(
            acc1.keybundle.identity.dsa.signing_key.0.as_slice(),
            acc2.keybundle.identity.dsa.signing_key.0.as_slice()
        );

        // Signed pre-key public keys differ
        assert_ne!(acc1.keybundle.spk.key.public_key, acc2.keybundle.spk.key.public_key);
        

        // Signed pre-key signatures differ
        assert_ne!(
        acc1.keybundle.spk.sig.as_ref(), acc2.keybundle.spk.sig.as_ref()
        );

        // One-time pre-key counts match
        
        assert_eq!(
        acc1.keybundle.opks.len(),
        acc2.keybundle.opks.len()
        );

        // PQ signed last resort keys differ
        assert_ne!(acc1.keybundle.pqspk.key.public_key.0,
                   acc2.keybundle.pqspk.key.public_key.0);

        // PQ one-time pre-key counts match
        
        assert_eq!(
        acc1.keybundle.pq_opks.len(),
        acc2.keybundle.pq_opks.len()
        );

        // Counters are equal (both freshly initialized)
        assert_eq!(acc1.opk_counter,
        acc2.opk_counter);

        assert_eq!(acc1.pq_opk_counter,
        acc2.pq_opk_counter);

        assert_eq!(acc1.pqspk_counter,
        acc2.pqspk_counter);

        assert_eq!(acc1.spk_counter,
        acc2.spk_counter);
        }
    #[test]
    #[ignore = "removed possibility for chosen seed for now"]
    fn equal_accounts_from_seed(){
        let seed = [0u8; 32];
        let mut rng = StdRng::from_seed(seed);
        let mut second_rng = StdRng::from_seed(seed);
        
        let acc1 = PQXDHState::new();
        let acc2 = PQXDHState::new();

        // Identity key pairs don't differ (compare public keys)
        assert_eq!(acc1.keybundle.identity.dh.public_key, acc2.keybundle.identity.dh.public_key);

        // Identity signing key pairs don't differ
        assert_eq!(
            acc1.keybundle.identity.dsa.signing_key.0.as_slice(),
            acc2.keybundle.identity.dsa.signing_key.0.as_slice()
        );

        // Signed pre-key public keys don't differ
        assert_eq!(acc1.keybundle.spk.key.public_key, acc2.keybundle.spk.key.public_key);
        

        // Signed pre-key signatures don't differ
        assert_eq!(
        acc1.keybundle.spk.sig.as_ref(), acc2.keybundle.spk.sig.as_ref()
        );

        // One-time pre-key counts match
        assert_eq!(
        acc1.keybundle.opks.len(),
        acc2.keybundle.opks.len()
        );

        // PQ signed last resort keys don't differ
        assert_eq!(acc1.keybundle.pqspk.key.public_key.0,
                acc2.keybundle.pqspk.key.public_key.0);

        // PQ one-time pre-key counts match
        
        assert_eq!(
        acc1.keybundle.pq_opks.len(),
        acc2.keybundle.pq_opks.len()
        );
    
    }

}