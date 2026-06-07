use crate::{double_ratchet::ratchet_state::StateDHRatchet, kdf_chain::kdf_chain_impl::KdfChain, pqxdh::pqxdh_impl, util::{constants::{NONCE_SIZE, TAG_SIZE}, keys::MessageKey, libcrux_wrap::{libcrux_aead_decrypts_ad, libcrux_aead_encrypts_ad}}};
use crate::util::messages::ECHeader;

pub(crate) const MAX_SKIP: u64 = 50;


#[hax_lib::requires(
    state.cks.is_some() 
    && state.ns < u64::MAX)]
#[hax_lib::ensures(|result| result.is_ok())]
pub(crate) fn ratchet_send_key<'a> (state: &mut StateDHRatchet) -> Result<(MessageKey, u64), &'a str> {
    
    hax_lib::assume!(state.cks.is_some());
    let cks = match state.cks{
        Some(cks) => cks,
        None => return Err("Couldn't find the chain key sender")
    };
    
    let (message_key, new_chain_key) = match KdfChain::kdf_ck(Some(cks)){
        Ok(tuple) => tuple,
        Err(_) => return Err("kdf_ck. should be able to make next chain key and message key")
    };

    state.set_cks(Some(new_chain_key));

    let old_ns = state.ns;

    hax_lib::assert!(state.ns <= u64::MAX-1);
    state.add_ns(); 

    Ok((message_key, old_ns))
}


// Ratchet encrypt used for Double Ratchet - depricated because no use for Triple ratchet
#[hax_lib::opaque]
pub fn ratchet_encrypt (ratchet_state: &mut StateDHRatchet, plaintext: &[u8], ad: &[u8; 64]) -> (ECHeader, Vec<u8>, [u8; TAG_SIZE], [u8; NONCE_SIZE]) {
    let (message_key, ns) = ratchet_send_key(ratchet_state)
        .expect("Tried to create the keys associated with sending a message");

    let header = ECHeader::header(Some(ratchet_state.dhs), ratchet_state.pn, ns)
        .expect("Tried to make the header for ratchet encrypt");

    let concatination: [u8; 116] = header.concat_with_ad(ad);

    let (ct, tag, nonce) = libcrux_aead_encrypts_ad(&message_key.0, &concatination, plaintext)
        .expect("Something is wrong");
    hax_lib::assert!(tag.len() == 16 && nonce.len() == 12);

    (header, ct, tag, nonce)
} 

#[hax_lib::opaque]  // Cannot reason about this function
#[hax_lib::requires(
    state.nr < u64::MAX 
    && state.nr <= (header.n as u64) 
    && state.nr < u64::MAX - MAX_SKIP 
    && header.pn <= u64::MAX
    && header.n <= u64::MAX
    && state.ckr.is_some()
    && state.nr <= header.pn)]
#[hax_lib::ensures(|res| res.0.len() == 32)]
pub(crate) fn ratchet_receive_key(state: &mut StateDHRatchet, header: &ECHeader) -> MessageKey {
    let old_state_nr = state.nr;
    let mk = try_skipped_message_keys(state, &header);
    hax_lib::assume!(old_state_nr == state.nr); // try_skipped_message_keys doesn't change the state.nr

    match mk {
        Some(mk) => {
            let res = mk;
            hax_lib::assume!(res.0.len() == 32); // Messages keys are always 32 byte array 
            return res
        },
        None => {}        
    }

    match state.dhr {
        Some(dhr) => {
            if header.dh_pub != dhr {
                hax_lib::assert!(header.pn <= u64::MAX && state.nr < u64::MAX - MAX_SKIP && state.nr <= header.pn);
                let _ = skip_message_keys(state, &(header.pn as u64));
                let _ = dh_ratchet(state, &header);
            }
        }
        None => {   
            hax_lib::assert!(header.pn <= u64::MAX && state.nr < u64::MAX - MAX_SKIP && state.nr <= header.pn);
            let _ = skip_message_keys(state, &(header.pn as u64));
            let _ = dh_ratchet(state, &header);
        }
    }

    hax_lib::assert!(header.n <= u64::MAX && state.nr < u64::MAX - MAX_SKIP && state.nr <= header.n);
    let _ = skip_message_keys(state, &(header.n as u64));

    hax_lib::assume!(state.ckr.is_some());  // Because required
    hax_lib::assume!(state.ckr.unwrap().0.len() == 32); // Chain keys are always 32 bytes
    let (mk, ck) = KdfChain::kdf_ck(state.ckr).expect("Could not make the new message key and chain key");
    hax_lib::assert!(mk.0.len() == 32); // Follows from kdf_ck ensures
    
    state.ckr = Some(ck);

    hax_lib::assert!(state.nr <= u64::MAX - 1);
    state.nr += 1;
    
    let res = mk;
    hax_lib::assume!(res.0.len() == 32); // If ckr.is_some(), then there will always be created a message key
    res
}

// Ratchet decrypt for Double Ratchet - depricated because no for Triple Ratchet
#[hax_lib::opaque] 
#[hax_lib::ensures(|res|
    match res {
        Ok(pt) => ciphertext.len() == pt.len(),
        Err(_) => true
    })]
pub fn ratchet_decrypt<'a> (state: &mut StateDHRatchet, header: &ECHeader, ciphertext: &[u8], ad: &[u8; 64], tag: [u8; TAG_SIZE], nonce: [u8; NONCE_SIZE]) -> Result<Vec<u8>, &'a str> {
    let mk = ratchet_receive_key(state, header);

    let concat = header.concat_with_ad(ad);

    let plaintext_vec = match libcrux_aead_decrypts_ad(&mk.0, &concat, ciphertext, &tag, &nonce){
        Ok(plt) => plt,
        Err(e) => return Err(e)
    };
    hax_lib::assume!(plaintext_vec.len() == ciphertext.len());  // Because ensure from libcrux decrypt call
    
    Ok(plaintext_vec)
}

#[hax_lib::opaque]  // No support for HashMap.remove
#[hax_lib::ensures(|res|
    match res {
        Some(mk) => mk.0.len() == 32,
        None => true
    })]
fn try_skipped_message_keys(state: &mut StateDHRatchet, header: &ECHeader) -> Option<MessageKey>{
    let key = (header.dh_pub, header.n);
    
    match state.mk_skipped.remove(&key){
        Some(mk) => return Some(mk),
        None => return None
    }

}

#[hax_lib::opaque]  // This function is difficult to reason with because of states and while loop
#[hax_lib::requires(*until <= u64::MAX
    && state.nr < u64::MAX - MAX_SKIP
    && state.nr <= *until
    && state.ckr.is_some()
    && state.dhr.is_some()
    && state.ckr.unwrap().0.len() == 32)]
#[hax_lib::ensures(|res| true)]
fn skip_message_keys<'a>(state: &mut StateDHRatchet, until: &u64) -> Result<(), &'a str>{
    let until_val: u64 = *until;
    hax_lib::assert!(until_val == *until);
    if state.nr + MAX_SKIP < until_val{
        return Err("Too many messages lost")
    }
    
    match state.ckr{
        Some(_chain_key) =>{
            

            let mut state_nr = state.nr; // For not to reason about state being changed in the functions for nr

            
            while state_nr < until_val {
                hax_lib::loop_invariant!(state_nr < u64::MAX
                        && until_val < u64::MAX
                        && state_nr <= until_val);
                hax_lib::loop_decreases!((until_val - state_nr) as usize);  // fstar cannot reason this loop_decreases. Even though it's right
                
                hax_lib::assume!(state.ckr.is_some());  // Assume because requires
                let kdf_ck_step = KdfChain::kdf_ck(state.ckr);

                hax_lib::assert!(kdf_ck_step.is_ok());
                let (mk, state_ckr) = match kdf_ck_step {
                    Ok((mk, sckr)) => (mk, sckr),
                    Err(_) => return Err("Couldn't find the ckr in the map")
                };
                state.ckr = Some(state_ckr);

                hax_lib::assume!(state.dhr.is_some());  // Assume because requires
                let state_dhr = match state.dhr {
                    Some(sdhr) => sdhr,
                    None => return Err("Could not find the public key for the chain key")
                };

                match state.mk_skipped.get(&(state_dhr, state_nr)){
                    Some(_mk) => {},
                    None => {let _ = state.mk_skipped.insert((state_dhr, state_nr), mk);}
                }

                hax_lib::assume!(state_nr < until_val);  // From loop guard + invariant
                hax_lib::assert!(until_val < u64::MAX);  // From invariant
                hax_lib::assert!(state_nr < u64::MAX);   // Therefore safe to increment

                state_nr += 1;
            }
            state.nr = state_nr;
            
            hax_lib::assume!(state.nr == until_val); // Out of loop 
        }
        None => return Err("The receiving chain key is None")
    }
    Ok(())
}


// Makes the new ratchet for the step
#[hax_lib::fstar::options("--z3rlimit 200")]
#[hax_lib::requires(state.dhr.is_some())]
pub(crate) fn dh_ratchet<'a> (state: &mut StateDHRatchet, header: &ECHeader) -> Result<(), &'a str>{    
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.dhr = Some(header.dh_pub);

    hax_lib::assume!(state.dhr.is_some());
    let state_dhr = state.dhr.expect("There is no dh ratchet public key received");
    
    hax_lib::assert!(state.dhr.unwrap().0.len() == 32 && state.dhs.private_key.0.len() == 32);
    let dh_out = state.make_dh_out(state_dhr)?;

    let (new_rk, new_ckr) = KdfChain::kdf_rk(*state.get_rk(), dh_out);
    state.rk = new_rk;
    state.ckr = Some(new_ckr);

    // Generate DH
    state.dhs = pqxdh_impl::gen_curve_key_pair();

    // Generate another 
    hax_lib::assert!(state.dhr.unwrap().0.len() == 32 && state.dhs.private_key.0.len() == 32);
    let dh_out = state.make_dh_out(state_dhr)?; 

    // Updates the rootkey and sending chain key
    let (newest_rk, new_cks)  = KdfChain::kdf_rk(*state.get_rk(), dh_out);
    state.rk = newest_rk;
    state.cks = Some(new_cks);  

    Ok(())
}

#[cfg(test)]
mod test_messages_ratchet {
    use crate::double_ratchet::messages_ratchet::{ratchet_decrypt, ratchet_encrypt};
    use crate::double_ratchet::ratchet_state::StateDHRatchet;
    use crate::pqxdh::pqxdh_impl::gen_curve_key_pair;
    use crate::util::keys::{RootChainKey, X25519KeyPair};
    use crate::util::helper_func;

    
    #[test]
    fn encrypt_decrypt() {
        let sk = RootChainKey(helper_func::make_randomness::<32>());
        let bob_dhs = gen_curve_key_pair();
        let bob_key_pair = X25519KeyPair {
            private_key: bob_dhs.private_key,
            public_key: bob_dhs.public_key,
        };
        let ad = helper_func::make_randomness::<64>();
        let plaintext = b"hello";

        let mut alice = StateDHRatchet::init_initiator(sk, bob_key_pair.public_key).unwrap();
        let mut bob = StateDHRatchet::init_responder(sk, bob_key_pair);

        let (a_header, a_ct, a_tag, a_nonce) = ratchet_encrypt(&mut alice, plaintext, &ad);
        let res = ratchet_decrypt(&mut bob, &a_header, &a_ct, &ad, a_tag, a_nonce).unwrap();
        
        
        
        assert_eq!(res, plaintext);
    }

}


