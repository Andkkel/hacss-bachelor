use crate::util::constants::
    {SHARED_SECRET_SIZE, PROTOCOL_INFO, ROOT_CHAIN_KEY_SIZE, CHAIN_KEY_SIZE, MESSAGE_KEY_SIZE};
use crate::util::keys::{RootChainKey, ChainKey, MessageKey};
use crate::util::{helper_func, libcrux_wrap};


#[derive(Debug, Clone, Copy)]
pub struct KdfChain{
    pub(crate) typ_chain: TypChain,
    pub(crate) kdf_key: [u8; 32],
    pub(crate) counter: u64
    /* 
    pub header_key: Option<[u8; 32]>,
    pub next_header_key: Option<[u8; 32]>
    */
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TypChain{
    Root,
    Sending,
    Receiving,
}

#[hax_lib::attributes]
impl KdfChain {
    pub fn new(typ_chain: TypChain, initial_key: [u8; 32], counter: u64) -> Self {
        if typ_chain == TypChain::Root {
            Self {
            typ_chain,
            kdf_key: initial_key,
            counter
            /* 
            header_key: None,
            next_header_key: None
            */
        }
        }
        else {
            Self {
                typ_chain,
                kdf_key: initial_key,
                counter
                /*
                header_key: Some([0u8; 32]), 
                next_header_key: Some([0u8; 32]) 
                */
            }
        }
        
    }

    /*
    We require that the kdf key is not none and has a length of 32 furthermore that there is space in the out_keys
    We ensure that the keys returned has a length of 32
    */
    #[hax_lib::requires(
        rk.0.len() == 32)]
    #[hax_lib::ensures( |res|
        res.0.0.len() == 32 &&
        res.1.0.len() == 32)]
    pub(crate) fn kdf_rk(rk: RootChainKey, dh_out: [u8;32]) -> (RootChainKey, ChainKey){ 
        // Should use rk as HKDF salt, dh_out as HKDF input key material, and an application-specific byte sequence as HKDF info.
        hax_lib::assert!(dh_out.len() == 32 && rk.0.len() == 32);
        let new_rk  = libcrux_wrap::libcrux_gen_kdf_key(&rk.0, &dh_out, b"kdf_rk");
        
        hax_lib::assert!(dh_out.len() == 32 && new_rk.len() == 32);
        let new_cks = libcrux_wrap::libcrux_gen_kdf_key(&new_rk, &dh_out, b"kdf_cks");

        (RootChainKey(new_rk), ChainKey(new_cks))
    }
    /*
    We require that the kdf key is not none and has a length of 32 furthermore that there is space in the out_keys
    We ensure that the keys returned has a length of 32
    */
    #[hax_lib::requires(
    ck.is_some() && ck.unwrap().0.len() == 32)]
    #[hax_lib::ensures( |result|
        match result {
            Ok((mk, ck)) => {
                mk.0.len() == 32
                && ck.0.len() == 32 
            },
            Err(_) => true 
        })]
    pub(crate) fn kdf_ck<'a> (ck: Option<ChainKey>) -> Result<(MessageKey, ChainKey), &'a str> {
        let ck_n = match ck{
            Some(ck) => ck.0,
            None => return Err("Chain key should not be None")
        };

        let message_key_data: [u8; 1] = *b"1";
        let chain_key_data: [u8; 1] = *b"2";

        hax_lib::assert!(ck_n.len() == 32);
        let message_key = libcrux_wrap::libcrux_hmac_sha2_256(&ck_n, &message_key_data);

        hax_lib::assert!(ck_n.len() == 32);
        let next_chain_key = libcrux_wrap::libcrux_hmac_sha2_256(&ck_n, &chain_key_data);

        Ok((MessageKey(message_key), ChainKey(next_chain_key)))

    }

    /*
    KDF initliaization used to support the implementation of Sparse Post-Quantum Ratchet
    */
    #[hax_lib::requires(ss.len() == 32)]
    #[hax_lib::ensures(|res|
        match res {
            Ok((rk, ck1, ck2)) => rk.0.len() == 32
                && ck1.0.len() == 32
                && ck2.0.len() == 32,
            Err(_) => true
        })]
    pub(crate) fn kdf_scka_init (ss: &[u8; SHARED_SECRET_SIZE]) -> Result<(RootChainKey, ChainKey, ChainKey), String> {
        let triple_kdf_key: [u8; ROOT_CHAIN_KEY_SIZE+2*CHAIN_KEY_SIZE] = libcrux_wrap::libcrux_gen_kdf_key_scka_init(&[0u8; 32], ss);
        let rk: [u8; ROOT_CHAIN_KEY_SIZE] = triple_kdf_key[..ROOT_CHAIN_KEY_SIZE].try_into().expect("Couldn't make the Root chain key");
        let ck1: [u8; CHAIN_KEY_SIZE] = triple_kdf_key[ROOT_CHAIN_KEY_SIZE..CHAIN_KEY_SIZE+ROOT_CHAIN_KEY_SIZE].try_into().expect("Couldn't make the sending Chain key");
        let ck2: [u8; CHAIN_KEY_SIZE] = triple_kdf_key[ROOT_CHAIN_KEY_SIZE+CHAIN_KEY_SIZE..].try_into().expect("Couldn't make the receiving Chain key");   

        let rk_struct = RootChainKey(rk);
        let ck1_struct = ChainKey(ck1);
        let ck2_struct = ChainKey(ck2);
        Ok((rk_struct, ck1_struct, ck2_struct))
    }

    /*
    KDF Root key chain step used to support the implementation of Sparse Post-Quantum Ratchet
    */
    #[hax_lib::requires(rk.0.len() == 32
        && key.len() == 32)]
    #[hax_lib::ensures(|res|
        match res {
            Ok((rk, ck1, ck2)) => rk.0.len() == 32
                && ck1.0.len() == 32
                && ck2.0.len() == 32,
            Err(_) => true
        })]
    pub(crate) fn kdf_scka_rk<'a> (rk: RootChainKey, key: [u8; 32]) -> Result<(RootChainKey, ChainKey, ChainKey), &'a str> {
        let triple_kdf_key: [u8; ROOT_CHAIN_KEY_SIZE+2*CHAIN_KEY_SIZE] = libcrux_wrap::libcrux_gen_kdf_key_scka_rk(&rk.0, &key);
        let rk: [u8; ROOT_CHAIN_KEY_SIZE] = triple_kdf_key[..ROOT_CHAIN_KEY_SIZE].try_into().expect("Couldn't make the Root chain key");
        let ck1: [u8; CHAIN_KEY_SIZE] = triple_kdf_key[ROOT_CHAIN_KEY_SIZE..CHAIN_KEY_SIZE+ROOT_CHAIN_KEY_SIZE].try_into().expect("Couldn't make the sending Chain key");
        let ck2: [u8; CHAIN_KEY_SIZE] = triple_kdf_key[ROOT_CHAIN_KEY_SIZE+CHAIN_KEY_SIZE..].try_into().expect("Couldn't make the receiving Chain key");   

        let rk_struct = RootChainKey(rk);
        let ck1_struct = ChainKey(ck1);
        let ck2_struct = ChainKey(ck2);

        Ok((rk_struct, ck1_struct, ck2_struct))
    }

    /*
    KDF Chain key step used to support the implementation of Sparse Post-Quantum Ratchet
    */
    #[hax_lib::opaque]
    #[hax_lib::requires(kdf_key.len() == 32
        && counter <= u64::MAX)]
    #[hax_lib::ensures(|res|
        match res {
            Ok((ck, mk)) => ck.0.len() == 32
                && mk.0.len() == 32,
            Err(_) => true
        })]
    pub(crate) fn kdf_scka_ck(kdf_key: [u8; MESSAGE_KEY_SIZE], counter: u64) -> Result<(ChainKey, MessageKey), String> {
        let info = format!("{}, {},  Chain Add Epoch", PROTOCOL_INFO, counter);
        let double_key: [u8; CHAIN_KEY_SIZE + MESSAGE_KEY_SIZE] = libcrux_wrap::libcrux_gen_kdf_key_auth(&[0u8; 32], &kdf_key, info.as_bytes());
        let ck: [u8; CHAIN_KEY_SIZE] = double_key[..CHAIN_KEY_SIZE].try_into().expect("Couldn't make the Root chain key");
        let mk: [u8; MESSAGE_KEY_SIZE] = double_key[CHAIN_KEY_SIZE..].try_into().expect("Couldn't make the sending Chain key");
        
        let ck_struct = ChainKey(ck);
        let mk_struct = MessageKey(mk);

        Ok((ck_struct, mk_struct))
    }

}

#[cfg(test)]
mod tests {
    use crate::kdf_chain::kdf::kdf_impl::make_kdf_chain_key_pair;
    use crate::kdf_chain::kdf_chain_impl::{KdfChain, TypChain};
    use crate::util::keys::{RootChainKey, ChainKey};
    use crate::util::constants::{SHARED_SECRET_SIZE, CHAIN_KEY_SIZE, ROOT_CHAIN_KEY_SIZE, MESSAGE_KEY_SIZE};


    fn seq_ss() -> [u8; SHARED_SECRET_SIZE] {
        let mut buf = [0u8; SHARED_SECRET_SIZE];
        for (i, b) in buf.iter_mut().enumerate() { *b = i as u8; }
        buf
    }
    fn zero_ss()    -> [u8; SHARED_SECRET_SIZE] { [0x00u8; SHARED_SECRET_SIZE] }
    fn ones_ss()    -> [u8; SHARED_SECRET_SIZE] { [0xFFu8; SHARED_SECRET_SIZE] }

    #[test]
        fn test_make_chain_kdf_keys_len_and_update() {
            let chain_key = [0u8; 32];
            let constant = [0x01];
            let (new_chain_key, message_key) = make_kdf_chain_key_pair(&chain_key, &constant);

            // the chain keys should be different
            assert_ne!(chain_key.to_vec(), new_chain_key.to_vec());
            // the chain key and message key should be different
            assert_ne!(message_key.to_vec(), new_chain_key.to_vec());

            // the length of the keys should be 32
            assert_eq!(new_chain_key.len(), 32);
            assert_eq!(message_key.len(), 32);
        }

    
    #[test]
        fn test_multiple_new_chain_kdf_keys_len_and_update() {
            let org_chain_key = [0u8; 32];
            let input = [0x01];
            let (chain_key_one, _message_key_one) = make_kdf_chain_key_pair(&org_chain_key, &input);
            let (chain_key_two, _message_key_two) = make_kdf_chain_key_pair(&chain_key_one, &input);
            let (chain_key_three, message_key_three) = make_kdf_chain_key_pair(&chain_key_two, &input);

            // the chain keys should be different
            assert_ne!(org_chain_key.to_vec(), chain_key_three.to_vec());
            // the chain key and message key should be different
            assert_ne!(message_key_three.to_vec(), chain_key_three.to_vec());

            // the length of the keys should be 32
            assert_eq!(chain_key_three.len(), 32);
            assert_eq!(message_key_three.len(), 32);
        }

    #[test]
        fn test_multiple_dh_input_should_output_different_keys() {
            let org_chain_key = [0u8; 32];
            let input_one = [0x01];
            let input_two = [0x02];
            let (chain_key_one, message_key_one) = make_kdf_chain_key_pair(&org_chain_key, &input_one);
            let (chain_key_two, message_key_two) = make_kdf_chain_key_pair(&org_chain_key, &input_two);

            // the chain keys should be different
            assert_ne!(chain_key_one.to_vec(), chain_key_two.to_vec());
            assert_ne!(message_key_one.to_vec(), message_key_two.to_vec());
        }

    #[test]
    fn test_kdf_is_deterministic() {
        let chain_key = [0u8; 32];
        let input = [0x01];
        let (ck1, mk1) = make_kdf_chain_key_pair(&chain_key, &input);
        let (ck2, mk2) = make_kdf_chain_key_pair(&chain_key, &input);
        assert_eq!(ck1, ck2);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn test_message_keys_unique_across_rounds() {
        let chain_key = [0u8; 32];
        let input = [0x01];
        let (ck1, mk1) = make_kdf_chain_key_pair(&chain_key, &input);
        let (ck2, mk2) = make_kdf_chain_key_pair(&ck1, &input);
        let (_ck3, mk3) = make_kdf_chain_key_pair(&ck2, &input);

        // all message keys should be unique
        assert_ne!(mk1, mk2);
        assert_ne!(mk2, mk3);
        assert_ne!(mk1, mk3);
    }

    #[test]
    fn test_keys_not_zero() {
        let chain_key = [0u8; 32];
        let input = [0x01];
        let (new_chain_key, message_key) = make_kdf_chain_key_pair(&chain_key, &input);
        assert_ne!(new_chain_key, [0u8; 32]);
        assert_ne!(message_key, [0u8; 32]);
    }


    #[test]
    fn test_kdf_root_chain(){
        let chain: KdfChain = KdfChain::new(TypChain::Root, [0u8; 32], 0);      
        // checks
        assert_eq!(chain.typ_chain, TypChain::Root);
        assert_eq!(chain.kdf_key, [0u8; 32]);
        // assert_eq!(chain.output_keys, Vec::<[u8;32]>::new());
    }

    #[test]
    fn test_kdf_send_chain(){
        let chain: KdfChain = KdfChain::new(TypChain::Sending, [0u8; 32], 0);      
        // checks
        assert_eq!(chain.typ_chain, TypChain::Sending);
        assert_eq!(chain.kdf_key, [0u8; 32]);
        // assert_eq!(chain.output_keys, Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_kdf_receive_chain(){
        let chain: KdfChain = KdfChain::new(TypChain::Receiving, [0u8; 32], 0);      
        // checks
        assert_eq!(chain.typ_chain, TypChain::Receiving);
        assert_eq!(chain.kdf_key, [0u8; 32]);
        // assert_eq!(chain.output_keys, Vec::<[u8; 32]>::new());
    }

    #[test]
    fn test_root_ratchet_makes_new_keys() {
        let chain = KdfChain::new(TypChain::Root, [0u8; 32], 0);

        // Save initial state for comparison
        let initial_kdf_key = chain.kdf_key.clone();
        // let initial_output_len = chain.output_keys.len();

        // Ratchet step
        let input = [01u8; 32];
        
        // We scope the references or clone them to satisfy the borrow checker
        let (new_kdf_ref, _new_output_ref) = KdfChain::kdf_rk(RootChainKey(chain.kdf_key), input);

        // Assertions
        assert_ne!(initial_kdf_key, new_kdf_ref.0, "KDF key should have changed");
        //assert_eq!(initial_output_len + 1, chain.output_keys.len(), "Output keys should have grown");
        //assert_eq!(output_key_copy, *chain.output_keys.last().unwrap(), "Returned key should match the last entry");
    }

    #[test]
    fn test_send_receive_ratchet_makes_new_keys() {
        let chain = KdfChain::new(TypChain::Sending, [0u8; 32], 0);

        // Save initial state for comparison
        let initial_kdf_key = chain.kdf_key.clone();
        //let initial_output_len = chain.output_keys.len();
        
        // We scope the references or clone them to satisfy the borrow checker
        let (new_kdf_ref, _new_output_ref) = KdfChain::kdf_ck(Some(ChainKey(initial_kdf_key)))
            .expect("Should be able to do kdf_ck");

        // Assertions
        assert_ne!(initial_kdf_key, new_kdf_ref.0, "KDF key should have changed");
        //assert_eq!(initial_output_len + 1, chain.output_keys.len(), "Output keys should have grown");
        //assert_eq!(output_key_copy, *chain.output_keys.last().unwrap(), "Returned key should match the last entry");
    }

    #[test]
    fn root_chain_to_sending(){
        let root_chain = KdfChain::new(TypChain::Root, [0u8; 32], 0);

        // Make the root chain ratchet step
        let input = [0x01; 32];
        
        // We scope the references or clone them to satisfy the borrow checker
        let (new_root_kdf_ref, new_root_output_ref) = KdfChain::kdf_rk(RootChainKey(root_chain.kdf_key), input);

        // Take output key from root chain ratchet to make 
        let send_chain = KdfChain::new(TypChain::Sending, new_root_output_ref.0, 0);

        // Make sending chain ratchet step
        let (new_send_kdf_ref, _new_send_output_ref) = KdfChain::kdf_ck(Some(ChainKey(send_chain.kdf_key)))
            .expect("Should be able to do the kdf_ck");

        // Assertions 
        assert_ne!(new_send_kdf_ref.0, new_root_kdf_ref.0, "KDF key should have changed from root output to new sending KDF key");
    }

    #[test]
    #[should_panic(expected = "Chain key should not be None")]
    fn kdf_ck_doesnt_work_initiator(){
        let (_mk, _ck) = KdfChain::kdf_ck(None).expect("Chain key should not be None");
    }

    #[test]
    fn kdf_scka_rk_different_rk_different_output() {
        let (out1, _, _) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).unwrap();
        let (out2, _, _) = KdfChain::kdf_scka_rk(RootChainKey([1u8; 32]), [1u8; 32]).unwrap();
        assert_ne!(out1.0, out2.0);
    }

    #[test]
    fn kdf_scka_rk_different_key_different_output() {
        let (_, c1a, _) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [0u8; 32]).unwrap();
        let (_, c1b, _) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).unwrap();
        assert_ne!(c1a.0, c1b.0);
    }

    #[test]
    fn kdf_scka_rk_output_differs_from_init() {
        // Domain separation: same key material through different KDF calls must differ
        let (rk_init, ck1_init, _) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        let key = [0x42u8; 32];
        let (_rk_rk, ck1_rk, _) = KdfChain::kdf_scka_rk(rk_init, key).unwrap();
        assert_ne!(ck1_init.0, ck1_rk.0,
            "kdf_scka_init and kdf_scka_rk must be domain-separated");
    }


    #[test]
    fn kdf_scka_ck_returns_ok() {
        assert!(KdfChain::kdf_scka_ck([0u8; 32], 0).is_ok());
    }

    #[test]
    fn kdf_scka_ck_output_lengths() {
        let (ck, mk) = KdfChain::kdf_scka_ck([0u8; 32], 0).unwrap();
        assert_eq!(ck.0.len(), CHAIN_KEY_SIZE);
        assert_eq!(mk.0.len(), MESSAGE_KEY_SIZE);
    }

    #[test]
    fn kdf_scka_ck_chain_key_and_message_key_distinct() {
        // Spec: two different outputs from the same HKDF call must differ
        let (ck, mk) = KdfChain::kdf_scka_ck([0u8; 32], 0).unwrap();
        assert_ne!(ck.0, mk.0);
    }

    #[test]
    fn kdf_scka_ck_deterministic() {
        let (ck1, mk1) = KdfChain::kdf_scka_ck([7u8; 32], 3).unwrap();
        let (ck2, mk2) = KdfChain::kdf_scka_ck([7u8; 32], 3).unwrap();
        assert_eq!(ck1.0, ck2.0);
        assert_eq!(mk1.0, mk2.0);
    }

    #[test]
    fn kdf_scka_ck_counter_advances_both_outputs() {
        // spec: ctr is mixed into info, so every increment produces new keys
        let (ck0, mk0) = KdfChain::kdf_scka_ck([0u8; 32], 0).unwrap();
        let (ck1, mk1) = KdfChain::kdf_scka_ck([0u8; 32], 1).unwrap();
        assert_ne!(ck0.0, ck1.0, "chain key must change with counter");
        assert_ne!(mk0.0, mk1.0, "message key must change with counter");
    }

    #[test]
    fn kdf_scka_ck_different_ck_different_output() {
        let (ck_a, mk_a) = KdfChain::kdf_scka_ck([0u8; 32], 0).unwrap();
        let (ck_b, mk_b) = KdfChain::kdf_scka_ck([1u8; 32], 0).unwrap();
        assert_ne!(ck_a.0, ck_b.0);
        assert_ne!(mk_a.0, mk_b.0);
    }

    #[test]
    fn kdf_scka_ck_non_zero_output_for_zero_input() {
        let (ck, mk) = KdfChain::kdf_scka_ck([0u8; 32], 0).unwrap();
        assert_ne!(ck.0, [0u8; CHAIN_KEY_SIZE]);
        assert_ne!(mk.0, [0u8; MESSAGE_KEY_SIZE]);
    }

    #[test]
    fn kdf_scka_ck_chain_evolves_correctly_over_three_steps() {
        // Simulate: CK_0 → (CK_1, MK_1) → (CK_2, MK_2) → (CK_3, MK_3)
        let seed = [0x11u8; 32];
        // All message keys must be distinct (forward secrecy property)
        let (ck1, mk1) = KdfChain::kdf_scka_ck(seed, 1).unwrap();
        let (ck2, mk2) = KdfChain::kdf_scka_ck(ck1.0, 2).unwrap();
        let (ck3, mk3) = KdfChain::kdf_scka_ck(ck2.0, 3).unwrap();

        assert_ne!(mk1.0, mk2.0, "mk1 must differ from mk2");
        assert_ne!(mk2.0, mk3.0, "mk2 must differ from mk3");
        assert_ne!(mk1.0, mk3.0, "mk1 must differ from mk3");
        assert_ne!(ck1.0, ck2.0, "ck1 must differ from ck2");
        assert_ne!(ck2.0, ck3.0, "ck2 must differ from ck3");
    }

    #[test]
    fn kdf_scka_init_non_zero_outputs() {
        let (rk, ck1, ck2) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        assert_ne!(rk.0,  [0u8; ROOT_CHAIN_KEY_SIZE], "rk must not be all-zero");
        assert_ne!(ck1.0, [0u8; CHAIN_KEY_SIZE],      "ck1 must not be all-zero");
        assert_ne!(ck2.0, [0u8; CHAIN_KEY_SIZE],      "ck2 must not be all-zero");
    }

    #[test]
    fn kdf_scka_init_deterministic() {
        let (rk1, ck1a, ck2a) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        let (rk2, ck1b, ck2b) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        assert_eq!(rk1.0, rk2.0);
        assert_eq!(ck1a.0, ck1b.0);
        assert_eq!(ck2a.0, ck2b.0);
    }

    #[test]
    fn kdf_scka_init_different_ss_different_output() {
        let (rk1, ck1a, _) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        let (rk2, ck1b, _) = KdfChain::kdf_scka_init(&ones_ss()).unwrap();
        assert_ne!(rk1.0, rk2.0);
        assert_ne!(ck1a.0, ck1b.0);
    }

    #[test]
    fn kdf_scka_init_zero_ss_does_not_panic() {
        // Edge: all-zero SS is cryptographically weak but must not crash
        let _ = KdfChain::kdf_scka_init(&zero_ss()).unwrap();
    }


    #[test]
    fn kdf_scka_rk_returns_ok() {
        assert!(KdfChain::kdf_scka_rk(RootChainKey([1u8; 32]), [2u8; 32]).is_ok());
    }

    #[test]
    fn kdf_scka_rk_three_distinct_outputs() {
        let (rk, ck1, ck2) = KdfChain::kdf_scka_rk(RootChainKey([1u8; 32]), [2u8; 32]).unwrap();
        assert_ne!(rk.0, ck1.0);
        assert_ne!(rk.0, ck2.0);
        assert_ne!(ck1.0, ck2.0);
    }

    #[test]
    fn kdf_scka_rk_deterministic() {
        let (rk1, c1a, c2a) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).unwrap();
        let (rk2, c1b, c2b) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).unwrap();
        assert_eq!(rk1.0, rk2.0);
        assert_eq!(c1a.0, c1b.0);
        assert_eq!(c2a.0, c2b.0);
    }

    #[test]
    fn kdf_scka_init_returns_ok() {
        assert!(KdfChain::kdf_scka_init(&seq_ss()).is_ok());
    }

    #[test]
    fn kdf_scka_init_output_lengths() {
        // Spec: 96 bytes total → 32 rk + 32 ck1 + 32 ck2
        let (rk, ck1, ck2) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        assert_eq!(rk.0.len(),  ROOT_CHAIN_KEY_SIZE);
        assert_eq!(ck1.0.len(), CHAIN_KEY_SIZE);
        assert_eq!(ck2.0.len(), CHAIN_KEY_SIZE);
    }

    #[test]
    fn kdf_scka_init_all_three_outputs_distinct() {
        // rk, ck1, ck2 must never alias each other
        let (rk, ck1, ck2) = KdfChain::kdf_scka_init(&seq_ss()).unwrap();
        assert_ne!(rk.0, ck1.0, "rk must not equal ck1");
        assert_ne!(rk.0, ck2.0, "rk must not equal ck2");
        assert_ne!(ck1.0, ck2.0, "ck1 must not equal ck2");
    }

    #[test]
    fn should_create_different_keys_kdf_scka_ck() {
        let (ck, mk) = KdfChain::kdf_scka_ck([0u8; 32], 0).expect("Could create chain and message key");
        let (ck_new, mk_new) = KdfChain::kdf_scka_ck([0u8; 32], 1).expect("Could create chain and message key");
        assert_ne!(ck.0, ck_new.0, "The chain keys should be different, when incrementing the counter");
        assert_ne!(mk.0, mk_new.0, "The chain keys should be different, when incrementing the counter");
    }

    #[test]
    fn should_produce_same_keys_kdf_scka_rk() {
        let (rk, ck1, ck2) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).expect("Could create chain and message key");
        let (rk_new, ck1_new, ck2_new) = KdfChain::kdf_scka_rk(RootChainKey([0u8; 32]), [1u8; 32]).expect("Could create chain and message key");
        
        assert_eq!(rk.0, rk_new.0, "The root keys should be the same");
        assert_eq!(ck1.0, ck1_new.0, "The chain keys should be the same");
        assert_eq!(ck2.0, ck2_new.0, "The chain keys should be the same");
    }

}