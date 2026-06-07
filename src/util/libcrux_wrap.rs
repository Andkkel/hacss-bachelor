use crate::util::constants::*;
use crate::util::keys;

/*
Translates the signing key pair to byte format
*/
#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.0.len() == 4032
    && res.1.len() == 1952)]
pub fn libcrux_ml_dsa_generate_key_pair() -> ([u8; 4032], [u8; 1952]) {
    #[cfg(not(hax))]{
    use crate::util::helper_func::make_randomness;

    let randomness = make_randomness::<32>();
    let signing_key_pair = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(randomness);        
    let signing_key = *signing_key_pair.signing_key.as_ref();
    let verification_key = *signing_key_pair.verification_key.as_ref();
    (signing_key, verification_key)
    }
    #[cfg(hax)]{
        let dummy_sk_bytes = [0u8; 4032];
        let dummy_vk_bytes = [0u8; 1952];
        
        (dummy_sk_bytes, dummy_vk_bytes)
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(signing_key.0.len() == 4032)]
#[hax_lib::ensures(|res| res.len() == 3309)]
pub fn libcrux_ml_dsa_sign(signing_key: &keys::MLDSA65SigningKey, key_to_sign: &[u8], zero_context: &[u8]) -> [u8; 3309]{
    #[cfg(not(hax))]{
    use crate::util::helper_func::make_randomness;

    let randomness = make_randomness::<32>();
    let libcrux_signing_key = libcrux_ml_dsa::MLDSASigningKey::new(signing_key.0);
    let spk_signature = libcrux_ml_dsa::ml_dsa_65::sign(&libcrux_signing_key, key_to_sign, &zero_context, randomness).unwrap();    
    let mut spk_signature_byte = [0u8; 3309];
    spk_signature_byte.copy_from_slice(spk_signature.as_ref());
    spk_signature_byte 
    }
    #[cfg(hax)]{
        [0u8; 3309] // dummy body for hax
    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.0.len() == 2400
    && res.1.len() == 1184)]
pub fn libcrux_ml_kem_generate_key_pair() -> ([u8; keys::ML_KEM_768_SK_SIZE], [u8; keys::ML_KEM_768_PK_SIZE]){
    #[cfg(not(hax))]{
    use crate::util::helper_func::make_randomness;

    let pq_randomness = make_randomness::<64>();
    let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(pq_randomness);
    let mut public_key_bytes = [0u8; keys::ML_KEM_768_PK_SIZE];
    public_key_bytes.copy_from_slice(key_pair.pk());

    let mut private_key_bytes = [0u8; keys::ML_KEM_768_SK_SIZE];
    private_key_bytes.copy_from_slice(key_pair.sk());

    (private_key_bytes, public_key_bytes)
}
    #[cfg(hax)]{
        ([0u8; keys::ML_KEM_768_SK_SIZE], [0u8; keys::ML_KEM_768_PK_SIZE])
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(verification_key.0.len() == 1952
    && signature.len() == 3309)]
pub fn libcrux_ml_dsa_verify<'a> (verification_key: &keys::MLDSA65VerificationKey, message: &[u8], context: &[u8], signature: &[u8; 3309]) -> Result<(), &'a str>{
    #[cfg(not(hax))]{
        let lib_sig  = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(*signature);
        let lib_ver_key = libcrux_ml_dsa::MLDSAVerificationKey::new(verification_key.0);
        // Verifies the signature with libcrux
        let res = libcrux_ml_dsa::ml_dsa_65::verify(&lib_ver_key, message, context, &lib_sig);
        match res {
            Ok(()) => Ok(()),
            Err(_) => Err("Could not verify the signature")
        }
        }
    #[cfg(hax)]{
        Ok(())
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(public_key.len() == 1184)]
#[hax_lib::ensures(|res| res.0.len() == 1088
    && res.1.len() == 32)]
pub fn libcrux_ml_kem_768_encaps(public_key: &[u8; keys::ML_KEM_768_PK_SIZE]) -> ([u8; keys::ML_KEM_768_CT_SIZE], [u8; 32]){
    #[cfg(not(hax))]{
        use libcrux_ml_kem::mlkem768::MlKem768PublicKey;
        use crate::util::helper_func::make_randomness;

        let randomness = make_randomness::<32>();

        let lib_pqpk = MlKem768PublicKey::from(public_key);
        let (lib_ct, lib_ss) = libcrux_ml_kem::mlkem768::encapsulate(&lib_pqpk, randomness);
        
        // Translates to bytes and slices to make it compatible
        let mut ct_bytes = [0u8; keys::ML_KEM_768_CT_SIZE];
        let lib_cit_slice = lib_ct.as_slice();
        ct_bytes.copy_from_slice(lib_cit_slice);
        (ct_bytes, lib_ss)
        
    }
    #[cfg(hax)]{
        // Dummy to make hax compile
        ([0u8; keys::ML_KEM_768_CT_SIZE], [0u8; 32])   
    }
}
#[hax_lib::opaque]
#[hax_lib::requires(public_key.0.len() == 32 && secret_key.0.len() == 32)]
#[hax_lib::ensures(|res|
    matches!(res, Ok(ss) if ss.len() == 32))]
pub fn libcrux_ecdh_x25519_derive<'a>(public_key: keys::X25519PublicKey, secret_key: keys::X25519PrivateKey) -> Result<[u8;32], &'a str>{
    #[cfg(not(hax))]{
        let lib_pk = libcrux_ecdh::X25519PublicKey::from(&public_key.0);
        let lib_sk = libcrux_ecdh::X25519PrivateKey::from(&secret_key.0);
        let ss = libcrux_ecdh::x25519_derive(&lib_pk, &lib_sk).expect("Could not derive dh from Public key and Private key");
        Ok(ss.0)
    }
    #[cfg(hax)]{
        Ok([0u8; 32])
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(
        private_key.len() == keys::ML_KEM_768_SK_SIZE
        && ciphertext.len() == keys::ML_KEM_768_CT_SIZE)]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_ml_kem_decapsulate(private_key: &[u8; keys::ML_KEM_768_SK_SIZE], ciphertext: [u8; keys::ML_KEM_768_CT_SIZE]) -> [u8; 32] {
    #[cfg(not(hax))]{
        let lib_pqsk = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(private_key);
        let lib_ct = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(ciphertext);
        
        let ss = libcrux_ml_kem::mlkem768::decapsulate(&lib_pqsk, &lib_ct);
        ss
    }
    #[cfg(hax)]{
        [0u8; 32]
    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| 
    match res {
        Ok((ct, tag, nonce)) => ct.len() == plaintext.len()
            && tag.len() == 16 
            && nonce.len() == 12,
        Err(_) => true
    })]
pub fn libcrux_aead_encrypts_ad(sk: &[u8;32], ad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16], [u8; NONCE_SIZE]), String>{
    #[cfg(not(hax))]{
        use libcrux_aead::chacha20poly1305::*;
        use crate::util::helper_func::make_randomness;


        let key_bytes = *sk;
        let tag_bytes = [0u8; TAG_LEN];
        let nonce_bytes = make_randomness::<NONCE_SIZE>(); 
        let mut ciphertext = vec![0u8; plaintext.len()]; 
        let mut tag = Tag::from(tag_bytes);


        let key = Key::from(key_bytes);
        let nonce = Nonce::from(nonce_bytes);    

        key.encrypt(&mut ciphertext, &mut tag, &nonce, ad, plaintext)
            .expect("Encryption error");
        
        let tag_ref = tag.as_ref();

        Ok((ciphertext, *tag_ref, nonce_bytes))
    }
    #[cfg(hax)]{
        Ok((Vec::new(),[0u8;16], [0u8; 12]))
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(sk.len() == 32
    && ad.len() == 64
    && plaintext.len() == 32)]
#[hax_lib::ensures(|res|
    match res{
        Ok((hash, tag, nonce)) => hash.len() == 32
            && tag.len() == 16
            && nonce.len() == 12,
        Err(_) => true
    })]
pub fn libcrux_aead_encrypts_ad_initial_message (sk: &[u8;32], ad: &[u8;64], plaintext: &[u8; 32]) -> Result<([u8;32], [u8; 16], [u8; NONCE_SIZE]), String>{
    #[cfg(not(hax))]{
        use libcrux_aead::chacha20poly1305::*;
        use crate::util::helper_func::make_randomness;

        let key_bytes = *sk;
        let tag_bytes = [0u8; TAG_LEN];
        let nonce_bytes = make_randomness::<NONCE_SIZE>(); 
        let mut ciphertext = [0u8; 32]; 
        let mut tag = Tag::from(tag_bytes);


        let key = Key::from(key_bytes);
        let nonce = Nonce::from(nonce_bytes);

        key.encrypt(&mut ciphertext, &mut tag, &nonce, ad, plaintext)
            .expect("Encryption error");
        let tag_ref = tag.as_ref();
        Ok((ciphertext, *tag_ref, nonce_bytes))
    }
    #[cfg(hax)]{
        Ok(([0u8; 32], [0u8;16], [0u8;12]))
    }
}



#[hax_lib::opaque]
#[hax_lib::requires(sk.len() == 32
    && tag.len() == 16
    && nonce.len() == 12)]
#[hax_lib::ensures(|res|
    match res {
        Ok(init) => init.len() == 32,
        Err(_) => true
    })]
pub fn libcrux_aead_decrypts_ad_initial_message(sk: &[u8;32], ad: &[u8], ciphertext: &[u8], tag: &[u8;16], nonce: &[u8; NONCE_SIZE]) -> Result<[u8; 32], String>{
    #[cfg(not(hax))]{
        use libcrux_aead::chacha20poly1305::*;

        let key_bytes = *sk;
        let mut plaintext = [0u8; 32];

        let key = Key::from(key_bytes);

        let tag = Tag::from(*tag);
        
        let nonce = Nonce::from(*nonce);

        key.decrypt(&mut plaintext, &nonce,  ad, &ciphertext, &tag)
            .expect("Decryption error");

        Ok(plaintext)
    }
    #[cfg(hax)]{
        Ok([0u8; 32])
    }

}

#[hax_lib::opaque]
#[hax_lib::requires(sk.len() == 32
    && tag.len() == 16
    && nonce.len() == 12)]
#[hax_lib::ensures(|res|
    match res {
        Ok(pt) => pt.len() == ciphertext.len(),
        Err(_) => true
    })]
pub fn libcrux_aead_decrypts_ad<'a> (sk: &[u8;32], ad: &[u8], ciphertext: &[u8], tag: &[u8; TAG_SIZE], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, &'a str>{
    #[cfg(not(hax))]{
        use libcrux_aead::chacha20poly1305::*;

        let key_bytes = *sk;
        let mut plaintext = vec![0u8; ciphertext.len()];

        let key = Key::from(key_bytes);

        let tag = Tag::from(*tag);
        
        let nonce = Nonce::from(*nonce);    

        match key.decrypt(&mut plaintext, &nonce,  ad, &ciphertext, &tag) {
            Ok(()) => {},
            Err(_) => return Err("Decryption error")
        }    
        Ok(plaintext)
    }
    #[cfg(hax)]{
        Ok(Vec::new())
    }

}

#[hax_lib::opaque]
#[hax_lib::requires(key.len() == 32)]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_hmac_sha2_256 (key: &[u8; 32], data: &[u8]) -> [u8; 32]{
    #[cfg(not(hax))]{
        use libcrux_hmac::hmac_sha2_256;
        let mut dst = [0u8; 32];
        hmac_sha2_256(&mut dst, key, data);

        dst
    }
    #[cfg(hax)]{
        [0u8; 32]
    }
}


#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 64)]
pub fn libcrux_gen_kdf_key_auth(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 64] {
    #[cfg(not(hax))] {
    let mut okm: [u8; 64] = [0u8; 64];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info,
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; 64] // dummy body for hax
    }  
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 80)]
pub fn libcrux_hkdf_80(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 80] {
    #[cfg(not(hax))] {
    let mut okm: [u8; 80] = [0u8; 80];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info,
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; 80] // dummy body for hax
    }  
}

#[hax_lib::opaque]
// Returns the dk, ek_vector and header
// Header is created by header = ek_seed || hek
// hek = SHA3-256(ek_seed || ek_vector) using SHA3-256 know from libcrux source files
#[hax_lib::ensures(|res| 
    res.0.len() == 2400
    && res.1.len() == 64
    && res.2.len() == 1152)]
pub fn libcrux_ml_kem_key_pair_compressed_generate() -> ([u8; DECAPSULATION_KEY_SIZE], [u8; HEADER_SIZE], [u8; EK_VECTOR_SIZE] ){

    #[cfg(not(hax))] {
        use rand::{RngCore, SeedableRng, rngs::StdRng};
        use libcrux_ml_kem;
        let mut ek_seed = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];   
        let mut rng = StdRng::from_os_rng();
        rng.fill_bytes(&mut ek_seed);
        let keys = libcrux_ml_kem::mlkem768::incremental::KeyPairCompressedBytes::from_seed(ek_seed);
        let hdr: [u8; HEADER_SIZE] = *keys.pk1();
        let ek: [u8; EK_VECTOR_SIZE] = *keys.pk2();
        let dk: [u8; DECAPSULATION_KEY_SIZE]  = *keys.sk();

        (dk, hdr, ek)   
    }
    #[cfg(hax)] {
        ([0u8; DECAPSULATION_KEY_SIZE], [0u8; HEADER_SIZE], [0u8; EK_VECTOR_SIZE])

    }
}

#[hax_lib::opaque]
// Validates the header and ek_vector from the KeyPairCompressedBytes generation
pub fn libcrux_ml_kem_validate<'a> (hdr: &[u8], ek_vector: &[u8]) -> Result<(), &'a str>{

    #[cfg(not(hax))] {
         match libcrux_ml_kem::mlkem768::incremental::validate_pk_bytes(hdr, ek_vector) {
            Ok(()) => return Ok(()),
            Err(_) => return Err("Couldn't validate the header and ek_vector")
         }
    }
    #[cfg(hax)] {
        Ok(())

    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_sha3_256(data: &[u8]) -> [u8; 32] {

    #[cfg(not(hax))] {
        use libcrux_sha3;
        let h_data = libcrux_sha3::sha256(data);
        h_data
    }
    #[cfg(hax)] {
        [0u8; 32]
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(private_key.len() == 2400
    && ct1.len() == 960
    && ct2.len() == 128)]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_ml_kem_decapsulate_compressed_key(private_key: &[u8; DECAPSULATION_KEY_SIZE], ct1: &[u8; CT1_SIZE], ct2: &[u8; CT2_SIZE]) -> [u8; 32] {

    #[cfg(not(hax))] {
        use libcrux_ml_kem;

        let ct1 = libcrux_ml_kem::mlkem768::incremental::Ciphertext1 {value: *ct1};
        let ct2 = libcrux_ml_kem::mlkem768::incremental::Ciphertext2 {value: *ct2};
        
        let ml_kem_shared_secret = libcrux_ml_kem::mlkem768::incremental::decapsulate_compressed_key(private_key, &ct1, &ct2);
        ml_kem_shared_secret
    }
    #[cfg(hax)] {
        [0u8; 32]
    }
}


#[hax_lib::opaque]
#[hax_lib::requires(hdr.len() == 64
    && randomness.len() == 32)]
#[hax_lib::ensures(|res|
    res.0.len() == 2080
    && res.1.len() == 960
    && res.2.len() == 32)]
pub fn libcrux_ml_kem_encapsulate_1(hdr: &[u8; 64], randomness: [u8; 32]) -> ([u8; ENCAPS_SECRET_SIZE], [u8; CT1_SIZE], [u8; SHARED_SECRET_SIZE]) {

    #[cfg(not(hax))] {
        use libcrux_ml_kem::mlkem768::{incremental::{encapsulate1}};
        use libcrux_ml_kem::mlkem768::incremental;


        let mut state = [0u8; incremental::encaps_state_len()];
        let mut ss = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];

        let ct1 = encapsulate1(hdr, randomness, &mut state, &mut ss).expect("Couldn't encapsulate 1 for the first part of the ciphertext");
        let ct1_bytes = ct1.value;

        (state, ct1_bytes, ss)
    }
    #[cfg(hax)] {
        ([0u8; ENCAPS_SECRET_SIZE], [0u8; CT1_SIZE], [0u8; SHARED_SECRET_SIZE])
    }
}



#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_gen_kdf_key_ok(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    #[cfg(not(hax))] {
    let mut okm: [u8; 32] = [0u8; 32];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info,
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; 32] // dummy body for hax
    }
    
}

#[hax_lib::opaque]
#[hax_lib::requires(state.len() == 2080
    && public_key_part.len() == 1152)]
#[hax_lib::ensures(|res| res.len() == 128)]
pub fn libcrux_ml_kem_encapsulate_2(state: &[u8; ENCAPS_SECRET_SIZE], public_key_part: &[u8; EK_VECTOR_SIZE]) -> [u8; CT2_SIZE] {
    #[cfg(not(hax))] {
        use libcrux_ml_kem::mlkem768::{incremental::{encapsulate2}};

        let ct2 = encapsulate2(&state, public_key_part);
        let ct2_bytes = ct2.value;

        ct2_bytes
    }
    #[cfg(hax)] {
        [0u8; CT2_SIZE] // Dummy body for hax
    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 32)]
pub fn libcrux_gen_kdf_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    #[cfg(not(hax))] {
    let mut okm: [u8; 32] = [0u8; 32];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info,
    ).unwrap();
    okm
}

    #[cfg(hax)] {
        [0u8; 32] // dummy body for hax
    }
    
}


#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 96)]
pub fn libcrux_gen_kdf_key_scka_init(salt: &[u8], ikm: &[u8]) -> [u8; 96] {
    #[cfg(not(hax))] {
    let info = format!("{} Chain start", PROTOCOL_INFO);
    let mut okm: [u8; 96] = [0u8; 96];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info.as_bytes(),
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; 96] // dummy body for hax
    }
}

#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == 96)]
pub fn libcrux_gen_kdf_key_scka_rk(salt: &[u8], ikm: &[u8]) -> [u8; 96] {
    #[cfg(not(hax))] {
    let info = format!("{} Chain Add Epoch", PROTOCOL_INFO);
    let mut okm: [u8; 96] = [0u8; 96];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info.as_bytes(),
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; 96] // dummy body for hax
    }
}


#[hax_lib::opaque]
#[hax_lib::ensures(|res| res.len() == MESSAGE_KEY_SIZE)]
pub fn libcrux_gen_kdf_hybrid(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; MESSAGE_KEY_SIZE] {
    #[cfg(not(hax))] {
    let mut okm: [u8; MESSAGE_KEY_SIZE] = [0u8; MESSAGE_KEY_SIZE];
    libcrux_hkdf::hkdf(
        libcrux_hkdf::Algorithm::Sha256,
        &mut okm,
        salt,
        ikm,
        info,
    ).unwrap();
    okm
}
    #[cfg(hax)] {
        [0u8; MESSAGE_KEY_SIZE] // dummy body for hax
    }  
}
