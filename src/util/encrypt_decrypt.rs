use crate::util::libcrux_wrap::{libcrux_hkdf_80, libcrux_hmac_sha2_256};
use crate::util::constants::TR_PROTOCOL_INFO;
use crate::util::keys::MessageKey;

#[hax_lib::requires(encryption_key.len() == 32
    && iv.len() == 16
    && plaintext.len() < usize::MAX / 2)]   // To satisfy the size expansion the ciphertext needs
#[hax_lib::ensures(|res|
    res.len() == (plaintext.len() / 16 + 1) * 16    // plaintext will be assorted in chunks of 16 bytes - if it cannot it will add +1
)]
pub fn encrypt_aes256_cbc (plaintext: Vec<u8>, encryption_key: [u8; 32], iv: [u8; 16]) -> Vec<u8> {
    #[cfg(not(hax))]{
    use aes::Aes256;
    use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
    
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    
    let buf_len = (plaintext.len() / 16 + 1) * 16;
    let mut buf = vec![0u8; buf_len];
    let ct = Aes256CbcEnc::new(&encryption_key.into(), &iv.into())
        .encrypt_padded_b2b::<Pkcs7>(&plaintext, &mut buf)
        .unwrap();
    ct.to_vec()
    }
    #[cfg(hax)]{
        vec![0u8; (plaintext.len() / 16 + 1) * 16]
    }
}

#[hax_lib::requires(decryption_key.len() == 32
    && iv.len() == 16
    && ciphertext.len() % 16 == 0   // ciphertext fills up 16 bytes
    && ciphertext.len() >= 16       // ciphertext can atleast be 16 bytes
    && ciphertext.len() < usize::MAX)] 
#[hax_lib::ensures(|res|
            res.len() >= ciphertext.len() - 16  // plaintext can be the full ciphertext
            && res.len() < ciphertext.len()     // ciphertext will always be larger than the plaintext
        )]
pub fn decrypt_aes256_cbc (ciphertext: &[u8], decryption_key: [u8; 32], iv: [u8; 16]) -> Vec<u8> {
    #[cfg(not(hax))]{
    use aes::Aes256;
    use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    let mut buf = ciphertext.to_vec();
    let pt = Aes256CbcDec::new(&decryption_key.into(), &iv.into())
        .decrypt_padded_b2b::<Pkcs7>(&ciphertext, &mut buf)
        .unwrap();
    pt.to_vec()
    }
    #[cfg(hax)]{
        vec![0u8; ciphertext.len() - 1]
    }
} 

#[hax_lib::requires(mk.0.len() == 32
    && plaintext.as_bytes().len() < usize::MAX / 2)]
#[hax_lib::ensures(|res|
    res.len() == 32 + (plaintext.as_bytes().len() / 16 + 1) * 16)]
pub(crate) fn encrypt (mk: &MessageKey, plaintext: &str, ad_header: &[u8]) -> Vec<u8> {
    #[cfg(not(hax))]{
        let ek_auth_iv: [u8; 80] = libcrux_hkdf_80(&[0u8; 80], &mk.0, TR_PROTOCOL_INFO);
        let ek: [u8; 32] = ek_auth_iv[..32].try_into().unwrap();
        let auth: [u8; 32] = ek_auth_iv[32..32+32].try_into().unwrap();
        let iv: [u8; 16] = ek_auth_iv[32+32..].try_into().unwrap();

        let plaintext_bytes = plaintext.as_bytes().to_vec();
        let plaintext_len = plaintext_bytes.len();
        hax_lib::assert!(plaintext_len == plaintext.as_bytes().len());

        let ciphertext = encrypt_aes256_cbc(plaintext_bytes, ek, iv);
        let ct_len = (plaintext_len / 16 + 1) * 16;
        hax_lib::assert!(ciphertext.len() == (plaintext_len / 16 + 1) * 16);
        hax_lib::assert!(ciphertext.len() == ct_len);
        
        
        let mut ad_header_ct: Vec<u8> = Vec::new();
        ad_header_ct.extend_from_slice(ad_header);
        ad_header_ct.extend_from_slice(&ciphertext);
        
        let hmac_ad_ct = libcrux_hmac_sha2_256(&auth, &ad_header_ct);

        let mut ct = Vec::new();
        ct.extend_from_slice(&hmac_ad_ct);
        ct.extend_from_slice(&ciphertext);
        ct
    }
    #[cfg(hax)]{
        vec![0u8; 32 + (plaintext.as_bytes().len() / 16 + 1) * 16]
    }
}

#[hax_lib::opaque]
#[hax_lib::requires(
    mk.0.len() == 32
    && ciphertext.len() < usize::MAX / 2)]
pub(crate) fn decrypt<'a> (mk: &MessageKey, ciphertext: &Vec<u8>, ad_header: &[u8]) -> Result<String, &'a str> {
    #[cfg(not(hax))]{
    let dk_auth_iv: [u8; 80] = libcrux_hkdf_80(&[0u8; 80], &mk.0, TR_PROTOCOL_INFO);
    let dk: [u8; 32] = dk_auth_iv[..32].try_into().unwrap();
    let auth: [u8; 32] = dk_auth_iv[32..32+32].try_into().unwrap();
    let iv: [u8; 16] = dk_auth_iv[32+32..].try_into().unwrap();

    let hmac: [u8; 32] = ciphertext[..32].try_into().unwrap();
    let ciphertext = &ciphertext[32..];

    // Testing for hmac and expected hmac
    let ad_header_ct = [ad_header.to_vec().as_slice(), ciphertext].concat();
    
    let expected_hmac = libcrux_hmac_sha2_256(&auth, &ad_header_ct);
    
    if hmac != expected_hmac {
        return Err("Expected HMAC and HMAC is not equal");
    }

    let pt_vec = decrypt_aes256_cbc(ciphertext, dk, iv);
    String::from_utf8(pt_vec).map_err(|_| "decrypted bytes are not valid UTF-8")
    }
    #[cfg(hax)]{
        Ok("".to_string())
    }
}