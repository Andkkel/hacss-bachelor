use crate::util::libcrux_wrap::{libcrux_gen_kdf_key};

const KDF_KEY_LABEL: [u8; 7] = *b"kdf_key";
const OUTPUT_KEY_LABEL: [u8; 10] = *b"output_key";

/*
This is the making of one KDF-chain step. 
- return new chain key and a message key
*/
#[hax_lib::ensures(
    |res|
    res.0.len() == 32 &&
    res.1.len() == 32 
)]
pub fn make_kdf_chain_key_pair(kdf_key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) { 
    let new_kdf_key= libcrux_gen_kdf_key( input,kdf_key,  &KDF_KEY_LABEL);
    let output_key= libcrux_gen_kdf_key(input, kdf_key, &OUTPUT_KEY_LABEL);

    (new_kdf_key, output_key)
} 