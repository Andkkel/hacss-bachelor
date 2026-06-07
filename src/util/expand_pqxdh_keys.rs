use crate::util::libcrux_wrap::libcrux_gen_kdf_key_auth;
use crate::util::constants::SHARED_SECRET_SIZE;
#[hax_lib::requires(sk.len() == SHARED_SECRET_SIZE)]
#[hax_lib::ensures(|res| res.0.len() == SHARED_SECRET_SIZE && res.1.len() == SHARED_SECRET_SIZE)]
pub(crate) fn expand_pqxdh_sk (sk: [u8; SHARED_SECRET_SIZE]) -> ([u8; SHARED_SECRET_SIZE], [u8; SHARED_SECRET_SIZE]) {
    let salt = [0u8; 32];

    let info = b"EXPANDED_SHARED_SECRET_FROM_PQXDH";

    let expand_sk = libcrux_gen_kdf_key_auth(&salt, &sk, info);

    let mut ec_sk: [u8; SHARED_SECRET_SIZE] = [0u8; SHARED_SECRET_SIZE];
    ec_sk.copy_from_slice(&expand_sk[..SHARED_SECRET_SIZE]);

    let mut scka_sk: [u8; SHARED_SECRET_SIZE] = [0u8; SHARED_SECRET_SIZE];
    scka_sk.copy_from_slice(&expand_sk[SHARED_SECRET_SIZE..]);
    
    (ec_sk, scka_sk)
}