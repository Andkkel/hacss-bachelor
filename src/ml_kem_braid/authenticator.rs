use crate::ml_kem_braid::ml_kem_braid_impl::{MlKemHeader};
use crate::util::constants::{CT1_SIZE, CT2_SIZE, MAC_SIZE, PROTOCOL_INFO, ROOT_CHAIN_KEY_SIZE, EK_SEED_SIZE, HEK_SIZE};
use crate::util::keys::ML_KEM_768_CT_SIZE;
use crate::util::{helper_func::extract_chunk};
use crate::util::libcrux_wrap::{libcrux_hmac_sha2_256, libcrux_gen_kdf_key, libcrux_gen_kdf_key_auth};

// Mirrors the Ratcheted Authenticator from section 2.4
#[derive(Clone, Copy, Debug)]
pub(crate) struct Authenticator {
    pub(crate) root_key: [u8; 32],
    pub(crate) mac_key:  Option<[u8; 32]>,
}
#[hax_lib::attributes]
impl Authenticator {
    #[hax_lib::opaque]
    pub fn new(epoch: u64, key: &[u8; 32]) -> Self {
        let mut auth_state = Self {
            root_key: [0u8; 32],
            mac_key: None
        };

        _ = auth_state.update_auth_state(epoch, key);

        auth_state
    }

    #[hax_lib::opaque]
    pub fn size(&self) -> usize {
        32                                      // root_key
        + 1 + self.mac_key.map_or(0, |_| 32)  // Option<[u8;32]>
    }

    #[hax_lib::opaque]
    pub(crate) fn update_auth_state<'a> (&mut self, epoch: u64, key: &[u8; 32]) -> Result<(), &'a str>{
        let prefix = b"HACSS_MLKEM768_SHA-256 : Authenticator Update ";
        let epoch_bytes = epoch.to_le_bytes(); 
        
        let mut label = [0u8; 46 + 8]; 
        label[..46].copy_from_slice(prefix);
        label[46..].copy_from_slice(&epoch_bytes);

        let concat_key = libcrux_gen_kdf_key_auth(&self.root_key, key, &label);
        
        hax_lib::assume!(concat_key.len() >= ROOT_CHAIN_KEY_SIZE);
        let root_key: [u8; ROOT_CHAIN_KEY_SIZE] = extract_chunk::<ROOT_CHAIN_KEY_SIZE>(&concat_key, 0);
        
        hax_lib::assume!(concat_key.len() >= MAC_SIZE);
        let mac_key: [u8; MAC_SIZE] = extract_chunk::<MAC_SIZE>(&concat_key, MAC_SIZE);
        
        self.root_key = root_key;
        self.mac_key = Some(mac_key);

        Ok(())
    }
    
    #[hax_lib::opaque]
    #[hax_lib::requires(self.mac_key.is_some())]
    pub(crate) fn mac_hdr<'a> (&mut self, epoch: u64, hdr: MlKemHeader) -> Result<[u8; MAC_SIZE], &'a str>{
        let mut data = Vec::new();
        hax_lib::assume!(data.len() <= usize::MAX - PROTOCOL_INFO.as_bytes().len());
        data.extend_from_slice(PROTOCOL_INFO.as_bytes());
        
        hax_lib::assume!(data.len() <= usize::MAX - 9);
        data.extend_from_slice(b":ekheader");

        hax_lib::assume!(data.len() <= usize::MAX - 8);
        data.extend_from_slice(&epoch.to_be_bytes());  // big-endian as spec recommends
        
        hax_lib::assume!(data.len() <= usize::MAX - EK_SEED_SIZE );
        data.extend_from_slice(&hdr.ek_seed);

        hax_lib::assume!(data.len() <= usize::MAX - HEK_SIZE );
        data.extend_from_slice(&hdr.hek);

        
        let mac_key = match self.mac_key {
            Some(mk) => mk,
            None => return Err("Could not find mac key")
        };
        let dst = libcrux_hmac_sha2_256(&mac_key, &data);

        Ok(dst)
    }
    
    #[hax_lib::opaque]
    pub(crate) fn mac_ct <'a> (&mut self, epoch: u64, ct: [u8; ML_KEM_768_CT_SIZE]) -> Result<[u8; 32], &'a str> {
        let mut data = Vec::new();
        
        hax_lib::assume!(data.len() <= usize::MAX - PROTOCOL_INFO.as_bytes().len());
        data.extend_from_slice(PROTOCOL_INFO.as_bytes());
        
        hax_lib::assume!(data.len() <= usize::MAX - 11);
        data.extend_from_slice(b":ciphertext");

        hax_lib::assume!(data.len() <= usize::MAX - 8);
        data.extend_from_slice(&epoch.to_be_bytes());  // big-endian as spec recommends

        hax_lib::assume!(data.len() <= usize::MAX - 1568);
        data.extend_from_slice(&ct);

        
        let key = match self.mac_key {
            Some(key) => key,
            None => return Err("Couldn't find any mac key")
        };
        let dst = libcrux_hmac_sha2_256(&key, &data);
        
        Ok(dst)
    }
    #[hax_lib::opaque]
    #[hax_lib::requires(self.mac_key.is_some())]
    pub(crate) fn vfy_hdr <'a>(&mut self, epoch: u64, hdr: MlKemHeader, expected_mac: [u8; 32]) -> Result<(), &'a str> {
        let mac_hdr = match self.mac_hdr(epoch, hdr) {
            Ok(mac_hdr) => mac_hdr,
            Err(_e) => return Err("Should be able to create the MAC for the header")
        };
        if expected_mac != mac_hdr {
            return Err("Expected MAC and actual MAC are not equal for the header");
        }

        Ok(())
    }

    #[hax_lib::opaque]
    #[hax_lib::requires(self.mac_key.is_some())]
    pub(crate) fn vfy_ct <'a> (&mut self, epoch: u64, ct: [u8; CT1_SIZE + CT2_SIZE], expected_mac: [u8; 32]) -> Result<(), &'a str> {
        let mac_ct = match self.mac_ct(epoch, ct) {
            Ok(mac_ct) => mac_ct,
            Err(e) => return Err("Should be able to create the MAC for the ciphertext")
        };
        if expected_mac != mac_ct {
            return Err("Expected MAC and actual MAC are not equal for the ciphertext - Start a new Session");
        }

        Ok(())
    }

    #[hax_lib::opaque]
    pub(crate) fn kdf_ok (shared_secret: [u8; 32], epoch: u64) -> [u8; 32] {
        let mut data = Vec::new();
        hax_lib::assume!(data.len() <= usize::MAX - PROTOCOL_INFO.as_bytes().len());
        data.extend_from_slice(PROTOCOL_INFO.as_bytes());
        
        hax_lib::assume!(data.len() <= usize::MAX - 9);
        data.extend_from_slice(b":SCKA Key");

        hax_lib::assume!(data.len()<= usize::MAX - 8);
        data.extend_from_slice(&epoch.to_be_bytes());

        let ok = libcrux_gen_kdf_key(&[0u8; 32], &shared_secret, &data);
        ok
    }

}