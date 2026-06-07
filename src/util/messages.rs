use crate::util::keys::{EncapsulationKey, ML_KEM_768_CT_SIZE, MLDSA_65_SIGNATURE_KEY_SIZE, X25519PublicKey, X25519KeyPair};
use std::fmt;

#[derive(PartialEq, Debug, Clone)]
pub struct Chunk {
    pub index: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) enum MessageType{
    MakeOneTimePreKey,
    MakePQOneTimePreKey,
    NewMessage {from: (String, [u8; 1]), payload: (TRHeader, Vec<u8>), retry_init: Option<Box<MessageType>>},
    UploadOpks {upload_opks_user_id: (String, [u8; 1]), opks: Vec<(X25519PublicKey, u32)>},
    UploadPQOpks {upload_pqopks_user_id: (String, [u8; 1]), pq_opks: Vec<(EncapsulationKey, u32, [u8; MLDSA_65_SIGNATURE_KEY_SIZE])>},
    InitialMessage {
        ik_pub: X25519PublicKey,
        ek: X25519PublicKey,
        pq_ct: [u8; ML_KEM_768_CT_SIZE],
        pre_key_ids: Vec<IDUseNameKey>, 
        init_ct: [u8; 32],
        init_ct_tag: [u8; 16],
        init_ct_nonce: [u8; 12],
        salt: [u8; 32],
        initiator_id: (String, [u8; 1]),
        ad: [u8; 64]
    }
}

#[derive(Clone, Debug)]
pub enum IDUseNameKey {
    PQOPK {pqopk_id: u32},
    PQSPK {pqspk_id: u32},
    OPK {opk_id: u32},
    SPK {spk_id: u32}
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::MakeOneTimePreKey => write!(f, "MakeOneTimePreKey"),
            MessageType::MakePQOneTimePreKey => write!(f, "MakePQOneTimePreKey"),
            MessageType::NewMessage {from, .. } => write!(f, "NewMessage {{from: {:?} }}", from),
            MessageType::UploadOpks { upload_opks_user_id, opks } => write!(f, "UploadOpks {{ user_id: {:?}, count: {} }}", upload_opks_user_id, opks.len()),
            MessageType::UploadPQOpks { upload_pqopks_user_id, pq_opks } => write!(f, "UploadPQOpks {{ user_id: {:?}, count: {} }}", upload_pqopks_user_id, pq_opks.len()),
            MessageType::InitialMessage { initiator_id, .. } => write!(f, "InitialMessage {{ from: {:?} }}", initiator_id),
        }
    }
}

impl fmt::Display for IDUseNameKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IDUseNameKey::PQOPK { pqopk_id } => write!(f, "PQOPK({})", pqopk_id),
            IDUseNameKey::PQSPK { pqspk_id } => write!(f, "PQSPK({})", pqspk_id),
            IDUseNameKey::OPK {   opk_id } => write!(f, "OPK({})", opk_id),
            IDUseNameKey::SPK {   spk_id } => write!(f, "SPK({})", spk_id),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct SCKAMessage {
    pub(crate) epoch: u64,
    pub(crate) message_type: Option<SCKAMessageType>,
    pub(crate) data: Option<Chunk>,
}

#[derive(Debug, Clone)]
pub struct SCKAMessageHeader {
    pub(crate) message: SCKAMessage,
    pub(crate) pn: u64,
}

impl SCKAMessageHeader {
    pub(crate) fn new(msg: SCKAMessage, pn: u64) -> Self {
        Self {
            message: msg,
            pn
        }
    }
    pub(crate) fn default() -> Self{
        Self { message: SCKAMessage::default_msg(), pn: 0 }
    }
}
impl SCKAMessage {
    pub(crate) fn default_msg() -> Self {
        Self {
            epoch: 0,
            message_type: None,
            data: None,
        }
    }
}


#[derive(PartialEq, Debug, Clone)]
pub enum SCKAMessageType {
    Hdr,
    Ek,
    EkCt1Ack,
    Ct1Ack,
    Ct1,
    Ct2,
}

#[derive(Debug, Clone)]
pub struct TRHeader {
    pub(crate) ec_header: ECHeader,
    pub(crate) scka_header: SCKAMessageHeader
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ECHeader{
    pub(crate) dh_pub: X25519PublicKey,
    pub(crate) pn: u64, // Previous chain length
    pub(crate) n: u64 // Message number
}

#[hax_lib::attributes]
impl ECHeader{

    #[hax_lib::requires(dh_pair.is_some() 
        && dh_pair.unwrap().private_key.0.len() == 32
        && dh_pair.unwrap().public_key.0.len() == 32)]
    #[hax_lib::ensures(|result| 
        matches!(result, Ok(header) if dh_pair.is_some()))]
    pub fn header<'a> (dh_pair: Option<X25519KeyPair>, pn: u64, n: u64) -> Result<Self, &'a str> {
        let dh_pair_n = dh_pair.expect("There is no dh_pair for making of header");
        Ok(Self {
            dh_pub: dh_pair_n.public_key,
            pn: pn,
            n: n
        })
    }
    
    // Used in depricated ratchet encrypt and decrypt for DOuble Ratchet
    #[hax_lib::requires(ad.len() == 64)]
    #[hax_lib::ensures(|res| res.len() == 116)]
    pub(crate) fn concat_with_ad(&self, ad: &[u8; 64]) -> [u8; 116] {
        // The size is ad (64), dh_pub (32), pn (4*2), n (4*2) and the length of ad (4)
        let mut res: [u8; 116] = [0u8; 116];
        
        let dh_pub: [u8; 32] = self.dh_pub.0;

        res[0..4].copy_from_slice(&(64 as u32).to_be_bytes());
        res[4..68].copy_from_slice(ad);
        res[68..100].copy_from_slice(&dh_pub);
        res[100..108].copy_from_slice(&self.pn.to_be_bytes());
        res[108..116].copy_from_slice(&self.n.to_be_bytes());

        res
    }
    
    #[hax_lib::requires(self.dh_pub.0.len() == 32)]
    #[hax_lib::ensures(|res| res.len() == 48)]
    pub(crate) fn header_to_bytes(&self) -> [u8; 48] {
        // dh_pub (32) + pn (8) + n (8) = 48 bytes
        let mut res: [u8; 48] = [0u8; 48];
        let dh_pub: [u8; 32] = self.dh_pub.0;
        res[0..32].copy_from_slice(&dh_pub);
        res[32..40].copy_from_slice(&self.pn.to_be_bytes());
        res[40..48].copy_from_slice(&self.n.to_be_bytes());
        res
    }
}