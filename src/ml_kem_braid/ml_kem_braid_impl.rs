use crate::util::constants::{CT1_SIZE, CT2_SIZE, EK_VECTOR_SIZE, HEADER_SIZE, MAC_SIZE};
use crate::util::helper_func::{concat, extract_chunk, make_randomness};
use crate::util::keys::{ML_KEM_768_CT_SIZE, SCKAOutputKey};
use crate::util::{helper_func};
use crate::ml_kem_braid::{decoder::SimpleDecoder, encoder::SimpleEncoder, authenticator::Authenticator};
use crate::util::libcrux_wrap::
    { 
        libcrux_ml_kem_decapsulate_compressed_key, 
        libcrux_ml_kem_encapsulate_1, 
        libcrux_ml_kem_key_pair_compressed_generate,
        libcrux_ml_kem_encapsulate_2,
        libcrux_ml_kem_validate};
use crate::util::messages::{SCKAMessage, SCKAMessageType};
use crate::util::constants::{EK_SEED_SIZE, CHUNK_SIZE, DECAPSULATION_KEY_SIZE, HEK_SIZE, ENCAPS_SECRET_SIZE, SHARED_SECRET_SIZE};



#[derive(Debug, Clone)]
pub(crate) struct MlKemBraid {
    pub(crate) state: BraidState
}
#[derive(Debug)]
pub(crate) struct MlKemHeader {
    pub(crate) ek_seed: [u8; EK_SEED_SIZE],
    pub(crate) hek:     [u8; HEK_SIZE],
}

// The opaque SCKA state — one of these variants is active at a time
#[derive(Debug, Clone)]
pub(crate) enum BraidState {
    KeysUnsampled{
        ku_epoch:      u64,
        ku_auth:       Authenticator        
    },
    KeysSampled {
        ks_epoch:          u64,
        ks_auth:           Authenticator,
        ks_dk:             [u8; DECAPSULATION_KEY_SIZE],        // ML-KEM decapsulation key
        ks_ek_seed:        [u8; EK_SEED_SIZE],
        ks_ek_vector:      [u8; EK_VECTOR_SIZE],
        ks_hek:            [u8; HEK_SIZE],       // SHA3-256(ek_seed || ek_vector)
        ks_header_encoder: SimpleEncoder,
    },
    HeaderSent {
        hs_epoch:       u64,
        hs_auth:        Authenticator,
        hs_dk:          [u8; DECAPSULATION_KEY_SIZE],
        hs_ct1_decoder: SimpleDecoder,
        hs_ek_encoder:  SimpleEncoder,
    },
    Ct1Received {
        ct1r_epoch:      u64,
        ct1r_auth:       Authenticator,
        ct1r_dk:         [u8; DECAPSULATION_KEY_SIZE],
        ct1r_ct1:        Option<[u8; CT1_SIZE]>,
        ct1r_ek_encoder: SimpleEncoder,
    },
    EkSentCt1Received {
        eksct1r_epoch:        u64,
        eksct1r_auth:         Authenticator,
        eksct1r_dk:          [u8; DECAPSULATION_KEY_SIZE],
        eksct1r_ct1:         Option<[u8; CT1_SIZE]>,
        eksct1r_ct2_decoder: SimpleDecoder,
    },
    NoHeaderReceived {
        nhr_epoch:        u64,
        nhr_auth:         Authenticator,
        nhr_header_decoder: SimpleDecoder,
    },
    HeaderReceived {
        hr_epoch:        u64,
        hr_auth:         Authenticator,
        hr_ek_seed:    [u8; EK_SEED_SIZE],
        hr_hek:        [u8; HEK_SIZE],
        hr_ek_decoder: SimpleDecoder,
    },
    Ct1Sampled {
        ct1s_epoch:         u64,
        ct1s_auth:          Authenticator,
        ct1s_encaps_secret: [u8; ENCAPS_SECRET_SIZE],
        ct1s_ct1:           [u8; CT1_SIZE],
        ct1s_hek:           [u8; HEK_SIZE],
        ct1s_ek_seed:       [u8; EK_SEED_SIZE],
        ct1s_ek_decoder:    SimpleDecoder,
        ct1s_ct1_encoder:   SimpleEncoder,
    },
    EkReceivedCt1Sampled {
        ekrct1s_epoch:        u64,
        ekrct1s_auth:         Authenticator,
        ekrct1s_encaps_secret: [u8; ENCAPS_SECRET_SIZE],
        ekrct1s_ek_vector:     [u8; EK_VECTOR_SIZE],
        ekrct1s_ek_seed:       [u8; EK_SEED_SIZE],
        ekrct1s_ct1:           [u8; CT1_SIZE],
        ekrct1s_ct1_encoder:   SimpleEncoder,
    },
    Ct1Acknowledged {
        ct1a_epoch:        u64,
        ct1a_auth:         Authenticator,
        ct1a_encaps_secret: [u8; ENCAPS_SECRET_SIZE],
        ct1a_ct1:           [u8; CT1_SIZE],
        ct1a_hek:           [u8; HEK_SIZE],
        ct1a_ek_seed:       [u8; EK_SEED_SIZE],
        ct1a_ek_decoder:    SimpleDecoder,
    },
    Ct2Sampled {
        ct2s_epoch:        u64,
        ct2s_auth:         Authenticator,
        ct2s_ct2_encoder: SimpleEncoder,
    },
}
#[hax_lib::attributes]
impl BraidState {
    #[hax_lib::opaque]
    pub fn state_size(&self) -> usize {
        match self {
            BraidState::KeysUnsampled { ku_auth, .. } =>
                8 + ku_auth.size(),
            BraidState::KeysSampled { ks_auth, ks_header_encoder, .. } =>
                8 + ks_auth.size()
                + DECAPSULATION_KEY_SIZE + EK_SEED_SIZE + EK_VECTOR_SIZE
                + HEK_SIZE + ks_header_encoder.size(),
            BraidState::HeaderSent { hs_auth, hs_ct1_decoder, hs_ek_encoder, .. } =>
                8 + hs_auth.size()
                + DECAPSULATION_KEY_SIZE
                + hs_ct1_decoder.size() + hs_ek_encoder.size(),
            BraidState::Ct1Acknowledged { ct1a_epoch, ct1a_auth, ct1a_encaps_secret, ct1a_ct1, ct1a_hek, ct1a_ek_seed, ct1a_ek_decoder } =>
                8 + ct1a_auth.size() + ct1a_encaps_secret.len() + CT1_SIZE + HEK_SIZE + EK_SEED_SIZE + ct1a_ek_decoder.size(),
            BraidState::Ct1Received { ct1r_epoch, ct1r_auth, ct1r_dk, ct1r_ct1, ct1r_ek_encoder } =>
                8 + ct1r_auth.size() + DECAPSULATION_KEY_SIZE + CT1_SIZE + ct1r_ek_encoder.size(),
            BraidState::Ct1Sampled { ct1s_epoch, ct1s_auth, ct1s_encaps_secret, ct1s_ct1, ct1s_hek, ct1s_ek_seed, ct1s_ek_decoder, ct1s_ct1_encoder } =>
                8 + ct1s_auth.size() + ENCAPS_SECRET_SIZE + CT1_SIZE + HEK_SIZE + EK_SEED_SIZE + ct1s_ek_decoder.size() + ct1s_ct1_encoder.size(),
            BraidState::Ct2Sampled { ct2s_epoch, ct2s_auth, ct2s_ct2_encoder } =>
                8 + ct2s_auth.size() + ct2s_ct2_encoder.size(),
            BraidState::EkReceivedCt1Sampled { ekrct1s_epoch, ekrct1s_auth, ekrct1s_encaps_secret, ekrct1s_ek_vector, ekrct1s_ek_seed, ekrct1s_ct1, ekrct1s_ct1_encoder } =>
                8 + ekrct1s_auth.size() + ENCAPS_SECRET_SIZE + EK_VECTOR_SIZE + EK_SEED_SIZE + CT1_SIZE + ekrct1s_ct1_encoder.size(),
            BraidState::EkSentCt1Received { eksct1r_epoch, eksct1r_auth, eksct1r_dk, eksct1r_ct1, eksct1r_ct2_decoder } =>
                8 + eksct1r_auth.size() + DECAPSULATION_KEY_SIZE + CT1_SIZE + eksct1r_ct2_decoder.size(),
            BraidState::HeaderReceived { hr_epoch, hr_auth, hr_ek_seed, hr_hek, hr_ek_decoder } =>
                8+ hr_auth.size() + EK_SEED_SIZE + HEK_SIZE + hr_ek_decoder.size(),
            BraidState::NoHeaderReceived { nhr_epoch, nhr_auth, nhr_header_decoder } =>
                8 + nhr_auth.size() + nhr_header_decoder.size()
        }
    }
}

impl std::fmt::Display for BraidState {
    #[hax_lib::opaque]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BraidState::KeysUnsampled { ku_epoch: epoch, .. }        => write!(f, "KeysUnsampled(epoch={})", epoch),
            BraidState::KeysSampled { ks_epoch: epoch, .. }          => write!(f, "KeysSampled(epoch={})", epoch),
            BraidState::HeaderSent { hs_epoch: epoch, .. }           => write!(f, "HeaderSent(epoch={})", epoch),
            BraidState::Ct1Received { ct1r_epoch: epoch, .. }          => write!(f, "Ct1Received(epoch={})", epoch),
            BraidState::EkSentCt1Received { eksct1r_epoch: epoch, .. }    => write!(f, "EkSentCt1Received(epoch={})", epoch),
            BraidState::NoHeaderReceived { nhr_epoch: epoch, .. }     => write!(f, "NoHeaderReceived(epoch={})", epoch),
            BraidState::HeaderReceived { hr_epoch: epoch, .. }       => write!(f, "HeaderReceived(epoch={})", epoch),
            BraidState::Ct1Sampled { ct1s_epoch: epoch, .. }           => write!(f, "Ct1Sampled(epoch={})", epoch),
            BraidState::EkReceivedCt1Sampled { ekrct1s_epoch: epoch, .. } => write!(f, "EkReceivedCt1Sampled(epoch={})", epoch),
            BraidState::Ct1Acknowledged { ct1a_epoch: epoch, .. }      => write!(f, "Ct1Acknowledged(epoch={})", epoch),
            BraidState::Ct2Sampled { ct2s_epoch: epoch, .. }           => write!(f, "Ct2Sampled(epoch={})", epoch),
        }
    }
}

impl MlKemBraid {
    #[hax_lib::opaque]
    pub fn init_initiator(ss: &[u8; SHARED_SECRET_SIZE]) -> Self {
        let epoch = 1;
        let auth = Authenticator::new(epoch, ss);

        let state = BraidState::KeysUnsampled{ku_epoch: epoch, ku_auth: auth};

        Self {
            state
        }
    }
    #[hax_lib::opaque]
    pub(crate) fn init_responder(ss: &[u8; SHARED_SECRET_SIZE]) -> Self {
        let epoch = 1;
        let auth = Authenticator::new(epoch, ss);

        let header_decoder = SimpleDecoder::new(HEADER_SIZE + MAC_SIZE);

        let state = BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder };

        Self {
            state
        }
    }
    #[hax_lib::opaque]
    pub fn send<'a> (&mut self) -> Result<(SCKAMessage, (u64, Option<SCKAOutputKey>)), &'a str> {
         
         let state = std::mem::replace(
            &mut self.state,
            BraidState::KeysUnsampled { ku_epoch: 20000, ku_auth: Authenticator::new(1, &[0u8; 32]) }
        );
        
         match state  {
            BraidState::KeysUnsampled {ku_epoch: epoch, ku_auth: auth} => {
                let mut auth = auth;
    
                let (dk, header, ek_vector) = libcrux_ml_kem_key_pair_compressed_generate();
                
                // header = (ek_seed || hek)
                // hek = SHA3-256(ek_seed || ek_vector) for integrity binding
                let (ek_seed_slice, hek_slice) = header.split_at(32);
                let ek_seed: [u8; 32] = ek_seed_slice.try_into().unwrap();
                let hek: [u8; 32] = hek_slice.try_into().unwrap();

                let ml_kem_header = MlKemHeader { ek_seed, hek };

                hax_lib::assume!(auth.mac_key.is_some());
                let mac = match auth.mac_hdr(epoch, ml_kem_header) {
                    Ok(mac) => mac,
                    Err(e) => return Err(e)
                };
                let concat_header_mac: [u8; HEADER_SIZE + MAC_SIZE] = helper_func::concat(header, mac);
                
                
                let mut header_encoder = SimpleEncoder::new(&concat_header_mac, CHUNK_SIZE);
                
                // Generate message

                let chunk = match header_encoder.next_chunk(){
                    Ok(chunk) => chunk,
                    Err(e) => return Err(e)
                };
                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Hdr),
                    data: Some(chunk)
                };
                // Returns the message, the sending epoch and the outputkey
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                // Update state
                // Transition (1)

                // Updates the current state to Keys Sampled
                let state = BraidState::KeysSampled {ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder};
                self.state = state;
                
                Ok((msg, (sending_epoch, output_key)))                
            },
            BraidState::KeysSampled { ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder } => {
                let mut header_encoder = header_encoder;
                // Generate next header chunk
                let chunk = match header_encoder.next_chunk() {
                    Ok(chunk) => Some(chunk),
                    Err(_) => None
                };

                let msg = SCKAMessage{
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Hdr),
                    data: chunk
                };

                // Return values
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;
                self.state = BraidState::KeysSampled { ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder };
                Ok((msg, (sending_epoch, output_key)))
            },
            BraidState::HeaderSent { hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder } => {
                let mut ek_encoder = ek_encoder;
                // Generate next ek_vector chunk
                let chunk = match ek_encoder.next_chunk(){
                    Ok(chunk) => chunk,
                    Err(e) => return Err(e)
                };
                let msg = SCKAMessage{
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Ek),
                    data: Some(chunk)
                };
    
                // Return values
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = BraidState::HeaderSent { hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder };

                Ok((msg, (sending_epoch, output_key)))
            },
            BraidState::Ct1Received { ct1r_epoch: epoch, ct1r_auth: auth, ct1r_dk: dk, ct1r_ct1: ct1, ct1r_ek_encoder: ek_encoder } => {
                let mut ek_encoder = ek_encoder;
                // Generate next ek_vector chunk with acknowledgment
                let chunk = match ek_encoder.next_chunk() {
                    Ok(chunk) => Some(chunk),
                    Err(_) => None
                };
                let msg = SCKAMessage{
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::EkCt1Ack),
                    data: chunk
                };
                // Return values
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch-1;

                self.state = BraidState::Ct1Received { ct1r_epoch: epoch, ct1r_auth: auth, ct1r_dk: dk, ct1r_ct1: ct1, ct1r_ek_encoder: ek_encoder };
                
                Ok((msg, (sending_epoch, output_key)))
            },
            BraidState::EkSentCt1Received { eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder } => {
                // No data to send   
                let msg = SCKAMessage{
                    epoch: epoch,
                    message_type: None,
                    data: None
                };
                // Return values
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch-1;

                self.state = BraidState::EkSentCt1Received { eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder };

                Ok((msg, (sending_epoch, output_key)))
            },
            BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder } => {
                // No data to send
                let msg = SCKAMessage{
                    epoch: epoch,
                    message_type: None,
                    data: None
                };
                // Return values
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch-1;

                self.state = BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder };

                Ok((msg, (sending_epoch, output_key)))
            }

            BraidState::HeaderReceived { hr_epoch: epoch, hr_auth: auth, hr_ek_seed: ek_seed, hr_hek: hek, hr_ek_decoder: ek_decoder } => {         
                let randomness = make_randomness::<32>();

                let hdr: [u8; EK_SEED_SIZE + HEK_SIZE] = helper_func::concat(ek_seed, hek);
                
                // Generate shared secret and ct1
                let (encaps_secret, ct1, ss) = libcrux_ml_kem_encapsulate_1(&hdr, randomness); //TODO: maybe should the randomness here be ek_seed (and not randomness), and then we should change the size in the ml kem key gen
                let ss = Authenticator::kdf_ok(ss, epoch);
                
                // Update auth
                let mut auth = auth;
                match auth.update_auth_state(epoch, &ss){
                    Ok(()) => {},
                    Err(e) => return Err(e)
                }

                //Encode ct1 for trasnmission
                let mut ct1_encoder = SimpleEncoder::new(&ct1, CHUNK_SIZE);
                let chunk = match ct1_encoder.next_chunk(){
                    Ok(chunk) => chunk,
                    Err(e) => return Err(e)
                };
                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Ct1),
                    data: Some(chunk),
                };

                let state = BraidState::Ct1Sampled { 
                    ct1s_epoch: epoch,
                    ct1s_auth: auth,
                    ct1s_encaps_secret: encaps_secret,
                    ct1s_ct1: ct1,
                    ct1s_hek: hek,
                    ct1s_ek_seed: ek_seed,
                    ct1s_ek_decoder: ek_decoder.clone(), 
                    ct1s_ct1_encoder: ct1_encoder 
                };
            
                let output_key = SCKAOutputKey{epoch: epoch, key: ss};
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = state;

                Ok((msg, (sending_epoch, Some(output_key))))
            }

            BraidState::Ct1Sampled { ct1s_epoch: epoch, ct1s_auth: auth, ct1s_encaps_secret: encaps_secret, ct1s_ct1: ct1, ct1s_hek: hek, ct1s_ek_seed: ek_seed, ct1s_ek_decoder: ek_decoder, ct1s_ct1_encoder: ct1_encoder } => {
                let mut ct1_encoder = ct1_encoder;
                let chunk = match ct1_encoder.next_chunk() {
                    Ok(chunk) => Some(chunk),
                    Err(_) => None
                };

                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Ct1),
                    data: chunk,
                };

                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = BraidState::Ct1Sampled { ct1s_epoch: epoch, ct1s_auth: auth, ct1s_encaps_secret: encaps_secret, ct1s_ct1: ct1, ct1s_hek: hek, ct1s_ek_seed: ek_seed, ct1s_ek_decoder: ek_decoder, ct1s_ct1_encoder: ct1_encoder };

                Ok((msg, (sending_epoch, output_key)))
            }

            BraidState::EkReceivedCt1Sampled { ekrct1s_epoch: epoch, ekrct1s_auth: auth, ekrct1s_encaps_secret: encaps_secret, ekrct1s_ek_vector: ek_vector, ekrct1s_ek_seed: ek_seed, ekrct1s_ct1: ct1, ekrct1s_ct1_encoder: ct1_encoder } => {
                let mut ct1_encoder = ct1_encoder;
                let chunk = match ct1_encoder.next_chunk(){
                    Ok(chunk) => chunk,
                    Err(e) => return Err(e)
                };
                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Ct1),
                    data: Some(chunk)
                };
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = BraidState::EkReceivedCt1Sampled { ekrct1s_epoch: epoch, ekrct1s_auth: auth, ekrct1s_encaps_secret: encaps_secret, ekrct1s_ek_vector: ek_vector, ekrct1s_ek_seed: ek_seed, ekrct1s_ct1: ct1, ekrct1s_ct1_encoder: ct1_encoder };

                Ok((msg, (sending_epoch, output_key)))
            }

            BraidState::Ct1Acknowledged { ct1a_epoch: epoch, ct1a_auth: auth, ct1a_encaps_secret: encaps_secret, ct1a_ct1: ct1, ct1a_hek: hek, ct1a_ek_seed: ek_seed, ct1a_ek_decoder: ek_decoder } => {
                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: None,
                    data: None
                };

                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = BraidState::Ct1Acknowledged { ct1a_epoch: epoch, ct1a_auth: auth, ct1a_encaps_secret: encaps_secret, ct1a_ct1: ct1, ct1a_hek: hek, ct1a_ek_seed: ek_seed, ct1a_ek_decoder: ek_decoder };
                
                Ok((msg, (sending_epoch, output_key)))
            } 

            BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder } => {
                let mut ct2_encoder = ct2_encoder;
                let chunk = match ct2_encoder.next_chunk(){
                    Ok(chunk) => Some(chunk),
                    Err(_) => None
                };
                
                let msg = SCKAMessage {
                    epoch: epoch,
                    message_type: Some(SCKAMessageType::Ct2),
                    data: chunk
                };

                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let sending_epoch = epoch - 1;

                self.state = BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder };
            
                Ok((msg, (sending_epoch, output_key)))
            }
        }
    }

    #[hax_lib::opaque]
    pub fn receive<'a>(&mut self, msg: SCKAMessage) -> Result<(u64, Option<SCKAOutputKey>), &'a str> {
        let state = std::mem::replace(
            &mut self.state,
            BraidState::KeysUnsampled { ku_epoch: 10000, ku_auth: Authenticator::new(1, &[0u8; 32]) }
        );

        match state {
            BraidState::KeysUnsampled { ku_epoch: epoch, ku_auth: auth } => {
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch-1;

                self.state = BraidState::KeysUnsampled { ku_epoch: epoch, ku_auth: auth };
    
                Ok((receiving_epoch, output_key))
            },
            
            BraidState::KeysSampled { ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder } => {
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch-1;

                let msg_type = match msg.message_type {
                    Some(e) => e,
                    None => {
                        self.state = BraidState::KeysSampled { ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder };
                        return Ok((receiving_epoch, output_key))
                    },
                };

                if msg.epoch == epoch && msg_type == SCKAMessageType::Ct1 {
                    // Initialize ct1 decoder and ek encoder
                    let mut ct1_decoder = SimpleDecoder::new(CT1_SIZE);
                    let chunk = match msg.data {
                        Some(chunk) => chunk,
                        None => return Err("Couldn't find the message data")
                    };
                    hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                    ct1_decoder.add_chunk(chunk);
                    let ek_encoder = SimpleEncoder::new(&ek_vector, CHUNK_SIZE);

                    // Update state
                    // Transition (2)
                    let state = BraidState::HeaderSent {hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder };
        
                    self.state = state;

                } else {
                    self.state = BraidState::KeysSampled { ks_epoch: epoch, ks_auth: auth, ks_dk: dk, ks_ek_seed: ek_seed, ks_ek_vector: ek_vector, ks_hek: hek, ks_header_encoder: header_encoder };
                }
                Ok((receiving_epoch, output_key))                    
            }
            BraidState::HeaderSent { hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder } => {
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch - 1;  
                let mut ct1_decoder = ct1_decoder;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::Ct1) {
                    let chunk = match msg.data{
                        Some(chunk) => chunk,
                        None => return Err("Couldn't find the message")
                    };
                    hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                    ct1_decoder.add_chunk(chunk);

                    if ct1_decoder.has_message() {
            
                        let ct1_vec = match ct1_decoder.message(){
                            Some(message) => message,
                            None => return Err("Couldn't find the message")
                        };

                        // Replace the loop with this:
                        hax_lib::assume!(ct1_vec.len() >= CT1_SIZE);
                        let ct1: [u8; CT1_SIZE] = extract_chunk::<CT1_SIZE>(&ct1_vec, 0);

                        /* hax_lib::assume!(ct1_vec.len() == CT1_SIZE);
                        let mut ct1: [u8; CT1_SIZE] = [0u8; CT1_SIZE];
                        
                        for i in 0..CT1_SIZE {
                            ct1[i] = ct1_vec[i]; 
                        } */

                        self.state = BraidState::Ct1Received { ct1r_epoch: epoch, ct1r_auth: auth, ct1r_dk: dk, ct1r_ct1: Some(ct1), ct1r_ek_encoder: ek_encoder };
                    } else {
                        self.state = BraidState::HeaderSent { hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder };
                    }
                } else {
                    self.state = BraidState::HeaderSent { hs_epoch: epoch, hs_auth: auth, hs_dk: dk, hs_ct1_decoder: ct1_decoder, hs_ek_encoder: ek_encoder };
                }
                Ok((receiving_epoch, output_key))
            }
            BraidState::Ct1Received { ct1r_epoch: epoch, ct1r_auth: auth, ct1r_dk: dk, ct1r_ct1: ct1, ct1r_ek_encoder: ek_encoder } => {
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch-1;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::Ct2) {
                    // Initialize ct2 decoder 
                    let mut ct2_decoder = SimpleDecoder::new(CT2_SIZE + MAC_SIZE);
                    let chunk = match msg.data{
                        Some(chunk) => chunk,
                        None => return Err("Couldn't find the message")
                    };
                    hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                    ct2_decoder.add_chunk(chunk);

                    // Update state
                    // Transition (4)
                    let state = BraidState::EkSentCt1Received {eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder };
                    self.state = state;
                } else {
                    self.state = BraidState::Ct1Received { ct1r_epoch: epoch, ct1r_auth: auth, ct1r_dk: dk, ct1r_ct1: ct1, ct1r_ek_encoder: ek_encoder };
                }

                Ok((receiving_epoch, output_key))
            }

            BraidState::EkSentCt1Received { eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder } => {
                let mut auth = auth;
                let mut ct2_decoder = ct2_decoder;
                let mut output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch-1;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::Ct2) {
                    // Add chunk to decoder
                    let chunk = match msg.data{
                        Some(chunk) => chunk,
                        None => return Err("Couldn't find the message")
                    };
                    hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                    ct2_decoder.add_chunk(chunk);

                    // Check if ct2 is complete
                    if ct2_decoder.has_message() {
                        let ct2_with_mac_vec = match ct2_decoder.message() {
                            Some(message) => message,
                            None => return Err("Couldn't find the message")
                        };
                        // Has the size of the ct2+mac size
                        hax_lib::assume!(ct2_with_mac_vec.len() >= CT2_SIZE + MAC_SIZE);
                        let ct2_with_mac: [u8; CT2_SIZE + MAC_SIZE] = extract_chunk::<{ CT2_SIZE + MAC_SIZE }>(&ct2_with_mac_vec,0);
                        
                        hax_lib::assume!(ct2_with_mac.len() >= CT2_SIZE);
                        let ct2: [u8; CT2_SIZE] = extract_chunk::<{CT2_SIZE}>(&ct2_with_mac, 0);
                        
                        hax_lib::assume!(ct2_with_mac.len() >= MAC_SIZE);
                        let mac: [u8; MAC_SIZE] = extract_chunk::<MAC_SIZE>(&ct2_with_mac, CT2_SIZE);
                        
                        // Decapsulate shared secret
                        let ct1 = match ct1 {
                            Some(ct1) => ct1,
                            None => return Err("Couldn't find the message")
                        };
                        let mut ss: [u8; SHARED_SECRET_SIZE] = libcrux_ml_kem_decapsulate_compressed_key(&dk, &ct1, &ct2);
            
                        ss = Authenticator::kdf_ok(ss, epoch);
                        
                        // Update authenticator and verify MAC
                        auth.update_auth_state(epoch, &ss)?;
            
                        let concat_ct1_ct2: [u8; ML_KEM_768_CT_SIZE] = concat(ct1, ct2);
                        
                        match auth.vfy_ct(epoch, concat_ct1_ct2, mac){
                            Ok(_) => {},
                            Err(e) => return Err(e)
                        };

                        // Prepare for next epoch
                        let header_decoder = SimpleDecoder::new(HEADER_SIZE + MAC_SIZE);

                        // Update state and return key
                        // Transition (5)
                        hax_lib::assume!(epoch < u64::MAX);
                        let state = BraidState::NoHeaderReceived {nhr_epoch: epoch + 1, nhr_auth: auth, nhr_header_decoder: header_decoder };
                        hax_lib::assume!(epoch >= 1);
                        output_key = Some(SCKAOutputKey{epoch: epoch, key: ss}); // This is not -1 since we can't access the updated +1 BraidState

                        self.state = state;

                    } else {
                        self.state = BraidState::EkSentCt1Received { eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder };
                    }

                } else { 
                    self.state = BraidState::EkSentCt1Received { eksct1r_epoch: epoch, eksct1r_auth: auth, eksct1r_dk: dk, eksct1r_ct1: ct1, eksct1r_ct2_decoder: ct2_decoder };
                }

                Ok((receiving_epoch, output_key))
                
            }
            BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder } => {
                let mut header_decoder = header_decoder;
                let mut auth = auth;
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch-1;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::Hdr) {
                    // Add chunk to decoder
                    match msg.data {
                        
                        Some(chunk) => {
                            hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                            header_decoder.add_chunk(chunk)
                        },
                        None => {}
                    }

                    // Check if header is complete
                    if header_decoder.has_message(){
                        let concat_header_mac = match header_decoder.message() {
                            Some(hmac) => hmac,
                            None => return Err("Could not find any message")
                        };
                        

                        hax_lib::assert!(concat_header_mac.len() == HEADER_SIZE + MAC_SIZE);
                        
                        hax_lib::assume!(concat_header_mac.len() >= HEADER_SIZE);
                        let header: [u8; HEADER_SIZE] = extract_chunk::<HEADER_SIZE>(&concat_header_mac, 0);
                        hax_lib::assume!(concat_header_mac.len() >= MAC_SIZE);
                        let mac: [u8; MAC_SIZE] = extract_chunk::<MAC_SIZE>(&concat_header_mac, HEADER_SIZE);
            
                        hax_lib::assume!(header.len() == EK_SEED_SIZE + HEK_SIZE);
                        let ek_seed: [u8; EK_SEED_SIZE] = extract_chunk::<EK_SEED_SIZE>(&header, 0);
                        let hek: [u8; HEK_SIZE] = extract_chunk::<HEK_SIZE>(&header, EK_SEED_SIZE);

                        let ml_kem_header = MlKemHeader{ ek_seed, hek };
                        
                        
                        // Verify header Mac
                        hax_lib::assume!(auth.mac_key.is_some());
                        match auth.vfy_hdr(epoch, ml_kem_header, mac){
                            Ok(()) => {},
                            Err(e) => return Err(e)
                        };

                        // Prepare ek_vector decoder
                        let ek_decoder = SimpleDecoder::new(EK_VECTOR_SIZE);

                        // Update state
                        // Transition (6)
                        let state = BraidState::HeaderReceived {hr_epoch: epoch, hr_auth: auth, hr_ek_seed: ek_seed, hr_hek: hek, hr_ek_decoder: ek_decoder };
                        self.state = state;
                    } else {
                        self.state = BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder };
                    }
                } else {
                    self.state = BraidState::NoHeaderReceived { nhr_epoch: epoch, nhr_auth: auth, nhr_header_decoder: header_decoder };
                }
                
                Ok((receiving_epoch, output_key))
            },
            BraidState::HeaderReceived { hr_epoch: epoch, hr_auth: auth, hr_ek_seed: ek_seed, hr_hek: hek, hr_ek_decoder: ek_decoder } => {
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch - 1;

                self.state = BraidState::HeaderReceived { hr_epoch: epoch, hr_auth: auth, hr_ek_seed: ek_seed, hr_hek: hek, hr_ek_decoder: ek_decoder };
    
                Ok((receiving_epoch, output_key))
            
            },
            BraidState::Ct1Sampled { ct1s_epoch: epoch, ct1s_auth: auth, ct1s_encaps_secret: encaps_secret, ct1s_ct1: ct1, ct1s_hek: hek, ct1s_ek_seed: ek_seed, ct1s_ek_decoder: ek_decoder, ct1s_ct1_encoder: ct1_encoder } => {
                let mut ek_decoder = ek_decoder;
                let mut auth = auth;
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch - 1;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::Ek) {
                    match msg.data {
                        Some(chunk) => {
                            hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                            ek_decoder.add_chunk(chunk);
                        },
                        None => return Err("Couldn't find the message data")
                    }
                    

                    if ek_decoder.has_message() {
            
                        let ek_vector_vec = match ek_decoder.message(){
                            Some(ek_vec) => ek_vec,
                            None => return Err("Couldn't find the ek vec")
                        };
                        hax_lib::assume!(ek_vector_vec.len() >= EK_VECTOR_SIZE);
                        let ek_vector: [u8; EK_VECTOR_SIZE] = extract_chunk::<EK_VECTOR_SIZE>(&ek_vector_vec, 0);
            
                        let ek_seed:[u8; EK_SEED_SIZE] = ek_seed.clone();

                        let concat: [u8; EK_SEED_SIZE + 32] = helper_func::concat(ek_seed, hek);

                        match libcrux_ml_kem_validate(&concat, &ek_vector) {
                            Ok(()) => {},
                            Err(e) => return Err(e)
                        }

                        let state = BraidState::EkReceivedCt1Sampled { 
                            ekrct1s_epoch: epoch,
                            ekrct1s_auth: auth,
                            ekrct1s_encaps_secret: encaps_secret, 
                            ekrct1s_ek_vector: ek_vector,
                            ekrct1s_ek_seed: ek_seed,
                            ekrct1s_ct1: ct1,
                            ekrct1s_ct1_encoder: ct1_encoder.clone() 
                        };
                        self.state = state;
                    } else {
                        self.state = BraidState::Ct1Sampled { ct1s_epoch: epoch, ct1s_auth: auth, ct1s_encaps_secret: encaps_secret, ct1s_ct1: ct1, ct1s_hek: hek, ct1s_ek_seed: ek_seed, ct1s_ek_decoder: ek_decoder, ct1s_ct1_encoder: ct1_encoder };
                    }
                } else if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::EkCt1Ack) {
                    match msg.data {
                        Some(chunk) => {
                            hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);                            
                            ek_decoder.add_chunk(chunk);
                        },
                        None => return Err("Couldn't find the message data")
                    }

                    if ek_decoder.has_message() {
                        let ek_vector_vec = match ek_decoder.message(){
                            Some(ek_vec) => ek_vec,
                            None => return Err("Couldn't find the ek vec")
                        };
                        hax_lib::assume!(ek_vector_vec.len() >= EK_VECTOR_SIZE);
                        let ek_vector: [u8; EK_VECTOR_SIZE] = extract_chunk::<EK_VECTOR_SIZE>(&ek_vector_vec, 0);

                        let ek_seed: [u8; EK_SEED_SIZE] =   ek_seed.clone();

                        let concat: [u8; EK_SEED_SIZE + 32] = helper_func::concat(ek_seed,hek);

                        match libcrux_ml_kem_validate(&concat, &ek_vector) {
                            Ok(()) => {},
                            Err(e) => return Err(e)
                        }

                        let ct2: [u8; CT2_SIZE] = libcrux_ml_kem_encapsulate_2(&encaps_secret,&ek_vector);
            
                        let ct:[u8; CT1_SIZE + CT2_SIZE]  = helper_func::concat(ct1, ct2);

                        let mac: [u8; MAC_SIZE] = auth.mac_ct(epoch, ct)?;
                        let concat_ct2_mac: [u8; CT2_SIZE+MAC_SIZE] = helper_func::concat(ct2, mac);

                        
                        let ct2_encoder = SimpleEncoder::new(&concat_ct2_mac, CHUNK_SIZE);

                        let state = BraidState::Ct2Sampled {ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder };
                        self.state = state;
                    } else {
                        let state = BraidState::Ct1Acknowledged { 
                            ct1a_epoch: epoch,
                            ct1a_auth: auth,
                            ct1a_encaps_secret: encaps_secret, 
                            ct1a_ct1: ct1,
                            ct1a_hek: hek,
                            ct1a_ek_seed: ek_seed,
                            ct1a_ek_decoder: ek_decoder.clone(),
                        };

                        self.state = state;
                    }
                } else {
                    self.state = BraidState::Ct1Sampled { ct1s_epoch: epoch, ct1s_auth: auth, ct1s_encaps_secret: encaps_secret, ct1s_ct1: ct1, ct1s_hek: hek, ct1s_ek_seed: ek_seed, ct1s_ek_decoder: ek_decoder, ct1s_ct1_encoder: ct1_encoder };
                }
                Ok((receiving_epoch, output_key))
            },

            BraidState::EkReceivedCt1Sampled { ekrct1s_epoch: epoch, ekrct1s_auth: auth, ekrct1s_encaps_secret: encaps_secret, ekrct1s_ek_vector: ek_vector, ekrct1s_ek_seed: ek_seed, ekrct1s_ct1: ct1, ekrct1s_ct1_encoder: ct1_encoder } => {
                let mut auth = auth;
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch - 1;
                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::EkCt1Ack) {
                    let ct2: [u8; CT2_SIZE] = libcrux_ml_kem_encapsulate_2(&encaps_secret, &ek_vector);

                    let ct: [u8; CT2_SIZE + CT1_SIZE] = helper_func::concat(ct1, ct2);

                    let mac: [u8; MAC_SIZE] = auth.mac_ct(epoch, ct)?;

                    let concat_ct2_mac: [u8; CT2_SIZE + MAC_SIZE] = helper_func::concat(ct2, mac);

                    

                    let ct2_encoder = SimpleEncoder::new(&concat_ct2_mac, CHUNK_SIZE);

                    let state = BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder };
                    self.state = state;
                } else {
                    self.state = BraidState::EkReceivedCt1Sampled { ekrct1s_epoch: epoch, ekrct1s_auth: auth, ekrct1s_encaps_secret: encaps_secret, ekrct1s_ek_vector: ek_vector, ekrct1s_ek_seed: ek_seed, ekrct1s_ct1: ct1, ekrct1s_ct1_encoder: ct1_encoder };
                }

                Ok((receiving_epoch, output_key))
            },

            BraidState::Ct1Acknowledged { ct1a_epoch: epoch, ct1a_auth: auth, ct1a_encaps_secret: encaps_secret, ct1a_ct1: ct1, ct1a_hek: hek, ct1a_ek_seed: ek_seed, ct1a_ek_decoder: ek_decoder } => {
                let mut ek_decoder = ek_decoder;
                let mut auth = auth;
                let output_key = None;
                hax_lib::assume!(epoch >= 1);
                let receiving_epoch = epoch - 1;

                if msg.epoch == epoch && msg.message_type == Some(SCKAMessageType::EkCt1Ack) {
                    // Add chunk to decoder
                    match msg.data {
                        
                        Some(chunk) => {
                            hax_lib::assume!(chunk.data.len() < usize::MAX && chunk.data.len() > 0);
                            ek_decoder.add_chunk(chunk)
                        },
                        None => {}
                    }

                    if ek_decoder.has_message() {
                        let ek_vector_vec = match ek_decoder.message(){
                            Some(ek_vec) => ek_vec,
                            None => return Err("Could not get the ek vec")
                        };
                        
                        hax_lib::assume!(ek_vector_vec.len() >= EK_VECTOR_SIZE);
                        let ek_vector: [u8; EK_VECTOR_SIZE] = extract_chunk::<EK_VECTOR_SIZE>(&ek_vector_vec, 0);

                        let mut header = [0u8; EK_SEED_SIZE + 32];
                        header[..EK_SEED_SIZE].copy_from_slice(&ek_seed);
                        header[EK_SEED_SIZE..].copy_from_slice(&hek);
                        
                        match libcrux_ml_kem_validate(&header, &ek_vector) {
                            Ok(()) => {},
                            Err(e) => return Err(e)
                        }

                        let ct2: [u8; CT2_SIZE] = libcrux_ml_kem_encapsulate_2(&encaps_secret,&ek_vector);            
                        let ct: [u8; CT1_SIZE + CT2_SIZE] = helper_func::concat(ct1, ct2);

                        let mac: [u8; MAC_SIZE] = auth.mac_ct(epoch, ct)?;

                        let concat_ct2_mac: [u8; CT2_SIZE + MAC_SIZE] = helper_func::concat(ct2, mac);

                        

                        let ct2_encoder = SimpleEncoder::new(&concat_ct2_mac, CHUNK_SIZE);

                        let state = BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder };
                        self.state = state;

                    } else {
                        self.state = BraidState::Ct1Acknowledged { ct1a_epoch: epoch, ct1a_auth: auth, ct1a_encaps_secret: encaps_secret, ct1a_ct1: ct1, ct1a_hek: hek, ct1a_ek_seed: ek_seed, ct1a_ek_decoder: ek_decoder };
                    }
                } else {
                    self.state = BraidState::Ct1Acknowledged { ct1a_epoch: epoch, ct1a_auth: auth, ct1a_encaps_secret: encaps_secret, ct1a_ct1: ct1, ct1a_hek: hek, ct1a_ek_seed: ek_seed, ct1a_ek_decoder: ek_decoder };
                }

                Ok((receiving_epoch, output_key))
            },

            BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder } => {
                let output_key = None;       
                hax_lib::assert!(epoch < u64::MAX);         
                if msg.epoch == epoch + 1 {
                    
                    let state = BraidState::KeysUnsampled{ku_epoch: epoch + 1, ku_auth: auth};
                    
                    self.state = state;

                    return Ok((epoch, output_key))
                } else {
                    hax_lib::assert!(epoch >= 1);

                    self.state = BraidState::Ct2Sampled { ct2s_epoch: epoch, ct2s_auth: auth, ct2s_ct2_encoder: ct2_encoder };

                    return Ok((epoch - 1, output_key))
                };
            }
        }
    }
}


#[cfg(test)]
#[cfg(not(hax))]
mod tests {
    use crate::ml_kem_braid::ml_kem_braid_impl::{MlKemBraid, SHARED_SECRET_SIZE};
    use crate::util::messages::SCKAMessageType;

    // Helper: shared secret for initializing both sides
    fn test_ss<'a> () -> &'a[u8; SHARED_SECRET_SIZE] {
        &[42u8; 32]
    }

    // ── Initialization ────────────────────────────────────────────────────────

    #[test]
    fn initiator_starts_in_keys_unsampled() {
        // After init, the initiator should be ready to send a header (KeysUnsampled)
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let (msg,( sending_epoch, output_key)) = alice.send().expect("Couldn't send the message");

        // First send from KeysUnsampled should produce a Hdr message
        assert_eq!(msg.message_type, Some(SCKAMessageType::Hdr));
        assert!(output_key.is_none());
    }

    #[test]
    fn responder_starts_in_no_header_received() {
        // Responder starts waiting for a header — send should produce no data
        let mut bob = MlKemBraid::init_responder(test_ss());
        let (msg, (_epoch, output_key)) = bob.send().expect("Couldn't send the message");

        assert_eq!(msg.message_type, None);
        assert!(output_key.is_none());
    }

    #[test]
    fn epoch_starts_at_one_for_initiator() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let (msg, (sending_epoch, _)) = alice.send().expect("Couldn't send the message");

        // sending_epoch is epoch - 1, and epoch starts at 1, so sending_epoch = 0
        assert_eq!(sending_epoch, 0);
        assert_eq!(msg.epoch, 1);
    }

    #[test]
    fn epoch_starts_at_one_for_responder() {
        let mut bob = MlKemBraid::init_responder(test_ss());
        let (msg, (sending_epoch, _)) = bob.send().expect("Couldn't send the message");

        assert_eq!(sending_epoch, 0);
        assert_eq!(msg.epoch, 1);
    }

    // ── Header transmission (Transition 1 → KeysSampled) ─────────────────────

    #[test]
    fn initiator_sends_header_chunks_until_complete() {
        let mut alice = MlKemBraid::init_initiator(test_ss());

        let mut bob = MlKemBraid::init_responder(test_ss());

        // Header is 96 bytes, chunk size is 32 — so exactly 3 chunks
        let (msg1,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(msg1.message_type, Some(SCKAMessageType::Hdr));

        let (msg2,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(msg2.message_type, Some(SCKAMessageType::Hdr));

        let (msg3,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(msg3.message_type, Some(SCKAMessageType::Hdr));

        let _ = bob.receive(msg1);
        let _ = bob.receive(msg2);
        let _= bob.receive(msg3);
        alice.receive(bob.send().expect("Should send").0).unwrap();

        let (msg4,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_ne!(msg4.message_type, Some(SCKAMessageType::Hdr));
    }

    #[test]
    fn header_chunks_carry_correct_epoch() {
        let mut alice = MlKemBraid::init_initiator(test_ss());

        let (msg1,( _, _)) = alice.send().expect("Couldn't send the message");
        let (msg2,( _, _)) = alice.send().expect("Couldn't send the message");

        assert_eq!(msg1.epoch, 1);
        assert_eq!(msg2.epoch, 1);
    }

    // ── Ct1 reception triggers transition to HeaderSent (Transition 2) ───────

    #[test]
    fn initiator_transitions_to_header_sent_on_receiving_ct1() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Alice sends both header chunks to Bob
        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let hdr2 = alice.send().expect("Couldn't send the message").0;
        let hdr3 = alice.send().expect("Couldn't send the message").0;
        bob.receive(hdr1).unwrap();
        bob.receive(hdr2).unwrap();
        bob.receive(hdr3).unwrap();

        // Bob now sends ct1 back — Alice should transition to HeaderSent
        let (ct1_msg,( _, output_key)) = bob.send().expect("Couldn't send the message");
        assert_eq!(ct1_msg.message_type, Some(SCKAMessageType::Ct1));

        // Alice receives ct1 — transitions KeysSampled → HeaderSent
        alice.receive(ct1_msg).unwrap();

        // Alice should now be sending the ek_vector
        let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(ek_msg.message_type, Some(SCKAMessageType::Ek));
    }

    // ── Full header + EK exchange produces output key on Bob's side ───────────

    #[test]
    fn bob_produces_output_key_after_encapsulating_ct1() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Alice sends header chunks
        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let hdr2 = alice.send().expect("Couldn't send the message").0;
        let hdr3 = alice.send().expect("Couldn't send the message").0;

        bob.receive(hdr1).unwrap();
        bob.receive(hdr2).unwrap();
        bob.receive(hdr3).unwrap();

        // Bob sends ct1 — this is where Bob produces the output key (HeaderReceived → Ct1Sampled)
        let (ct1_msg,( _, output_key)) = bob.send().expect("Couldn't send the message");
        
        assert_eq!(ct1_msg.message_type, Some(SCKAMessageType::Ct1));
        assert!(output_key.is_some(), "Bob should produce an output key when sending ct1");

        let key = output_key.unwrap();
        assert_eq!(key.epoch, 1);
        assert_ne!(key.key, [0u8; 32], "Output key should not be all zeros");
    }

    #[test]
    fn output_key_epoch_is_correct() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let hdr2 = alice.send().expect("Couldn't send the message").0;
        let hdr3 = alice.send().expect("Couldn't send the message").0;
        bob.receive(hdr1).unwrap();
        bob.receive(hdr2).unwrap();
        bob.receive(hdr3).unwrap();

        let (_,( _, output_key)) = bob.send().expect("Couldn't send the message");
        let key = output_key.unwrap();
        assert_eq!(key.epoch, 1);
    }

    // ── EK vector transmission and integrity check ────────────────────────────

    #[test]
    fn alice_sends_ek_vector_after_receiving_ct1() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let hdr2 = alice.send().expect("Couldn't send the message").0;
        let hdr3 = alice.send().expect("Couldn't send the message").0;
        
        bob.receive(hdr1).unwrap();
        bob.receive(hdr2).unwrap();
        bob.receive(hdr3).unwrap();

        let ct1_msg = bob.send().expect("Couldn't send the message").0;
        alice.receive(ct1_msg).unwrap();

        // Alice should now be in HeaderSent, sending ek_vector chunks
        let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(
                ek_msg.message_type,
                Some(SCKAMessageType::Ek),
                "Testing message_type: {:?}, should be {:?}",
                ek_msg.message_type,
                SCKAMessageType::Ek
            );
    }

    #[test]
    fn ek_integrity_check_fails_with_wrong_data() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let hdr2 = alice.send().expect("Couldn't send the message").0;
        let hdr3 = alice.send().expect("Couldn't send the message").0;
        bob.receive(hdr1).unwrap();
        bob.receive(hdr2).unwrap();
        bob.receive(hdr3).unwrap();

        let ct1_msg = bob.send().expect("Couldn't send the message").0;
        alice.receive(ct1_msg).unwrap();

        // Collect all ek chunks first
        let mut ek_chunks = vec![];
        for _ in 0..36 {
            let (msg,( _, _)) = alice.send().expect("Couldn't send the message");
            if msg.message_type == Some(SCKAMessageType::Ek) {
                ek_chunks.push(msg);
            } else {
                break;
            }
        }

        // Send all but the last chunk uncorrupted
        for msg in ek_chunks.iter().take(ek_chunks.len() - 1) {
            bob.receive(msg.clone()).unwrap();
        }

        // Corrupt the last chunk so the decoder completes with bad data
        let mut last = ek_chunks.into_iter().last().unwrap();
        if let Some(ref mut chunk) = last.data {
            chunk.data[0] ^= 0xFF;
        }

        // Bob should reject the corrupted ek_vector
        let result = bob.receive(last);
        assert!(result.is_err(), "Corrupted EK should fail integrity check");
    }

    // ── Full handshake: Alice produces ct2, Alice decapsulates ───────────────

    #[test]
    fn full_handshake_completes_and_alice_gets_output_key_left_path() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Step 1: Alice sends header (3 chunks)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        // Step 2: Bob sends all 30 ct1 chunks; Alice transitions to HeaderSent
        // on receiving the last one (ct1 is 960 bytes / 32 = 30 chunks) 
        for _ in 0..30 {
            let ct1_chunk = bob.send().expect("Couldn't send the message").0;
            alice.receive(ct1_chunk).unwrap();
        }

        // Step 3: Alice (now in HeaderSent or Ct1Received) sends all 36 ek chunks;
        // Bob verifies integrity and encapsulates ct2
        // ek_vector is 1152 bytes / 32 = 36 chunks
        let mut bob_output_key = None;
        for _ in 0..36 {
            let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
            if ek_msg.message_type.is_none() { break; }
            let (_, key) = bob.receive(ek_msg).unwrap();
            if key.is_some() {
                bob_output_key = key;
            }
        }

        // Step 4: Bob sends ct2 (160 bytes / 32 ceil = 6 chunks); Alice decapsulates
        let mut alice_output_key = None;
        for _ in 0..6 {
            let (ct2_msg,( _, _)) = bob.send().expect("Couldn't send the message");
            if ct2_msg.message_type != Some(SCKAMessageType::Ct2) { break; }
            let (_, key) = alice.receive(ct2_msg).unwrap();
            if key.is_some() {
                alice_output_key = key;
            }
        }

        assert!(alice_output_key.is_some(), "Alice should get an output key after full handshake");
        assert!(bob_output_key.is_some() || alice_output_key.is_some(),
            "At least one side should have produced an output key");
    }

    #[test]
    fn handshake_center_path_ek_completes() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Alice sends header (3 chunks)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        // Bob sends first ct1 chunk → Alice enters HeaderSent
        alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();

        // Pre-send 2 Ek chunks to Bob before ct1 exchange.
        // Bob accumulates 2 Ek chunks, Alice is HeaderSent.
        for _ in 0..6 {
            let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
            assert_eq!(ek_msg.message_type, Some(SCKAMessageType::Ek));
            bob.receive(ek_msg).unwrap();
        }
        // Bob: 2 Ek chunks. Alice: 1/30 ct1 received, HeaderSent, 34/36 ek remaining.

        // 28 parallel rounds: Alice receives ct1 chunk first, then sends Ek.
        // After this loop: Alice has received chunks 1+28=29 of 30 ct1 → still HeaderSent.
        // Bob has 6+28=34 Ek chunks.
        for _ in 0..28 {
            alice.receive(bob.send().expect("Couldn't send the message").0).unwrap(); // ct1 chunk to Alice
            let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");    // Alice still HeaderSent → Ek
            assert_eq!(ek_msg.message_type, Some(SCKAMessageType::Ek),
                "Alice should be HeaderSent, sending Ek");
            bob.receive(ek_msg).unwrap();
        }
        // Alice: 29/30 ct1 chunks, still HeaderSent. Bob: 34 Ek chunks.

        // Deliver the 30th (final) ct1 chunk to Alice → she transitions to Ct1Received.
        // Then send 1 more Ek chunk to Bob to bring him to 35 total.
        // Order matters: send ek first (Alice still HeaderSent), THEN deliver ct1.
        let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(ek_msg.message_type, Some(SCKAMessageType::Ek),
            "Alice should still be HeaderSent before receiving final ct1 chunk");
        alice.receive(bob.send().expect("Couldn't send the message").0).unwrap(); // 30th ct1 chunk → Alice now Ct1Received
        bob.receive(ek_msg).unwrap();         // Bob now has 35 Ek chunks
        // Bob: 35 Ek chunks, ek_decoder at 35/36, still Ct1Sampled.
        // Alice: Ct1Received.

        // The 24th and final chunk: Alice sends EkCt1Ack (she's Ct1Received).
        // This completes Bob's ek_decoder while he's still in Ct1Sampled
        // → transition 9 directly to Ct2Sampled (center path).
        let (last_ek,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(last_ek.message_type, Some(SCKAMessageType::EkCt1Ack),
            "Alice should be Ct1Received now, sending EkCt1Ack");
        bob.receive(last_ek).unwrap();

        assert_eq!(bob.state.to_string(), "Ct2Sampled(epoch=1)",
            "Bob must reach Ct2Sampled via center path (transition 9 from Ct1Sampled)");

        // Bob sends ct2 (3 chunks), Alice decapsulates
        let mut alice_output_key = None;
        for _ in 0..5 {
            let (ct2_msg,( _, _)) = bob.send().expect("Couldn't send the message");
            if ct2_msg.message_type != Some(SCKAMessageType::Ct2) { break; }
            let (_, key) = alice.receive(ct2_msg).unwrap();
            if key.is_some() { alice_output_key = key; }
        }
        assert!(alice_output_key.is_some(), "Alice should get output key via center path");
    }

    // PATH 3 (Right-top): ek arrives fully while Alice is still in HeaderSent
    // (before ct1 is complete) → HeaderSent,EkReceivedCt1Sampled → Ct1Received,EkReceivedCt1Sampled
    #[test]
    fn handshake_right_top_path_ek_received_before_ct1_complete() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Header
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        // Bob sends first ct1 chunk only — Alice transitions to HeaderSent
        alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        // Alice is now HeaderSent — send ALL 36 ek chunks as Ek before ct1 is done
        // Bob receives full ek_vector → transitions Ct1Sampled → EkReceivedCt1Sampled
        for _ in 0..36 {
            let (ek_msg,( _, _)) = alice.send().expect("Couldn't send the message");
            assert_eq!(ek_msg.message_type, Some(SCKAMessageType::Ek),
                "Alice should send Ek type since ct1 not yet fully received");
            bob.receive(ek_msg).unwrap();
        }

        
        // Bob is now EkReceivedCt1Sampled — Alice sends remaining 29 ct1 chunks
        // plus EkCt1Ack; when Bob sees EkCt1Ack he computes ct2
        for _ in 0..29 {
            alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        }
        // Alice is now Ct1Received — next send is EkCt1Ack (but ek already sent,
        // so Alice sends a no-data EkCt1Ack or transitions; Bob triggers ct2)
        // Send one EkCt1Ack to signal ct1 acknowledgment
        let (ack_msg,( _, _)) = alice.send().expect("Couldn't send the message");
        assert_eq!(ack_msg.message_type, Some(SCKAMessageType::EkCt1Ack));
        bob.receive(ack_msg).unwrap();

        // Bob should now be Ct2Sampled
        let mut alice_output_key = None;
        for _ in 0..5 {
            let (ct2_msg,( _, _)) = bob.send().expect("Couldn't send the message");
            if ct2_msg.message_type != Some(SCKAMessageType::Ct2) { break; }
            let (_, key) = alice.receive(ct2_msg).unwrap();
            if key.is_some() { alice_output_key = key; }
        }
        assert!(alice_output_key.is_some(), "Alice should get output key via right-top path");
    }

    // PATH 4 (Right-bottom): ek arrives fully after ct1 complete but before ack triggers ct2
    // Ct1Received,Ct1Sampled → Ct1Received,EkReceivedCt1Sampled → Ct1Received,Ct2Sampled
    #[test]
    fn handshake_right_bottom_path_ek_received_after_ct1_before_ack() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // (KeysUnsampled, NoHeaderReceived)
        // Alice KeysUnsampled => Bob NoHeaderReceived
        // (KeysSampled, NoHeaderReceived)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        
        // (KeysSampled, NoHeaderReceived)
        // Alice KeysSampled => Bob NoHeaderReceived
        // (KeysSampled, NoHeaderReceived)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        // (KeysSampled, NoHeaderReceived)
        // Alice KeysSampled => Bob NoHeaderReceived
        // (KeysSampled, HeaderReceived)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        
        // (KeysSampled, HeaderReceived)
        // Bob HeaderReceived => Alice KeysSampled
        // (HeaderSent, Ct1Sampled)
        let (msg_bob_header_received,( _, bob_key)) = bob.send().expect("Couldn't send the message");
        alice.receive(msg_bob_header_received).unwrap();

        // Alice sends all ek messages, but bob receives all but the last one
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => Bob Ct1Sampled
        // (HeaderSent, Ct1Sampled)
        for _ in 0..35 {
            bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        }
        
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => 
        // (HeaderSent, Ct1Sampled)
        let (alice_last_msg_headersent_state,( _, _)) = alice.send().expect("Couldn't send the message");

        // (HeaderSent, Ct1Sampled)
        // Bob Ct1Sampled => Alice HeaderSent
        // (Ct1Received, Ct1Sampled)
        for _ in 0..29 {
            alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        }

        
        // (Ct1Received, Ct1Sampled)
        //  => Bob Ct1Sampled
        // (Ct1Received, EkReceivedCt1Sampled)
        bob.receive(alice_last_msg_headersent_state).unwrap();

        // (Ct1Received, EkReceivedCt1Sampled)
        //  Alice Ct1Received => Bob EkRecievedCt1Sampled
        // (Ct1Received, Ct2Sampled)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();


        // (Ct1Received, Ct2Sampled)
        //  Bob Ct2Sampled => 
        // (Ct1Received, Ct2Sampled)
        let (last_bob_msg,( _, _)) = bob.send().expect("Couldn't send the message");
        assert_eq!(last_bob_msg.message_type, Some(SCKAMessageType::Ct2));
        
        // (Ct1Received, Ct2Sampled)
        //  => Alice Ct1Received 
        // (EkSentCt1Received, Ct2Sampled)
        alice.receive(last_bob_msg).unwrap();
        
        // (EkSentCt1Received, Ct2Sampled)
        //  Bob Ct2Sampled => Alice EkSentCt1Received 
        // (NoHeaderReceived, Ct2Sampled)
        for _ in 0..3 {
            alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        }
        
        let (_, alice_output_key) = alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        
        assert!(alice_output_key.is_some(), "Alice should get output key via right-bottom path");

        assert!(bob_key.is_some(), "Bob should get output key via right-bottom path");

        assert_eq!(alice_output_key.unwrap().key, bob_key.unwrap().key);
        
    }

    #[test]
    fn both_sides_produce_same_output_key() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());


        // Alice sends header (3 chunks)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        // Bob sends first ct1 chunk — produces output key, Alice transitions to HeaderSent
        let (ct1_msg,( _, bob_key_opt)) = bob.send().expect("Couldn't send the message");

        let bob_key = bob_key_opt.expect("Bob should produce key on first ct1 send");
        alice.receive(ct1_msg).unwrap();

        // Remaining 29 ct1 chunks and 29 ek chunks sent in parallel
        for _ in 0..29 {

            let bob_msg = bob.send().expect("Couldn't send the message").0;

            alice.receive(bob_msg).unwrap();

            bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        }
        
    
        // 36-29 = 7
        // Alice sends remaining 7 ek chunks with EkCt1Ack (she's now in Ct1Received)
        for _ in 0..7 {
            bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        }
        

        
        
        
        


        // Bob sends ct2 (3 chunks), Alice decapsulates
        let mut alice_key = None;
        for _ in 0..5 {
            let (_, key) = alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
            if key.is_some() { alice_key = key; }
        }

        let alice_key = alice_key.expect("Alice should produce an output key");
        assert_eq!(alice_key.key, bob_key.key, "Both sides must derive the same shared key");
    }

    // ── Epoch advancement ─────────────────────────────────────────────────────

    #[test]
    fn epoch_increments_after_full_handshake_on_alice_side() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // (KeysUnsampled, NoHeaderReceived)
        // Alice KeysUnsampled => Bob NoHeaderReceived
        // (KeysSampled, NoHeaderReceived)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        
        // (KeysSampled, NoHeaderReceived)
        // Alice KeysSampled => Bob NoHeaderReceived
        // (KeysSampled, HeaderReceived)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        
        // (KeysSampled, HeaderReceived)
        // Bob HeaderReceived => Alice KeysSampled
        // (HeaderSent, Ct1Sampled)
        let (msg_bob_header_received,( _, _bob_key)) = bob.send().expect("Couldn't send the message");
        alice.receive(msg_bob_header_received).unwrap();

        // Alice sends all ek messages, but bob receives all but the last one
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => Bob Ct1Sampled
        // (HeaderSent, Ct1Sampled)
        for _ in 0..35 {
            bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();
        }
        
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => 
        // (HeaderSent, Ct1Sampled)
        let (alice_last_msg_headersent_state,( _, _)) = alice.send().expect("Couldn't send the message");

        // (HeaderSent, Ct1Sampled)
        // Bob Ct1Sampled => Alice HeaderSent
        // (Ct1Received, Ct1Sampled)
        for _ in 0..30 {
            alice.receive(bob.send().expect("Couldn't send the message").0).unwrap();
        }

        
        // (Ct1Received, Ct1Sampled)
        //  => Bob Ct1Sampled
        // (Ct1Received, EkReceivedCt1Sampled)
        bob.receive(alice_last_msg_headersent_state).unwrap();

        // (Ct1Received, EkReceivedCt1Sampled)
        //  Alice Ct1Received => Bob EkRecievedCt1Sampled
        // (Ct1Received, Ct2Sampled)
        bob.receive(alice.send().expect("Couldn't send the message").0).unwrap();

        let mut alice_epoch_after = 0u64;
        for _ in 0..30 {
            let (ct2_msg,( _, _)) = bob.send().expect("Couldn't send the message");
            if ct2_msg.message_type != Some(SCKAMessageType::Ct2) { break; }
            let (epoch, key) = alice.receive(ct2_msg).unwrap();

            if key.is_some() {
                alice_epoch_after = epoch + 1; // epoch has incremented
                break;
            }
        }


        assert!(alice_epoch_after >= 1, "Epoch should have advanced after handshake");
    }

    // ── No output key before handshake completes ──────────────────────────────

    #[test]
    fn no_output_key_before_handshake_completes() {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // Only send the first header chunk — handshake incomplete
        let hdr1 = alice.send().expect("Couldn't send the message").0;
        let (receiving_epoch, output_key) = bob.receive(hdr1).unwrap();

        assert!(output_key.is_none(), "No output key should be produced mid-handshake");
    }

    #[test]
    fn different_shared_secrets_produce_different_output_keys() {
        let mut alice1 = MlKemBraid::init_initiator(&[1u8; 32]);
        let mut bob1   = MlKemBraid::init_responder(&[1u8; 32]);

        let mut alice2 = MlKemBraid::init_initiator(&[2u8; 32]);
        let mut bob2   = MlKemBraid::init_responder(&[2u8; 32]);

        // Run both handshakes to the point where Bob produces a key
        fn run_to_bob_key(alice: &mut MlKemBraid, bob: &mut MlKemBraid) -> [u8; 32] {
            let hdr1 = alice.send().expect("Couldn't send the message").0;
            let hdr2 = alice.send().expect("Couldn't send the message").0;
            let hdr3 = alice.send().expect("Couldn't send the message").0;
            bob.receive(hdr1).unwrap();
            bob.receive(hdr2).unwrap();
            bob.receive(hdr3).unwrap();
            let (_,( _, key)) = bob.send().expect("Couldn't send the message");
            key.expect("Bob should produce key").key
        }

        let key1 = run_to_bob_key(&mut alice1, &mut bob1);
        let key2 = run_to_bob_key(&mut alice2, &mut bob2);

        assert_ne!(key1, key2, "Different initial secrets must produce different output keys");
    }

    #[test]
    fn epochs_throughout_the_execution () {
        let mut alice = MlKemBraid::init_initiator(test_ss());
        let mut bob = MlKemBraid::init_responder(test_ss());

        // (KeysUnsampled, NoHeaderReceived)
        // Alice KeysUnsampled => Bob NoHeaderReceived
        // (KeysSampled, NoHeaderReceived)
        let (a_msg_1, (a_epoch_1, _)) = alice.send().expect("Couldn't send the message");
        let (b_epoch_1, _) = bob.receive(a_msg_1).unwrap();

        let (a_msg_1, (a_epoch_1, _)) = alice.send().expect("Couldn't send the message");
        let (b_epoch_1, _) = bob.receive(a_msg_1).unwrap();
        
        // (KeysSampled, NoHeaderReceived)
        // Alice KeysSampled => Bob NoHeaderReceived
        // (KeysSampled, HeaderReceived)
        let (a_msg_2, (a_epoch_2, _)) = alice.send().expect("Couldn't send the message");
        let (b_epoch_2, _) = bob.receive(a_msg_2).unwrap();
        
        // (KeysSampled, HeaderReceived)
        // Bob HeaderReceived => Alice KeysSampled
        // (HeaderSent, Ct1Sampled)
        let (msg_bob_header_received, (b_epoch_3, bob_key)) = bob.send().expect("Couldn't send the message");
        let (a_epoch_3, _) =alice.receive(msg_bob_header_received).unwrap();

        // Alice sends all ek messages, but bob receives all but the last one
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => Bob Ct1Sampled
        // (HeaderSent, Ct1Sampled)
        for _ in 1..36 {
            let (a_msg_1_loop,( a_epoch_1_loop, _)) = alice.send().expect("Couldn't send the message");

            let (b_epoch_1_loop, _) = bob.receive(a_msg_1_loop).unwrap();

        }
        
        // (HeaderSent, Ct1Sampled)
        // Alice HeaderSent => 
        // (HeaderSent, Ct1Sampled)
        let (alice_last_msg_headersent_state,( a_epoch_4, _)) = alice.send().expect("Couldn't send the message");

        // (HeaderSent, Ct1Sampled)
        // Bob Ct1Sampled => Alice HeaderSent
        // (Ct1Received, Ct1Sampled)
        for _ in 1..30 {
            let (b_msg_2_loop,( b_epoch_2_loop, bob_key)) = bob.send().expect("Couldn't send the message");

            let (a_epoch_2_loop, _) =alice.receive(b_msg_2_loop).unwrap();

        }

        
        // (Ct1Received, Ct1Sampled)
        //  => Bob Ct1Sampled
        // (Ct1Received, EkReceivedCt1Sampled)
        let (b_epoch_4, _) = bob.receive(alice_last_msg_headersent_state).unwrap();

        // (Ct1Received, EkReceivedCt1Sampled)
        //  Alice Ct1Received => Bob EkRecievedCt1Sampled
        // (Ct1Received, Ct2Sampled)
        let (a_msg_5,( a_epoch_5, _)) = alice.send().expect("Couldn't send the message");
        let (b_epoch_5, _) = bob.receive(a_msg_5).unwrap();

        // (Ct1Received, Ct2Sampled)
        //  Bob Ct2Sampled => 
        // (Ct1Received, Ct2Sampled)
        let (last_bob_msg,( b_epoch_6, _)) = bob.send().expect("Couldn't send the message");
        assert_eq!(last_bob_msg.message_type, Some(SCKAMessageType::Ct2));
        
        // (Ct1Received, Ct2Sampled)
        //  => Alice Ct1Received 
        // (EkSentCt1Received, Ct2Sampled)
        let (a_epoch_6, _) = alice.receive(last_bob_msg).unwrap();
        
        // (EkSentCt1Received, Ct2Sampled)
        //  Bob Ct2Sampled => Alice EkSentCt1Received 
        // (EkSentReceived, Ct2Sampled)
        for _ in 0..4 {
            let (b_msg_last,( b_epoch_7, bob_key)) = bob.send().expect("Couldn't send the message");
            let (a_epoch_7, _) = alice.receive(b_msg_last).unwrap();
        }

        // (NoHeaderReceived, Ct2Sampled)
        //  Bob Ct2Sampled => Alice NoHeaderReceived 
        // (NoHeader, Ct2Sampled)
        let (b_msg_last_last,( b_epoch_8, bob_key)) = bob.send().expect("Couldn't send the message");
        let (a_epoch_8, _) = alice.receive(b_msg_last_last).unwrap();

        let (a_msg_9,( a_epoch_9, _)) = alice.send().expect("Couldn't send the message");
        let (b_epoch_5, _) = bob.receive(a_msg_9).unwrap();

        let (b_msg_last_last, (b_epoch_8, bob_key)) = bob.send().expect("Couldn't send the message");
        let (a_epoch_8, _) = alice.receive(b_msg_last_last).unwrap();
        assert_eq!(1, b_epoch_8);
        assert_eq!(1, a_epoch_8);

    }
}