use crate::util::messages::Chunk;

// Naive chunker — just collects bytes into fixed-size pieces
// No redundancy, no loss tolerance, sufficient for testing
#[derive(Clone, Debug)]
pub struct SimpleDecoder {
    message_size: usize,
    received:     Vec<u8>,
}

#[hax_lib::attributes]
impl SimpleDecoder {
    #[hax_lib::opaque]
    pub fn new(message_size: usize) -> Self {
        Self { message_size, received: Vec::new() }
    }
    
    #[hax_lib::requires(chunk.data.len() > 0)]
    #[hax_lib::ensures(|res| true)]
    pub(crate) fn add_chunk(&mut self, chunk: Chunk) {
        hax_lib::assume!(self.received.len() < usize::MAX - chunk.data.len());
        self.received.extend_from_slice(&chunk.data);
    }
    
    #[hax_lib::opaque]
    pub(crate) fn has_message(&self) -> bool {
        self.received.len() >= self.message_size
    }
    
    #[hax_lib::opaque]
    pub(crate) fn message(&self) -> Option<Vec<u8>> {
        if self.has_message() {
            let slice: &[u8] = &self.received;          
            Some(slice[..self.message_size].to_vec())
        } else {
            None
        }
    
    }
    #[hax_lib::opaque]
    pub fn size(&self) -> usize {
        8                        // message_size (usize)
        + 24                     // Vec stack size
        + self.received.len()    // heap content
    }
}

