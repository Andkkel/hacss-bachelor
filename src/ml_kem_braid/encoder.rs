use crate::util::messages::Chunk;

// Naive chunker — just splits bytes into fixed-size pieces
// No redundancy, no loss tolerance, sufficient for testing
#[derive(Clone, Debug)]
pub struct SimpleEncoder {
    pub(crate) chunks: Vec<Chunk>,
}

#[hax_lib::attributes]
impl SimpleEncoder {
    #[hax_lib::opaque]
    #[hax_lib::requires(data.len() < usize::MAX &&
        chunk_size > 0 && chunk_size < usize::MAX
        )]
    #[hax_lib::ensures(|res| res.chunks.len() < usize::MAX)]
    pub fn new(data: &[u8], chunk_size: usize) -> Self {
        let mut chunks = Vec::new();
        let mut index = 0u32;
        let mut offset = 0;

        while offset < data.len() {
            hax_lib::loop_invariant!(offset <= data.len() &&
                                     chunks.len() < usize::MAX);
            hax_lib::loop_decreases!(data.len()-offset);
            hax_lib::assert!(offset < usize::MAX-chunk_size &&
                             chunks.len() < usize::MAX);

            let end = if offset + chunk_size < data.len() {
                    offset + chunk_size
                } else {
                    data.len()
                };
            chunks.push(Chunk {
                index,
                data: data[offset..end].to_vec(),
            });
            hax_lib::assert!(index < u32::MAX-1 && 
                             chunks.len() < usize::MAX);
            index += 1;
            offset += chunk_size;

            //hax_lib::assert!(offset <= data.len());
        }

        Self { chunks }
     }
    
    #[hax_lib::opaque]
    pub(crate) fn next_chunk<'a>(&mut self) -> Result<Chunk, &'a str> {
        if self.chunks.is_empty() {
            return Err("Next_chunk called on empty encoder!");
        }

        Ok(self.chunks.remove(0))
    }
    
    #[hax_lib::opaque]
    pub(crate) fn is_done(&self) -> bool {
        self.chunks.is_empty()
    }
    
    #[hax_lib::opaque]
    pub fn size(&self) -> usize {
        24                       // Vec stack size
        + self.chunks.iter().map(|chunk| {
            4                    // index (u32)
            + 24                 // Vec stack size for data
            + chunk.data.len()   // heap content
        }).sum::<usize>()
    }
}