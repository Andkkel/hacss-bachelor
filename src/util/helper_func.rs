#[hax_lib::requires(A <= usize::MAX - B 
            && A + B == C)]
#[hax_lib::ensures(|res| res.len() == C)]
pub(crate) fn concat<const A: usize, const B: usize, const C: usize>(a: [u8; A], b: [u8; B]) -> [u8; C] {
    let mut out = [0u8; C];
    
    for i in 0..A {
        hax_lib::loop_invariant!(|i: usize| i <= A && A + B == C);
        out[i] = a[i];
    }
    
    for i in 0..B {
        hax_lib::loop_invariant!(|i: usize| i <= B && A + i <= C && A + B == C);
        out[A + i] = b[i];
    }
    out
}

#[hax_lib::opaque]
pub(crate) fn make_randomness<const A: usize>() -> [u8; A]
where
    [u8; A]: Sized,   
{
    #[cfg(not(hax))]{
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    let mut randomness = [0u8; A];
    StdRng::from_os_rng().fill_bytes(&mut randomness);
    randomness}
    #[cfg(hax)]{
        [0u8; A]
    }
}

#[hax_lib::requires(offset <= src.len() && A <= src.len() - offset)]
#[hax_lib::ensures(|res| res.len() == A)]
pub fn extract_chunk<const A: usize>(src: &[u8], offset: usize) -> [u8; A] {
    hax_lib::assert!(offset <= src.len() && A <= src.len() - offset);
    
    let mut element = [0u8; A];
    
    element.copy_from_slice(&src[offset..offset + A]);
    
    element
} 