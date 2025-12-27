pub fn bytes_split(input: Vec<u8>, chunk_size: i32) -> Vec<Vec<u8>> {
    let mut chunks: Vec<Vec<u8>> = Vec::new(); // ahora Vec<Vec<u8>>
    let total_chunks = input.len() / chunk_size as usize;

    for i in 0..total_chunks {
        let start = i * chunk_size as usize;
        let end = start + chunk_size as usize;

        let chunk_slice = &input[start..end];
        chunks.push(chunk_slice.to_vec()); // convierte &[u8] -> Vec<u8>
    }

    chunks
}
