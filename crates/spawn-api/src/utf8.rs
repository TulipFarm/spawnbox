//! Turns a byte stream into UTF-8 text chunks without breaking characters
//! that are split across chunks.

#[derive(Default)]
pub struct Utf8Stream {
    pending: Vec<u8>,
}

impl Utf8Stream {
    /// Text decoded so far. Bytes of an unfinished character are kept for
    /// the next call; invalid bytes become U+FFFD.
    pub fn push(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        let mut out = String::new();
        let mut rest = &self.pending[..];
        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    out.push_str(text);
                    rest = &[];
                    break;
                }
                Err(error) => {
                    let (valid, after) = rest.split_at(error.valid_up_to());
                    out.push_str(&String::from_utf8_lossy(valid));
                    match error.error_len() {
                        Some(len) => {
                            out.push(char::REPLACEMENT_CHARACTER);
                            rest = &after[len..];
                        }
                        // An unfinished character at the end: wait for more.
                        None => {
                            rest = after;
                            break;
                        }
                    }
                }
            }
        }
        self.pending = rest.to_vec();
        out
    }

    /// Text left at the end of the stream.
    pub fn finish(&mut self) -> String {
        let out = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Utf8Stream;

    #[test]
    fn keeps_split_characters_whole() {
        let bytes = "a€b".as_bytes();
        let mut stream = Utf8Stream::default();
        assert_eq!(stream.push(&bytes[..2]), "a");
        assert_eq!(stream.push(&bytes[2..3]), "");
        assert_eq!(stream.push(&bytes[3..]), "€b");
        assert_eq!(stream.finish(), "");
    }

    #[test]
    fn replaces_invalid_bytes_and_truncated_ends() {
        let mut stream = Utf8Stream::default();
        assert_eq!(stream.push(b"a\xffb\xe2\x82"), "a\u{fffd}b");
        assert_eq!(stream.finish(), "\u{fffd}");
    }
}
