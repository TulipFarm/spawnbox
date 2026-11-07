//! A small parser for server-sent events, as `spawn-api` sends them.

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub event: String,
    pub data: String,
    pub id: Option<String>,
}

/// Feed it body chunks; it returns each event once its blank line arrives.
#[derive(Default)]
pub struct Parser {
    line: Vec<u8>,
    current: Event,
    has_data: bool,
}

impl Parser {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Event> {
        let mut done = Vec::new();
        for &byte in chunk {
            if byte != b'\n' {
                self.line.push(byte);
                continue;
            }
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            let line = String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
            if let Some(event) = self.line_done(&line) {
                done.push(event);
            }
        }
        done
    }

    fn line_done(&mut self, line: &str) -> Option<Event> {
        if line.is_empty() {
            let event = std::mem::take(&mut self.current);
            return std::mem::take(&mut self.has_data).then_some(event);
        }
        if line.starts_with(':') {
            return None;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => value.clone_into(&mut self.current.event),
            "id" => self.current.id = Some(value.to_owned()),
            "data" => {
                if self.has_data {
                    self.current.data.push('\n');
                }
                self.current.data.push_str(value);
                self.has_data = true;
            }
            _ => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_events_split_across_chunks() {
        let mut parser = Parser::default();
        assert!(parser.push(b": keep-alive\n\nevent: std").is_empty());
        let events = parser.push(b"out\r\ndata: {\"text\":\"a\"}\n\nid: 7\ndata: x\ndata: y\n\n");
        assert_eq!(
            events,
            vec![
                Event {
                    event: "stdout".into(),
                    data: "{\"text\":\"a\"}".into(),
                    id: None,
                },
                Event {
                    event: String::new(),
                    data: "x\ny".into(),
                    id: Some("7".into()),
                },
            ]
        );
    }
}
