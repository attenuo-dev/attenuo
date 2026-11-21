//! Reading `text/event-stream` bodies (Server-Sent Events) one event at a time, as they
//! arrive. Used by `init` (the answer to one request) and `connect` (every message of a
//! stream, in order).

/// The first blank line (the end of an SSE event) in `buf` at or after `from`: where the
/// event's text ends, and where the next event starts. A blank line is `\n\n`, or `\n\r\n`
/// when lines end in CRLF.
pub(crate) fn event_end(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while let Some(off) = buf.get(i..)?.iter().position(|b| *b == b'\n') {
        let nl = i + off;
        match buf.get(nl + 1..) {
            Some([b'\n', ..]) => return Some((nl, nl + 2)),
            Some([b'\r', b'\n', ..]) => return Some((nl, nl + 3)),
            _ => i = nl + 1,
        }
    }
    None
}

/// The parts of one SSE event that matter here.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Event {
    /// The `id:` field, if the event has one.
    pub id: Option<String>,
    /// The `data:` lines joined with a line feed, as the SSE format says. `None` when the
    /// event has no `data:` line (a comment, a keep-alive).
    pub data: Option<String>,
}

/// Split one event's text into its fields.
pub(crate) fn parse_event(event: &str) -> Event {
    let mut out = Event::default();
    for line in event.lines() {
        // A last line that ended in CRLF still holds its `\r` here.
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(d) = line.strip_prefix("data:") {
            let d = d.strip_prefix(' ').unwrap_or(d);
            match out.data.as_mut() {
                Some(data) => {
                    data.push('\n');
                    data.push_str(d);
                }
                None => out.data = Some(d.to_string()),
            }
        } else if let Some(id) = line.strip_prefix("id:") {
            out.id = Some(id.strip_prefix(' ').unwrap_or(id).to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_events_end_at_a_blank_line() {
        assert_eq!(event_end(b"data: 1\n\ndata: 2\n\n", 0), Some((7, 9)));
        assert_eq!(event_end(b"data: 1\n\ndata: 2\n\n", 9), Some((16, 18)));
        assert_eq!(event_end(b"data: 1\r\n\r\nrest", 0), Some((8, 11)));
        assert_eq!(event_end(b"event: m\ndata: 1\n\n", 0), Some((16, 18)));
        assert_eq!(event_end(b"data: 1\n", 0), None);
        assert_eq!(event_end(b"data: 1\ndata", 0), None);
        assert_eq!(event_end(b"", 0), None);
        assert_eq!(event_end(b"abc", 7), None);
    }

    #[test]
    fn events_are_split_into_id_and_data() {
        assert_eq!(
            parse_event("id: 7\nevent: message\ndata: {\"a\":\ndata:1}"),
            Event {
                id: Some("7".into()),
                data: Some("{\"a\":\n1}".into())
            }
        );
        assert_eq!(parse_event(": keep-alive"), Event::default());
        assert_eq!(
            parse_event("data: x\r\nid:9\r"),
            Event {
                id: Some("9".into()),
                data: Some("x".into()),
            }
        );
    }
}
