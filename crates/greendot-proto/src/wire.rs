//! Newline-delimited JSON framing over a byte stream.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, BufRead, Write};

/// Upper bound on a single message line, including the trailing newline.
pub const MAX_LINE: u64 = 256 * 1024;

pub fn write_msg<T: Serialize, W: Write>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut buf = serde_json::to_vec(msg)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Reads one message. Returns `Ok(None)` on clean EOF. Lines longer than
/// [`MAX_LINE`] and truncated lines are errors.
pub fn read_msg<T: DeserializeOwned, R: BufRead>(r: &mut R) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    loop {
        let (newline_at, available) = {
            let buf = r.fill_buf()?;
            (buf.iter().position(|&b| b == b'\n'), buf.len())
        };
        match newline_at {
            _ if available == 0 && line.is_empty() => return Ok(None), // clean EOF
            _ if available == 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated message line",
                ));
            }
            Some(pos) => {
                let buf = r.fill_buf()?;
                line.extend_from_slice(&buf[..pos]);
                r.consume(pos + 1);
                return Ok(Some(serde_json::from_slice(&line)?));
            }
            None => {
                let buf = r.fill_buf()?;
                line.extend_from_slice(buf);
                r.consume(available);
            }
        }
        if line.len() as u64 >= MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message line exceeds MAX_LINE",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Request, Response};
    use std::io::BufReader;

    #[test]
    fn framing_roundtrip_eof_and_oversize() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Ping).unwrap();
        write_msg(&mut buf, &Response::Ok).unwrap();
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 2);

        let mut r = BufReader::new(buf.as_slice());
        assert_eq!(read_msg::<Request, _>(&mut r).unwrap(), Some(Request::Ping));
        assert_eq!(read_msg::<Response, _>(&mut r).unwrap(), Some(Response::Ok));
        // clean EOF
        assert_eq!(read_msg::<Request, _>(&mut r).unwrap(), None);

        // truncated line (no trailing newline) is an error, not a message
        let mut r = BufReader::new(&b"{\"op\":\"ping\"}"[..]);
        assert!(read_msg::<Request, _>(&mut r).is_err());

        // oversized line is an error
        let huge = format!("{}\n", "x".repeat(MAX_LINE as usize));
        let mut r = BufReader::new(huge.as_bytes());
        assert!(read_msg::<Request, _>(&mut r).is_err());
    }
}
