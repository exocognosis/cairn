//! Wire protocol between a root engine and its MPC party process.
//!
//! One Unix domain socket per party (`p1.sock`, `p2.sock`, `p3.sock` in a socket directory).
//! A frame is a big-endian `u32` length followed by that many payload bytes. `payload[0]` is the
//! tag. Every other integer is little-endian; field elements are `u32` in `[0, q)`; polynomial
//! vectors are row-major, 256 coefficients per polynomial.
//!
//! | Tag | Message | Body |
//! |---|---|---|
//! | `0x01` | `MASK` | `session[32] party:u8 attempt:u32 mu[64] rho[32] k_share[32]` |
//! | `0x02` | `RESPONSE` | `session[32] party:u8 z_share[1280] r_share[1536] t0[1536] T[3][1536]` |
//! | `0x03` | `CLOSE` | `session[32]` |
//! | `0x81` | `MASK_OK` | `c_tilde[48] y_share[1280]` |
//! | `0x82` | `REJECT` | |
//! | `0x83` | `ACCEPT` | `n:u16 positions[n]:u16 z_1[1280] z_2[1280] z_3[1280]` |
//! | `0x84` | `CLOSED` | |
//! | `0x8F` | `FAULT` | `code:u8 party:u8 len:u16 utf8[len]` |
//!
//! The same protocol is spoken by the reference worker ([`crate::worker`]) and by the MP-SPDZ
//! bridge under `mpc/mp-spdz/`.

use std::io::{self, Read, Write};
use threshold_mldsa::fips204::{C_TILDE_BYTES, K, L, N, Q};

pub const PARTIES: usize = 3;
pub const Z_LEN: usize = L * N;
pub const R_LEN: usize = K * N;
pub const MAX_FRAME: usize = 1 << 20;

pub const FAULT_BLAME: u8 = 1;
pub const FAULT_UNATTRIBUTED: u8 = 2;
pub const FAULT_PROTOCOL: u8 = 3;

#[derive(Clone, PartialEq, Eq)]
pub struct MaskRequest {
    pub session: [u8; 32],
    /// 1-based party number.
    pub party: u8,
    pub attempt: u32,
    pub mu: [u8; 64],
    pub rho: [u8; 32],
    pub k_share: Vec<i32>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ResponseRequest {
    pub session: [u8; 32],
    pub party: u8,
    pub z_share: Vec<i32>,
    pub r_share: Vec<i32>,
    pub t0: Vec<i32>,
    /// Verification shares `T_k = A s1_k + s2_k` of parties 1..3.
    pub t: [Vec<i32>; PARTIES],
}

#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    Mask(MaskRequest),
    Response(Box<ResponseRequest>),
    Close([u8; 32]),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reply {
    MaskOk {
        c_tilde: [u8; C_TILDE_BYTES],
        y_share: Vec<i32>,
    },
    Reject,
    Accept {
        hint: Vec<u16>,
        z: [Vec<i32>; PARTIES],
    },
    Closed,
    Fault {
        code: u8,
        party: u8,
        message: String,
    },
}

fn put_elems(out: &mut Vec<u8>, v: &[i32]) {
    for e in v {
        out.extend_from_slice(&(*e as u32).to_le_bytes());
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated IPC payload",
            ));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const M: usize>(&mut self) -> io::Result<[u8; M]> {
        Ok(self.take(M)?.try_into().expect("length checked"))
    }

    fn elems(&mut self, n: usize) -> io::Result<Vec<i32>> {
        let v: Vec<i32> = self
            .take(4 * n)?
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes")) as i32)
            .collect();
        if v.iter().any(|e| !(0..Q).contains(e)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "field element out of range",
            ));
        }
        Ok(v)
    }

    fn done(&self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing IPC bytes",
            ))
        }
    }
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Request::Mask(m) => {
                out.push(0x01);
                out.extend_from_slice(&m.session);
                out.push(m.party);
                out.extend_from_slice(&m.attempt.to_le_bytes());
                out.extend_from_slice(&m.mu);
                out.extend_from_slice(&m.rho);
                put_elems(&mut out, &m.k_share);
            }
            Request::Response(r) => {
                out.push(0x02);
                out.extend_from_slice(&r.session);
                out.push(r.party);
                put_elems(&mut out, &r.z_share);
                put_elems(&mut out, &r.r_share);
                put_elems(&mut out, &r.t0);
                r.t.iter().for_each(|t| put_elems(&mut out, t));
            }
            Request::Close(session) => {
                out.push(0x03);
                out.extend_from_slice(session);
            }
        }
        out
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = Cursor(payload);
        let req = match c.take(1)?[0] {
            0x01 => Request::Mask(MaskRequest {
                session: c.array()?,
                party: c.take(1)?[0],
                attempt: u32::from_le_bytes(c.array()?),
                mu: c.array()?,
                rho: c.array()?,
                k_share: c.elems(32)?,
            }),
            0x02 => Request::Response(Box::new(ResponseRequest {
                session: c.array()?,
                party: c.take(1)?[0],
                z_share: c.elems(Z_LEN)?,
                r_share: c.elems(R_LEN)?,
                t0: c.elems(R_LEN)?,
                t: [c.elems(R_LEN)?, c.elems(R_LEN)?, c.elems(R_LEN)?],
            })),
            0x03 => Request::Close(c.array()?),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown IPC request tag",
                ))
            }
        };
        c.done()?;
        Ok(req)
    }
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Reply::MaskOk { c_tilde, y_share } => {
                out.push(0x81);
                out.extend_from_slice(c_tilde);
                put_elems(&mut out, y_share);
            }
            Reply::Reject => out.push(0x82),
            Reply::Accept { hint, z } => {
                out.push(0x83);
                out.extend_from_slice(&(hint.len() as u16).to_le_bytes());
                hint.iter()
                    .for_each(|p| out.extend_from_slice(&p.to_le_bytes()));
                z.iter().for_each(|v| put_elems(&mut out, v));
            }
            Reply::Closed => out.push(0x84),
            Reply::Fault {
                code,
                party,
                message,
            } => {
                out.extend_from_slice(&[0x8F, *code, *party]);
                out.extend_from_slice(&(message.len() as u16).to_le_bytes());
                out.extend_from_slice(message.as_bytes());
            }
        }
        out
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        let mut c = Cursor(payload);
        let reply = match c.take(1)?[0] {
            0x81 => Reply::MaskOk {
                c_tilde: c.array()?,
                y_share: c.elems(Z_LEN)?,
            },
            0x82 => Reply::Reject,
            0x83 => {
                let n = u16::from_le_bytes(c.array()?) as usize;
                let hint = c
                    .take(2 * n)?
                    .chunks(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                Reply::Accept {
                    hint,
                    z: [c.elems(Z_LEN)?, c.elems(Z_LEN)?, c.elems(Z_LEN)?],
                }
            }
            0x84 => Reply::Closed,
            0x8F => {
                let (code, party) = (c.take(1)?[0], c.take(1)?[0]);
                let len = u16::from_le_bytes(c.array()?) as usize;
                Reply::Fault {
                    code,
                    party,
                    message: String::from_utf8_lossy(c.take(len)?).into_owned(),
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown IPC reply tag",
                ))
            }
        };
        c.done()?;
        Ok(reply)
    }
}

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame length out of range",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_match_the_documented_bytes() {
        let close = Request::Close([0; 32]);
        let mut wire = Vec::new();
        write_frame(&mut wire, &close.encode()).unwrap();
        assert_eq!(&wire[..5], &[0, 0, 0, 0x21, 0x03]);
        assert!(Request::decode(&read_frame(&mut wire.as_slice()).unwrap()).unwrap() == close);

        assert_eq!(Reply::Reject.encode(), [0x82]);
        let fault = Reply::Fault {
            code: FAULT_BLAME,
            party: 2,
            message: "bad response".into(),
        };
        assert_eq!(&fault.encode()[..5], &[0x8F, 0x01, 0x02, 0x0C, 0x00]);
        assert_eq!(Reply::decode(&fault.encode()).unwrap(), fault);

        let accept = Reply::Accept {
            hint: vec![7, 515],
            z: [vec![1; Z_LEN], vec![2; Z_LEN], vec![3; Z_LEN]],
        };
        let bytes = accept.encode();
        assert_eq!(&bytes[..7], &[0x83, 2, 0, 7, 0, 3, 2]);
        assert_eq!(Reply::decode(&bytes).unwrap(), accept);
        assert!(Reply::decode(&bytes[..bytes.len() - 1]).is_err());

        let mask = Request::Mask(MaskRequest {
            session: [9; 32],
            party: 3,
            attempt: 4,
            mu: [1; 64],
            rho: [2; 32],
            k_share: vec![Q - 1; 32],
        });
        assert_eq!(mask.encode().len(), 1 + 32 + 1 + 4 + 64 + 32 + 128);
        assert!(Request::decode(&mask.encode()).unwrap() == mask);
        let mut bad = mask.encode();
        let n = bad.len();
        bad[n - 4..].copy_from_slice(&(Q as u32).to_le_bytes());
        assert!(Request::decode(&bad).is_err(), "out-of-range field element");
    }
}
