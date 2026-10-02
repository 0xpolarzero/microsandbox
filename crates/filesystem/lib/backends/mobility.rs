//! Bounded framing helpers for filesystem backend state.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use bincode::config;
use serde::{Serialize, de::DeserializeOwned};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: u16 = 1;
const HEADER_BYTES: usize = 10;
const MIB: usize = 1024 * 1024;
const DEFAULT_BACKEND_STATE_LIMIT: usize = 4 * MIB;

static BACKEND_STATE_LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_BACKEND_STATE_LIMIT);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Sets the largest backend state, in bytes, that this process encodes or decodes.
pub fn set_max_backend_state_bytes(bytes: usize) {
    BACKEND_STATE_LIMIT.store(bytes, Ordering::Relaxed);
}

pub(crate) fn encode<T: Serialize>(kind: &[u8; 8], state: &T) -> io::Result<Vec<u8>> {
    encode_with_limit(kind, state, BACKEND_STATE_LIMIT.load(Ordering::Relaxed))
}

pub(crate) fn decode<T: DeserializeOwned>(kind: &[u8; 8], bytes: &[u8]) -> io::Result<T> {
    decode_with_limit(kind, bytes, BACKEND_STATE_LIMIT.load(Ordering::Relaxed))
}

fn encode_with_limit<T: Serialize>(kind: &[u8; 8], state: &T, limit: usize) -> io::Result<Vec<u8>> {
    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding();
    let payload = bincode::serde::encode_to_vec(state, config).map_err(invalid_data)?;
    let total = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "backend state is too large"))?;
    if total > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "filesystem state exceeds the {} MiB budget; raise snapshots.max_filesystem_state_mib \
                 (a running sandbox keeps the budget it started with)",
                limit / MIB
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(&SCHEMA.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_with_limit<T: DeserializeOwned>(
    kind: &[u8; 8],
    bytes: &[u8],
    limit: usize,
) -> io::Result<T> {
    if bytes.len() < HEADER_BYTES || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid backend state length",
        ));
    }
    if &bytes[..8] != kind || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported backend state format",
        ));
    }

    let (state, consumed) = match limit {
        limit if limit <= 4 * MIB => decode_tier::<{ 4 * MIB }, T>(&bytes[HEADER_BYTES..]),
        limit if limit <= 16 * MIB => decode_tier::<{ 16 * MIB }, T>(&bytes[HEADER_BYTES..]),
        limit if limit <= 64 * MIB => decode_tier::<{ 64 * MIB }, T>(&bytes[HEADER_BYTES..]),
        limit if limit <= 256 * MIB => decode_tier::<{ 256 * MIB }, T>(&bytes[HEADER_BYTES..]),
        limit if limit <= 1024 * MIB => decode_tier::<{ 1024 * MIB }, T>(&bytes[HEADER_BYTES..]),
        _ => decode_tier::<{ 4095 * MIB }, T>(&bytes[HEADER_BYTES..]),
    }?;
    if HEADER_BYTES + consumed != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing backend state bytes",
        ));
    }
    Ok(state)
}

/// Decodes with a compile-time allocation bound, which bincode only accepts as a const generic.
fn decode_tier<const L: usize, T: DeserializeOwned>(bytes: &[u8]) -> io::Result<(T, usize)> {
    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<L>();
    bincode::serde::decode_from_slice(bytes, config).map_err(invalid_data)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    const KIND: &[u8; 8] = b"MSBTEST\0";

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct State {
        value: u64,
    }

    #[test]
    fn framed_state_round_trips_and_rejects_trailing_bytes() {
        let encoded = encode(KIND, &State { value: 42 }).unwrap();
        assert_eq!(decode::<State>(KIND, &encoded).unwrap().value, 42);

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode::<State>(KIND, &trailing).is_err());
    }

    #[test]
    fn state_size_follows_the_budget() {
        let state = vec![7u8; 5 * MIB];

        let error = encode_with_limit(KIND, &state, DEFAULT_BACKEND_STATE_LIMIT).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("snapshots.max_filesystem_state_mib")
        );

        for limit in [8 * MIB, 4095 * MIB] {
            let encoded = encode_with_limit(KIND, &state, limit).unwrap();
            assert_eq!(
                decode_with_limit::<Vec<u8>>(KIND, &encoded, limit).unwrap(),
                state
            );
        }

        let encoded = encode_with_limit(KIND, &state, 8 * MIB).unwrap();
        assert!(decode_with_limit::<Vec<u8>>(KIND, &encoded, DEFAULT_BACKEND_STATE_LIMIT).is_err());
    }
}
