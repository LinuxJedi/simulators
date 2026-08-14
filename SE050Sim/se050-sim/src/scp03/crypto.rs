/* crypto.rs
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of SE050Sim.
 *
 * SE050Sim is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * SE050Sim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

//! Pure SCP03 crypto primitives: the SP800-108 counter-mode KDF, session
//! key / cryptogram derivation, C-MAC chaining, the response-encryption ICV,
//! AES-CBC, and ISO 9797-1 method 2 padding. No session state, no I/O, so
//! every function here is directly unit-testable.
//!
//! The KDF framing and derivation constants were validated byte-for-byte
//! against real SE050E silicon (see SE050Sim/HARDWARE_VALIDATION.md): the
//! card cryptogram recomputed here matched the chip's, and the derived
//! S-MAC produced a C-MAC the applet accepted at EXTERNAL AUTHENTICATE.

use crate::handlers::aes::{cbc_process, AnyAes};
use crate::handlers::mac::cmac_aes;

// GlobalPlatform Amendment D data-derivation constants (spec-fixed).
pub const DDC_CARD_CRYPTOGRAM: u8 = 0x00;
pub const DDC_HOST_CRYPTOGRAM: u8 = 0x01;
pub const DDC_S_ENC: u8 = 0x04;
pub const DDC_S_MAC: u8 = 0x06;
pub const DDC_S_RMAC: u8 = 0x07;

/// SP800-108 counter-mode KDF with AES-CMAC as the PRF, using the GP
/// SCP03 data-derivation input format:
///   11 zero bytes || DC || 0x00 || L (2 bytes, big-endian, in bits)
///   || i (1 byte counter from 1) || context
/// Iterates the counter until `out_bits` of output are produced.
pub fn kdf(key: &[u8], dc: u8, context: &[u8], out_bits: u16) -> Option<Vec<u8>> {
    let need = (out_bits as usize).div_ceil(8);
    let mut out = Vec::with_capacity(need + 16);
    let mut i: u8 = 1;
    while out.len() < need {
        let mut block = Vec::with_capacity(16 + context.len());
        block.extend_from_slice(&[0u8; 11]); // label: 11 zero bytes
        block.push(dc); // derivation constant
        block.push(0x00); // separation indicator
        block.extend_from_slice(&out_bits.to_be_bytes()); // L in bits
        block.push(i); // counter
        block.extend_from_slice(context);
        out.extend_from_slice(&cmac_aes(key, &block)?);
        i = i.checked_add(1)?;
    }
    out.truncate(need);
    Some(out)
}

/// Derive (S-ENC, S-MAC, S-RMAC) from the static ENC/MAC keys. S-ENC comes
/// from the static ENC key; both MAC session keys come from the static MAC
/// key. Context is host_challenge || card_challenge. Session keys are the
/// same width as the static keys.
pub fn derive_session_keys(
    enc: &[u8],
    mac: &[u8],
    host_ch: &[u8; 8],
    card_ch: &[u8; 8],
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut ctx = [0u8; 16];
    ctx[..8].copy_from_slice(host_ch);
    ctx[8..].copy_from_slice(card_ch);
    let bits = (enc.len() * 8) as u16;
    let s_enc = kdf(enc, DDC_S_ENC, &ctx, bits)?;
    let mbits = (mac.len() * 8) as u16;
    let s_mac = kdf(mac, DDC_S_MAC, &ctx, mbits)?;
    let s_rmac = kdf(mac, DDC_S_RMAC, &ctx, mbits)?;
    Some((s_enc, s_mac, s_rmac))
}

/// 8-byte card (DDC 0x00) or host (DDC 0x01) cryptogram, keyed with S-MAC
/// over host_challenge || card_challenge, L = 64 bits (leftmost 8 bytes).
pub fn cryptogram(s_mac: &[u8], host_ch: &[u8; 8], card_ch: &[u8; 8], dc: u8) -> Option<[u8; 8]> {
    let mut ctx = [0u8; 16];
    ctx[..8].copy_from_slice(host_ch);
    ctx[8..].copy_from_slice(card_ch);
    let full = kdf(s_mac, dc, &ctx, 64)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    Some(out)
}

/// Full 16-byte CMAC over (mcv || data). The caller truncates to 8 for the
/// wire; for C-MAC the full value becomes the next MAC chaining value
/// (R-MAC never advances the chain).
pub fn cmac_chain(key: &[u8], mcv: &[u8; 16], data: &[u8]) -> Option<[u8; 16]> {
    let mut input = Vec::with_capacity(16 + data.len());
    input.extend_from_slice(mcv);
    input.extend_from_slice(data);
    let full = cmac_aes(key, &input)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    Some(out)
}

/// ICV for command (response=false) or response (response=true) encryption:
/// AES-ECB(S-ENC) of a 16-byte block holding the command counter as a
/// big-endian integer, with the most-significant byte set to 0x80 for the
/// response direction.
pub fn counter_icv(s_enc: &[u8], counter: u32, response: bool) -> Option<[u8; 16]> {
    let cipher = AnyAes::new(s_enc)?;
    let mut block = [0u8; 16];
    block[12..].copy_from_slice(&counter.to_be_bytes());
    if response {
        block[0] |= 0x80;
    }
    cipher.encrypt_block(&mut block);
    Some(block)
}

/// AES-CBC over block-aligned `data` with the given ICV as the initial
/// chaining value.
pub fn cbc_crypt(key: &[u8], icv: &[u8; 16], data: &[u8], encrypting: bool) -> Option<Vec<u8>> {
    let cipher = AnyAes::new(key)?;
    let mut chain = *icv;
    Some(cbc_process(&cipher, &mut chain, data, encrypting))
}

/// ISO 9797-1 method 2 padding: append 0x80 then zeros to the next 16-byte
/// boundary. Always adds at least one byte (a full block when already
/// aligned), so the marker is unambiguous.
pub fn pad_m2(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

/// Strip ISO 9797-1 method 2 padding. Returns None if there is no 0x80
/// marker or if any byte after it is non-zero.
pub fn unpad_m2(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        match data[i] {
            0x00 => continue,
            0x80 => return Some(data[..i].to_vec()),
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // SE050E bench fixture (HARDWARE_VALIDATION.md): with the OEF 0001A921
    // default keys and these challenges the silicon returned this exact card
    // cryptogram, and derived these session keys. This pins the KDF to
    // real hardware.
    const K_ENC: [u8; 16] = [
        0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7, 0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF,
        0x64,
    ];
    const K_MAC: [u8; 16] = [
        0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0, 0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9,
        0x5B,
    ];
    const HOST_CH: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    const CARD_CH: [u8; 8] = [0x4E, 0xCD, 0x90, 0x6D, 0x32, 0x5D, 0x3D, 0x8A];

    #[test]
    fn session_keys_match_silicon() {
        let (s_enc, s_mac, _s_rmac) =
            derive_session_keys(&K_ENC, &K_MAC, &HOST_CH, &CARD_CH).unwrap();
        assert_eq!(
            s_enc,
            [
                0xcb, 0x15, 0xcc, 0x71, 0x07, 0x2b, 0x27, 0x3b, 0xd9, 0xf9, 0xcd, 0x94, 0x33, 0x90,
                0xd5, 0x6a
            ]
        );
        assert_eq!(
            s_mac,
            [
                0x26, 0x0b, 0x44, 0x54, 0xb2, 0xfe, 0xfc, 0x55, 0xd9, 0x76, 0x8f, 0xcb, 0xf5, 0xed,
                0x74, 0x9f
            ]
        );
    }

    #[test]
    fn card_cryptogram_matches_silicon() {
        let (_s_enc, s_mac, _s_rmac) =
            derive_session_keys(&K_ENC, &K_MAC, &HOST_CH, &CARD_CH).unwrap();
        let card = cryptogram(&s_mac, &HOST_CH, &CARD_CH, DDC_CARD_CRYPTOGRAM).unwrap();
        assert_eq!(card, [0xf7, 0xbe, 0x9f, 0x05, 0xea, 0xa0, 0xa6, 0x61]);
    }

    #[test]
    fn pad_unpad_round_trip() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).collect();
            let padded = pad_m2(&data);
            assert_eq!(padded.len() % 16, 0);
            assert!(padded.len() > data.len());
            assert_eq!(unpad_m2(&padded).unwrap(), data);
        }
    }

    #[test]
    fn unpad_rejects_bad_padding() {
        assert!(unpad_m2(&[0u8; 16]).is_none()); // no 0x80 marker
        assert!(unpad_m2(&[0x80, 0x01]).is_none()); // non-zero after marker
        assert!(unpad_m2(&[]).is_none());
    }

    #[test]
    fn counter_icv_sets_response_bit() {
        let key = [0u8; 16];
        let cmd = counter_icv(&key, 1, false).unwrap();
        let rsp = counter_icv(&key, 1, true).unwrap();
        assert_ne!(cmd, rsp);
    }
}
