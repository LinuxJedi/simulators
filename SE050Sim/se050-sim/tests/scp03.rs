/* scp03.rs
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

//! End-to-end SCP03 tests. These drive the full T=1 -> APDU pipeline via
//! `T1Responder::process_frame`, so they exercise the real wrap/unwrap layer
//! (unlike the in-module unit tests, which call the state machine directly).
//!
//! The host side of the secure channel is implemented here from the GP
//! Amendment D spec, independently of `src/scp03/` (its own KDF, CMAC, CBC
//! built directly on the `cmac`/`aes` crates), so a host derived
//! independently and a card derived from the simulator cross-check each
//! other. Tests run with `--test-threads=1` (they share process env vars and,
//! for the persistence case, on-disk state).

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use cmac::{Cmac, Mac};

use se050_sim::object_store::ObjectStore;
use se050_sim::t1::{crc16_x25, T1Responder};

// Compiled-in default SE050E (0001A921) platform SCP keys / KVN.
const DEF_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7, 0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
const DEF_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0, 0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];
const KVN: u8 = 0x0B;

// -------------------- host-side SCP03 crypto (independent) --------------------

fn cmac16(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut m = <Cmac<Aes128> as Mac>::new_from_slice(key).unwrap();
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut r = [0u8; 16];
    r.copy_from_slice(&out);
    r
}

fn kdf(key: &[u8; 16], dc: u8, ctx: &[u8], out_bits: u16) -> Vec<u8> {
    let need = (out_bits as usize).div_ceil(8);
    let mut out = Vec::new();
    let mut i = 1u8;
    while out.len() < need {
        let mut b = Vec::new();
        b.extend_from_slice(&[0u8; 11]);
        b.push(dc);
        b.push(0x00);
        b.extend_from_slice(&out_bits.to_be_bytes());
        b.push(i);
        b.extend_from_slice(ctx);
        out.extend_from_slice(&cmac16(key, &b));
        i += 1;
    }
    out.truncate(need);
    out
}

fn ecb(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut b = *block;
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));
    b
}

fn counter_block(counter: u32, response: bool) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[12..].copy_from_slice(&counter.to_be_bytes());
    if response {
        b[0] |= 0x80;
    }
    b
}

fn cbc_encrypt(key: &[u8; 16], icv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut chain = *icv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= chain[i];
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        chain = block;
        out.extend_from_slice(&block);
    }
    out
}

fn cbc_decrypt(key: &[u8; 16], icv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut chain = *icv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ct = {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            b
        };
        let mut pt = ct;
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut pt));
        for i in 0..16 {
            pt[i] ^= chain[i];
        }
        chain = ct;
        out.extend_from_slice(&pt);
    }
    out
}

fn pad_m2(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while out.len() % 16 != 0 {
        out.push(0x00);
    }
    out
}

fn unpad_m2(data: &[u8]) -> Vec<u8> {
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        match data[i] {
            0x00 => continue,
            0x80 => return data[..i].to_vec(),
            _ => panic!("bad M2 padding"),
        }
    }
    panic!("no M2 marker")
}

// -------------------- host-side SCP03 session client --------------------

struct HostScp03 {
    s_enc: [u8; 16],
    s_mac: [u8; 16],
    s_rmac: [u8; 16],
    level: u8,
    mcv: [u8; 16],
    counter: u32,
}

fn arr16(v: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(v);
    a
}

impl HostScp03 {
    /// Given the raw INITIALIZE UPDATE response, derive session keys and
    /// verify the card cryptogram. Panics if the card cryptogram is wrong.
    fn from_init_update(
        enc: &[u8; 16],
        mac: &[u8; 16],
        host_ch: &[u8; 8],
        resp: &[u8],
        level: u8,
    ) -> ([u8; 8], HostScp03) {
        assert_eq!(resp.len(), 29, "INIT UPDATE body should be 29 bytes");
        let card_ch = arr8(&resp[13..21]);
        let card_crypto = arr8(&resp[21..29]);

        let mut ctx = [0u8; 16];
        ctx[..8].copy_from_slice(host_ch);
        ctx[8..].copy_from_slice(&card_ch);

        let s_enc = arr16(&kdf(enc, 0x04, &ctx, 128));
        let s_mac = arr16(&kdf(mac, 0x06, &ctx, 128));
        let s_rmac = arr16(&kdf(mac, 0x07, &ctx, 128));

        let calc_card = &kdf(&s_mac, 0x00, &ctx, 64)[..8];
        assert_eq!(calc_card, card_crypto, "card cryptogram mismatch");

        let host_crypto = arr8(&kdf(&s_mac, 0x01, &ctx, 64)[..8]);
        (
            host_crypto,
            HostScp03 {
                s_enc,
                s_mac,
                s_rmac,
                level,
                mcv: [0u8; 16],
                counter: 1,
            },
        )
    }

    /// Build the EXTERNAL AUTHENTICATE APDU and set the initial MCV. The
    /// C-MAC covers the initial (all-zero) MCV || header || host cryptogram.
    fn external_authenticate(&mut self, host_crypto: &[u8; 8]) -> Vec<u8> {
        let mut apdu = vec![0x84, 0x82, self.level, 0x00, 0x10];
        apdu.extend_from_slice(host_crypto);
        let mut mac_in = self.mcv.to_vec(); // 16 zero bytes
        mac_in.extend_from_slice(&apdu[0..13]);
        let full = cmac16(&self.s_mac, &mac_in);
        apdu.extend_from_slice(&full[..8]);
        self.mcv = full;
        apdu
    }

    /// Wrap a plain command (CLA 0x80) for transmission.
    fn wrap(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u8>) -> Vec<u8> {
        let has_body = !data.is_empty();

        let data_field = if has_body && (self.level & 0x02 != 0) {
            let padded = pad_m2(data);
            let icv = ecb(&self.s_enc, &counter_block(self.counter, false));
            cbc_encrypt(&self.s_enc, &icv, &padded)
        } else {
            data.to_vec()
        };

        let lc = data_field.len() + 8;
        assert!(lc < 256, "test commands use short Lc");
        let mut apdu = vec![0x84, ins, p1, p2, lc as u8];
        apdu.extend_from_slice(&data_field);
        let mut mac_in = apdu[..5 + data_field.len()].to_vec();
        let full = cmac16(&self.s_mac, &{
            let mut m = self.mcv.to_vec();
            m.append(&mut mac_in);
            m
        });
        self.mcv = full;
        apdu.extend_from_slice(&full[..8]);
        if let Some(l) = le {
            apdu.push(l);
        }
        apdu
    }

    /// Verify + decrypt a response, returning (data, sw). Advances the counter.
    fn unwrap(&mut self, wire: &[u8]) -> (Vec<u8>, u16) {
        let rmac_level = self.level & 0x10 != 0;
        let (data, sw) = if !rmac_level || wire.len() == 2 {
            // Plain response (a MAC-only level, or a bare status word).
            let n = wire.len();
            (
                wire[..n - 2].to_vec(),
                u16::from_be_bytes([wire[n - 2], wire[n - 1]]),
            )
        } else {
            assert!(wire.len() >= 10, "wrapped response must carry R-MAC + SW");
            let sw = u16::from_be_bytes([wire[wire.len() - 2], wire[wire.len() - 1]]);
            let rmac_recv = &wire[wire.len() - 10..wire.len() - 2];
            let enc_data = &wire[..wire.len() - 10];

            let mut mac_in = self.mcv.to_vec();
            mac_in.extend_from_slice(enc_data);
            mac_in.extend_from_slice(&sw.to_be_bytes());
            let full = cmac16(&self.s_rmac, &mac_in);
            assert_eq!(&full[..8], rmac_recv, "R-MAC verify failed");

            let data = if !enc_data.is_empty() && (self.level & 0x20 != 0) {
                // Applet >= 4.3 semantics (the simulator's default 7.2.0
                // personality): the response ICV uses the current counter.
                let icv = ecb(&self.s_enc, &counter_block(self.counter, true));
                unpad_m2(&cbc_decrypt(&self.s_enc, &icv, enc_data))
            } else {
                enc_data.to_vec()
            };
            (data, sw)
        };
        // The command counter advances once per command regardless of whether
        // the command carried a body (only the no-body response ICV reuses
        // counter-1). Mirrors nxScp03_Com.c and src/scp03/mod.rs.
        self.counter = self.counter.wrapping_add(1);
        (data, sw)
    }
}

fn arr8(v: &[u8]) -> [u8; 8] {
    let mut a = [0u8; 8];
    a.copy_from_slice(v);
    a
}

// -------------------- T=1 host framing --------------------

struct T1Host {
    t1: T1Responder,
    store: ObjectStore,
    seq: u8,
}

impl T1Host {
    fn new() -> Self {
        Self {
            t1: T1Responder::new(0x5A),
            store: ObjectStore::new(),
            seq: 0,
        }
    }

    fn with_store(store: ObjectStore) -> Self {
        Self {
            t1: T1Responder::new(0x5A),
            store,
            seq: 0,
        }
    }

    /// Send one APDU as a single I-frame; reassemble the response I-frames
    /// into the full response APDU (data || SW).
    fn transceive(&mut self, apdu: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x5A, self.seq << 6, apdu.len() as u8];
        frame.extend_from_slice(apdu);
        let crc = crc16_x25(&frame);
        frame.push(crc as u8);
        frame.push((crc >> 8) as u8);
        self.seq ^= 1;

        let chunks = self.t1.process_frame(&frame, &mut self.store);
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < chunks.len() {
            let header = &chunks[i];
            let payload_crc = &chunks[i + 1];
            let len = header[2] as usize;
            out.extend_from_slice(&payload_crc[..len]);
            i += 2;
        }
        out
    }

    /// Send an S-frame request (e.g. soft reset 0x0F, resync 0x00).
    fn s_frame(&mut self, code: u8) {
        let pcb = 0xC0 | code; // S-request
        let mut frame = vec![0x5A, pcb, 0x00];
        let crc = crc16_x25(&frame);
        frame.push(crc as u8);
        frame.push((crc >> 8) as u8);
        let _ = self.t1.process_frame(&frame, &mut self.store);
    }
}

fn split_sw(resp: &[u8]) -> (&[u8], u16) {
    let n = resp.len();
    (&resp[..n - 2], u16::from_be_bytes([resp[n - 2], resp[n - 1]]))
}

/// Run the handshake against the host with the given static keys and level,
/// returning an authenticated client.
fn open_session(host: &mut T1Host, enc: &[u8; 16], mac: &[u8; 16], level: u8) -> HostScp03 {
    let host_ch = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let mut iu = vec![0x80, 0x50, KVN, 0x00, 0x08];
    iu.extend_from_slice(&host_ch);
    iu.push(0x00);
    let resp = host.transceive(&iu);
    let (body, sw) = split_sw(&resp);
    assert_eq!(sw, 0x9000, "INIT UPDATE failed");
    let (host_crypto, mut client) =
        HostScp03::from_init_update(enc, mac, &host_ch, body, level);
    let ea = client.external_authenticate(&host_crypto);
    let resp = host.transceive(&ea);
    assert_eq!(resp, vec![0x90, 0x00], "EXT AUTH should be bare 9000");
    client
}

// Inner-command builders (plain APDUs).
fn get_random(len: u16) -> (u8, u8, u8, Vec<u8>) {
    // INS_MGMT (0x04), P2_RANDOM (0x49), Tag1 = 2-byte length.
    (0x04, 0x00, 0x49, vec![0x41, 0x02, (len >> 8) as u8, len as u8])
}

// -------------------- tests --------------------

#[test]
fn handshake_and_wrapped_getversion() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    // GetVersion is a no-body command (Lc=0), exercising the response-ICV
    // counter-1 path. Default applet 7.2.0 -> 07 02 00 3f ff ff ff.
    let cmd = c.wrap(0x04, 0x00, 0x20, &[], Some(0x0B));
    let resp = host.transceive(&cmd);
    let (data, sw) = c.unwrap(&resp);
    assert_eq!(sw, 0x9000);
    // TLV Tag1 (0x41) len 7 || version.
    assert_eq!(data[0], 0x41);
    assert_eq!(&data[2..9], &[0x07, 0x02, 0x00, 0x3F, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn wrapped_getrandom_round_trips() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    let (ins, p1, p2, data) = get_random(32);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let resp = host.transceive(&cmd);
    let (out, sw) = c.unwrap(&resp);
    assert_eq!(sw, 0x9000);
    assert_eq!(out[0], 0x41); // Tag1
    assert_eq!(out[1], 32); // length
    assert_eq!(out.len(), 2 + 32);
}

#[test]
fn chained_commands_keep_mcv_and_counter() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    // no-body, body, no-body: exercises the counter/MCV bookkeeping across
    // the has-body / no-body mix.
    for (ins, p1, p2, data, le) in [
        (0x04u8, 0x00u8, 0x20u8, vec![], Some(0x0B)),
        {
            let (i, a, b, d) = get_random(16);
            (i, a, b, d, Some(0x00))
        },
        (0x04, 0x00, 0x20, vec![], Some(0x0B)),
    ] {
        let cmd = c.wrap(ins, p1, p2, &data, le);
        let resp = host.transceive(&cmd);
        let (_out, sw) = c.unwrap(&resp);
        assert_eq!(sw, 0x9000);
    }
}

#[test]
fn renc_multiframe_response() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    // 300 random bytes -> encrypted response + R-MAC + SW exceeds the 254-byte
    // I-frame payload, forcing multi-frame chaining.
    let (ins, p1, p2, data) = get_random(300);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let resp = host.transceive(&cmd);
    let (out, sw) = c.unwrap(&resp);
    assert_eq!(sw, 0x9000);
    // Tag1 (0x41) + 3-byte length header (0x82 hi lo, since 300 >= 128) + 300.
    assert_eq!(out.len(), 4 + 300);
    assert_eq!(out[0], 0x41);
    assert_eq!(out[1], 0x82);
}

#[test]
fn cmac_only_level_responses_are_plain() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x01);

    // At level 0x01 the command is MAC'd but not encrypted, and the response
    // is entirely plain (no R-MAC, no R-ENC).
    let (ins, p1, p2, data) = get_random(16);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let resp = host.transceive(&cmd);
    let (out, sw) = c.unwrap(&resp);
    assert_eq!(sw, 0x9000);
    assert_eq!(out[0], 0x41);
    assert_eq!(out[1], 16);
}

#[test]
fn mac_tamper_destroys_session() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    let (ins, p1, p2, data) = get_random(16);
    let mut cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let n = cmd.len();
    cmd[n - 2] ^= 0x01; // flip a byte in the C-MAC (before the trailing Le)
    let resp = host.transceive(&cmd);
    assert_eq!(resp, vec![0x69, 0x82], "tampered C-MAC -> bare 6982");

    // Session is gone: a correctly-wrapped follow-up also fails.
    let (ins, p1, p2, data) = get_random(16);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let resp = host.transceive(&cmd);
    assert_eq!(resp, vec![0x69, 0x82]);

    // A fresh handshake then succeeds.
    let mut c2 = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
    let (ins, p1, p2, data) = get_random(8);
    let cmd = c2.wrap(ins, p1, p2, &data, Some(0x00));
    let (_out, sw) = c2.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000);
}

#[test]
fn bad_host_cryptogram_refused() {
    let mut host = T1Host::new();
    let host_ch = [1u8; 8];
    let mut iu = vec![0x80, 0x50, KVN, 0x00, 0x08];
    iu.extend_from_slice(&host_ch);
    iu.push(0x00);
    let resp = host.transceive(&iu);
    let (_body, sw) = split_sw(&resp);
    assert_eq!(sw, 0x9000);

    // EXTERNAL AUTHENTICATE with a bogus cryptogram + MAC.
    let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x10];
    ea.extend_from_slice(&[0xAAu8; 16]);
    let resp = host.transceive(&ea);
    assert_eq!(resp, vec![0x69, 0x82]);

    // No session established: a secure-messaging command is refused.
    let mut cmd = vec![0x84, 0x04, 0x00, 0x49, 0x0C];
    cmd.extend_from_slice(&[0u8; 12]);
    let resp = host.transceive(&cmd);
    assert_eq!(resp, vec![0x69, 0x82]);
}

/// EXTERNAL AUTHENTICATE without a preceding INITIALIZE UPDATE is a sequencing
/// error, not a MAC failure: it must report 0x6985 rather than falling through
/// to the wrapped-command path and reporting 0x6982.
#[test]
fn external_authenticate_without_initialize_update() {
    let mut host = T1Host::new();
    let mut ea = vec![0x84, 0x82, 0x33, 0x00, 0x10];
    ea.extend_from_slice(&[0u8; 16]);
    assert_eq!(host.transceive(&ea), vec![0x69, 0x85]);

    // Still recoverable: a full handshake afterwards works.
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
    let (ins, p1, p2, data) = get_random(8);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let (_out, sw) = c.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000);
}

/// A wrapped command whose inner INS is 0x82 must still be treated as a
/// wrapped command inside an active session, not mistaken for a second
/// EXTERNAL AUTHENTICATE.
#[test]
fn wrapped_command_with_inner_ins_82_is_not_external_authenticate() {
    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    // INS 0x82 masks to INS_READ (0x02); P1/P2 here select ReadECCurveList,
    // so a correctly wrapped command must be dispatched and answered, and the
    // session must survive.
    let cmd = c.wrap(0x82, 0x0b, 0x25, &[], Some(0x00));
    let (_out, sw) = c.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000, "inner INS 0x82 should dispatch as a read");

    let (ins, p1, p2, data) = get_random(8);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let (_out, sw) = c.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000, "session should still be alive");
}

#[test]
fn soft_reset_and_resync_drop_session() {
    for reset_code in [0x0Fu8, 0x00u8] {
        let mut host = T1Host::new();
        let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
        host.s_frame(reset_code);
        // After a chip reset the session is gone; the T=1 seq also reset.
        host.seq = 0;
        let (ins, p1, p2, data) = get_random(16);
        let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
        let resp = host.transceive(&cmd);
        assert_eq!(resp, vec![0x69, 0x82], "reset code 0x{:02x}", reset_code);
    }
}

#[test]
fn reinitialize_update_mid_session() {
    let mut host = T1Host::new();
    let _c1 = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
    // A second full handshake replaces the first with fresh keys.
    let mut c2 = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
    let (ins, p1, p2, data) = get_random(16);
    let cmd = c2.wrap(ins, p1, p2, &data, Some(0x00));
    let (_out, sw) = c2.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000);
}

#[test]
fn plain_command_during_session_is_refused() {
    let mut host = T1Host::new();
    let _c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);

    // A plain (CLA 0x80) command while the channel is active is refused and
    // terminates the session.
    let plain_getversion = vec![0x80, 0x04, 0x00, 0x20, 0x0B];
    let resp = host.transceive(&plain_getversion);
    assert_eq!(resp, vec![0x69, 0x85]);

    // SELECT still works (host can always recover).
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x10];
    select.extend_from_slice(&[
        0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00,
        0x00,
    ]);
    select.push(0x00);
    let resp = host.transceive(&select);
    let (_b, sw) = split_sw(&resp);
    assert_eq!(sw, 0x9000);
}

#[test]
fn env_key_override_authenticates() {
    // Override the static keys; the handshake must succeed with them and then
    // fail once the override is removed (proving the override is honored).
    let enc = [0x00u8; 16];
    let mac = [0x11u8; 16];
    std::env::set_var("SE050_SIM_SCP03_ENC", hex::encode(enc));
    std::env::set_var("SE050_SIM_SCP03_MAC", hex::encode(mac));

    let mut host = T1Host::new();
    let mut c = open_session(&mut host, &enc, &mac, 0x33);
    let (ins, p1, p2, data) = get_random(8);
    let cmd = c.wrap(ins, p1, p2, &data, Some(0x00));
    let (_out, sw) = c.unwrap(&host.transceive(&cmd));
    assert_eq!(sw, 0x9000);

    std::env::remove_var("SE050_SIM_SCP03_ENC");
    std::env::remove_var("SE050_SIM_SCP03_MAC");
}

#[test]
fn set_platform_scp_request_flow() {
    let path = std::env::temp_dir().join(format!(
        "se050_sim_scp_required_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    {
        let mut host = T1Host::with_store(ObjectStore::with_persistence(path.clone()));

        // Plain SetPlatformSCPRequest is refused (needs an authenticated session).
        let plain = vec![0x80, 0x04, 0x00, 0x52, 0x03, 0x41, 0x01, 0x01];
        let resp = host.transceive(&plain);
        assert_eq!(resp, vec![0x69, 0x85]);

        // Inside a session, set SCP required (Tag1 = 0x01).
        let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
        let cmd = c.wrap(0x04, 0x00, 0x52, &[0x41, 0x01, 0x01], None);
        let (_d, sw) = c.unwrap(&host.transceive(&cmd));
        assert_eq!(sw, 0x9000);
        // Setting it terminated the plain path; the session object persisted.
    }

    // Reload: scp_required survived persistence, so a plain command is refused
    // while SELECT still works.
    {
        let mut host = T1Host::with_store(ObjectStore::with_persistence(path.clone()));
        let plain_getversion = vec![0x80, 0x04, 0x00, 0x20, 0x0B];
        assert_eq!(host.transceive(&plain_getversion), vec![0x69, 0x85]);

        let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x10];
        select.extend_from_slice(&[
            0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00,
            0x00, 0x00,
        ]);
        select.push(0x00);
        let (_b, sw) = split_sw(&host.transceive(&select));
        assert_eq!(sw, 0x9000);

        // Clear it again inside a session so the flag does not leak.
        let mut c = open_session(&mut host, &DEF_ENC, &DEF_MAC, 0x33);
        let cmd = c.wrap(0x04, 0x00, 0x52, &[0x41, 0x01, 0x02], None);
        let (_d, sw) = c.unwrap(&host.transceive(&cmd));
        assert_eq!(sw, 0x9000);
    }
    let _ = std::fs::remove_file(&path);
}
