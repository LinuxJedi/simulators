/* management.rs
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

use crate::apdu::{ApduResponse, ParsedApdu, P2_VERSION, P2_MEMORY, P2_RANDOM, P2_DELETE_ALL,
                  SW_CONDITIONS_NOT_SATISFIED, SW_WRONG_DATA};
use crate::applet::AppletVersion;
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1};
use rand::RngCore;

pub fn handle(apdu: &ParsedApdu, store: &mut ObjectStore, version: AppletVersion) -> ApduResponse {
    match apdu.p2 {
        P2_VERSION => handle_get_version(version),
        P2_MEMORY => handle_get_free_memory(apdu, version),
        P2_RANDOM => handle_get_random(apdu, version),
        P2_DELETE_ALL => handle_delete_all(apdu, store),
        _ => ApduResponse::error(0x6A86),
    }
}

/// GetVersion: returns TLV[Tag1] with the 7-byte version blob
/// (bench-captured per applet generation, see AppletVersion).
fn handle_get_version(version: AppletVersion) -> ApduResponse {
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &version.version_bytes())])
}

/// GetFreeMemory: Tag1 = memory type (1B). All bench parts (3.1.1,
/// 7.2.0, SE050E) reply with a 2-byte value; per-type values as
/// measured on the bench parts (see AppletVersion::free_memory_bytes).
fn handle_get_free_memory(apdu: &ParsedApdu, version: AppletVersion) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(0x6A80),
    };
    let mem_type = tlv::find_tlv(&tlvs, TAG_1)
        .and_then(|t| t.value.first().copied())
        .unwrap_or(0x01);
    match version.free_memory_bytes(mem_type) {
        Some(bytes) => ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &bytes)]),
        None => ApduResponse::error(0x6A80),
    }
}

/// GetRandom: reads TLV[Tag1] as 2-byte requested length, returns
/// random bytes. Zero-length requests fail 0x6985 and there is a
/// per-applet maximum (880 bytes on 3.1.1, 1018 on 7.2.0 and the
/// SE050E), all bench-verified.
fn handle_get_random(apdu: &ParsedApdu, version: AppletVersion) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(0x6A80),
    };

    let tag1 = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) => t,
        None => return ApduResponse::error(0x6A80),
    };

    if tag1.value.len() < 2 {
        return ApduResponse::error(0x6A80);
    }

    let requested_len = ((tag1.value[0] as usize) << 8) | (tag1.value[1] as usize);
    if requested_len == 0 || requested_len > version.get_random_max() {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    let mut random_data = vec![0u8; requested_len];
    rand::thread_rng().fill_bytes(&mut random_data);

    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &random_data)])
}

/// DeleteAll: clears all objects, curves, and crypto objects (the
/// simulator then re-provisions its default curve set, see
/// ObjectStore::clear).
fn handle_delete_all(_apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    store.clear();
    ApduResponse::success()
}

/// SetPlatformSCPRequest (INS_MGMT, P2=0x52): sets whether plain
/// (non-SCP03) commands are accepted. On real silicon this requires a
/// session authenticated with the reserved platform-SCP identity, so the
/// simulator requires an active SCP03 channel (`scp_active`) and otherwise
/// returns 0x6985. The nxp-se050 Rust driver sends this command plain with
/// an empty body, so it fails here exactly as it would on hardware.
///
/// Body: TLV Tag1, 1 byte -- 0x01 = SCP required, 0x02 = not required.
pub fn handle_set_platform_scp(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    scp_active: bool,
) -> ApduResponse {
    if !scp_active {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    match tlv::find_tlv(&tlvs, TAG_1).and_then(|t| t.value.first().copied()) {
        Some(0x01) => {
            store.set_scp_required(true);
            ApduResponse::success()
        }
        Some(0x02) => {
            store.set_scp_required(false);
            ApduResponse::success()
        }
        _ => ApduResponse::error(SW_WRONG_DATA),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::{INS_MGMT, P1_DEFAULT};

    fn random_apdu(len: u16) -> ParsedApdu {
        ParsedApdu {
            cla: 0x80,
            ins: INS_MGMT,
            p1: P1_DEFAULT,
            p2: P2_RANDOM,
            data: vec![TAG_1, 0x02, (len >> 8) as u8, len as u8],
            le: None,
        }
    }

    #[test]
    fn test_get_random_bounds_per_version() {
        // Bench-verified: size 0 fails on all parts; the cap is 880
        // on the SE050C (3.1.1) and 1018 on the SE051 (7.2.0) and
        // SE050E.
        let mut store = ObjectStore::new();
        for (version, max) in [
            (AppletVersion::V3_1_1, 880u16),
            (AppletVersion::V7_2_0, 1018u16),
            (AppletVersion::V7_2_0E, 1018u16),
        ] {
            let resp = handle(&random_apdu(0), &mut store, version);
            assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
            let resp = handle(&random_apdu(max), &mut store, version);
            assert_eq!(resp.sw, 0x9000);
            let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
            assert_eq!(tlvs[0].value.len(), max as usize);
            let resp = handle(&random_apdu(max + 1), &mut store, version);
            assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED, "{:?}", version);
        }
    }

    #[test]
    fn test_get_version_per_applet() {
        // Bench-captured blobs: SE050C 3.1.1 -> 03 01 01 6f ff 01 0b,
        // SE051 7.2.0 -> 07 02 00 3f ff ff ff, SE050E 7.2.0 ->
        // 07 02 00 3f 9f ff ff (appletConfig without the RSA bits).
        let mut store = ObjectStore::new();
        let apdu = ParsedApdu {
            cla: 0x80, ins: INS_MGMT, p1: P1_DEFAULT, p2: P2_VERSION,
            data: vec![], le: Some(0x0B),
        };
        let resp = handle(&apdu, &mut store, AppletVersion::V3_1_1);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlvs[0].value, [0x03, 0x01, 0x01, 0x6F, 0xFF, 0x01, 0x0B]);
        let resp = handle(&apdu, &mut store, AppletVersion::V7_2_0);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlvs[0].value, [0x07, 0x02, 0x00, 0x3F, 0xFF, 0xFF, 0xFF]);
        let resp = handle(&apdu, &mut store, AppletVersion::V7_2_0E);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        assert_eq!(tlvs[0].value, [0x07, 0x02, 0x00, 0x3F, 0x9F, 0xFF, 0xFF]);
    }

    #[test]
    fn test_get_free_memory_values_per_applet() {
        // All bench parts reply with a 2-byte value; per-type values
        // as measured on the bench (SE050E clamps PERSISTENT at
        // 0x7FFF). The v04.07.01 middleware rejects TLV values longer
        // than 2 bytes for these applets (tlvGet_U16), so a 4-byte
        // reply would make Se05x_API_GetFreeMemory fail host-side.
        let mut store = ObjectStore::new();
        for (version, persistent) in [
            (AppletVersion::V3_1_1, 31304u16),
            (AppletVersion::V7_2_0, 21000u16),
            (AppletVersion::V7_2_0E, 32767u16),
        ] {
            let apdu = ParsedApdu {
                cla: 0x80, ins: INS_MGMT, p1: P1_DEFAULT, p2: P2_MEMORY,
                data: vec![TAG_1, 0x01, 0x01], le: None,
            };
            let resp = handle(&apdu, &mut store, version);
            let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
            assert_eq!(tlvs[0].value.len(), 2, "{:?}", version);
            assert_eq!(
                u16::from_be_bytes([tlvs[0].value[0], tlvs[0].value[1]]),
                persistent,
                "{:?}", version
            );
        }
    }
}
