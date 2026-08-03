/* curve.rs
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

/// EC curve object management: CreateECCurve, SetECCurveParam,
/// DeleteECCurve, ReadECCurveList.
///
/// Weierstrass curves are dynamic objects on real applets: they must
/// be created and have all five parameters (A, B, G, N, PRIME)
/// uploaded before key operations on them succeed, and this state
/// persists across sessions. Bench-verified behaviors this module
/// models (SE050C applet 3.1.1 + SE051 applet 7.2.0, August 2026):
///
/// * Key generation on a missing or parameter-less curve fails 0x6985.
/// * A created but parameter-less curve still shows as SET (0x02) in
///   ReadECCurveList -- the list tracks existence, not usability.
/// * CreateECCurve on an existing curve: applet 7.2 refuses 0x6985;
///   applet 3.1.1 returns 0x9000 and silently resets the curve to the
///   parameter-less state (wiping a provisioned curve!).
/// * ReadECCurveList entries are 0x02 = SET / 0x01 = NOT_SET
///   (kSE05x_SetIndicator values).

use crate::apdu::*;
use crate::applet::AppletVersion;
use crate::object_store::ObjectStore;
use crate::tlv::{self, Tlv, TAG_1, TAG_2};

/// Number of entries in the ReadECCurveList response
/// (kSE05x_ECCurve_Total_Weierstrass_Curves).
const WEIERSTRASS_CURVE_COUNT: u8 = 0x11;

fn curve_id_from_tag1(apdu: &ParsedApdu) -> Option<u8> {
    let tlvs = apdu.parse_tlvs().ok()?;
    let t = tlv::find_tlv(&tlvs, TAG_1)?;
    if t.value.len() == 1 {
        Some(t.value[0])
    } else {
        None
    }
}

/// CreateECCurve: INS_WRITE, P1_CURVE, P2_CREATE, Tag1=curve id (1B).
pub fn handle_create(
    apdu: &ParsedApdu,
    store: &mut ObjectStore,
    version: AppletVersion,
) -> ApduResponse {
    let Some(curve_id) = curve_id_from_tag1(apdu) else {
        return ApduResponse::error(SW_WRONG_DATA);
    };
    if curve_id == 0 || curve_id > WEIERSTRASS_CURVE_COUNT {
        return ApduResponse::error(SW_WRONG_DATA);
    }
    if store.curve_exists(curve_id) {
        return match version {
            // Bench-verified on the SE051: re-creating an existing
            // curve is refused and the curve is left intact.
            AppletVersion::V7_2_0 => ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED),
            // Bench-verified on the SE050C: the duplicate create is
            // accepted and resets the curve to param-less, so key
            // generation on it fails until the parameters are
            // uploaded again.
            AppletVersion::V3_1_1 => {
                store.curve_reset(curve_id);
                ApduResponse::success()
            }
        };
    }
    store.curve_create(curve_id);
    ApduResponse::success()
}

/// SetECCurveParam: INS_WRITE, P1_CURVE, P2_PARAM,
/// Tag1=curve id (1B), Tag2=param type (1B bit), Tag3=param value.
/// The parameter values themselves are not stored -- the simulator's
/// crypto backends carry the standard NIST constants -- only the
/// completeness bitmask matters.
pub fn handle_set_param(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let tlvs = match apdu.parse_tlvs() {
        Ok(t) => t,
        Err(_) => return ApduResponse::error(SW_WRONG_DATA),
    };
    let curve_id = match tlv::find_tlv(&tlvs, TAG_1) {
        Some(t) if t.value.len() == 1 => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    let param = match tlv::find_tlv(&tlvs, TAG_2) {
        Some(t) if t.value.len() == 1 => t.value[0],
        _ => return ApduResponse::error(SW_WRONG_DATA),
    };
    if !matches!(param, 0x01 | 0x02 | 0x04 | 0x08 | 0x10) {
        return ApduResponse::error(SW_WRONG_DATA);
    }
    if !store.curve_exists(curve_id) {
        return ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED);
    }
    store.curve_add_param(curve_id, param);
    ApduResponse::success()
}

/// DeleteECCurve: INS_MGMT, P1_CURVE, P2_DELETE_OBJECT, Tag1=curve id.
pub fn handle_delete(apdu: &ParsedApdu, store: &mut ObjectStore) -> ApduResponse {
    let Some(curve_id) = curve_id_from_tag1(apdu) else {
        return ApduResponse::error(SW_WRONG_DATA);
    };
    if store.curve_delete(curve_id) {
        ApduResponse::success()
    } else {
        ApduResponse::error(SW_CONDITIONS_NOT_SATISFIED)
    }
}

/// ReadECCurveList: INS_READ, P1_CURVE, P2_LIST. Response Tag1 holds
/// one byte per Weierstrass curve ID 0x01..=0x11: 0x02 if the curve
/// object exists (parameterized or not), 0x01 otherwise.
pub fn handle_list(store: &ObjectStore) -> ApduResponse {
    let list: Vec<u8> = (1..=WEIERSTRASS_CURVE_COUNT)
        .map(|id| if store.curve_exists(id) { 0x02 } else { 0x01 })
        .collect();
    ApduResponse::success_with_tlvs(&[Tlv::new(TAG_1, &list)])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_apdu(curve_id: u8) -> ParsedApdu {
        ParsedApdu {
            cla: 0x80,
            ins: INS_WRITE,
            p1: P1_CURVE,
            p2: P2_CREATE,
            data: vec![TAG_1, 0x01, curve_id],
            le: None,
        }
    }

    fn param_apdu(curve_id: u8, param: u8) -> ParsedApdu {
        ParsedApdu {
            cla: 0x80,
            ins: INS_WRITE,
            p1: P1_CURVE,
            p2: P2_PARAM,
            data: vec![TAG_1, 0x01, curve_id, TAG_2, 0x01, param, TAG_3_LOCAL, 0x01, 0xAA],
            le: None,
        }
    }

    const TAG_3_LOCAL: u8 = 0x43;

    #[test]
    fn test_duplicate_create_is_version_dependent() {
        // SE051 7.2.0 refuses; SE050C 3.1.1 accepts and wipes params
        // (both bench-verified -- the 3.1.1 wipe broke a provisioned
        // P-256 curve during the August 2026 session).
        let mut store = ObjectStore::new(); // P-256 (0x03) provisioned
        assert!(store.curve_ready(0x03));

        let resp = handle_create(&create_apdu(0x03), &mut store, AppletVersion::V7_2_0);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(store.curve_ready(0x03), "7.2 dup create must not touch the curve");

        let resp = handle_create(&create_apdu(0x03), &mut store, AppletVersion::V3_1_1);
        assert_eq!(resp.sw, 0x9000);
        assert!(store.curve_exists(0x03));
        assert!(!store.curve_ready(0x03), "3.1.1 dup create wipes the params");
    }

    #[test]
    fn test_param_upload_completes_curve() {
        let mut store = ObjectStore::new();
        store.curve_delete(0x05);
        let resp = handle_create(&create_apdu(0x05), &mut store, AppletVersion::V7_2_0);
        assert_eq!(resp.sw, 0x9000);
        assert!(!store.curve_ready(0x05));
        for param in [0x01, 0x02, 0x04, 0x08, 0x10] {
            let resp = handle_set_param(&param_apdu(0x05, param), &mut store);
            assert_eq!(resp.sw, 0x9000);
        }
        assert!(store.curve_ready(0x05));
    }

    #[test]
    fn test_set_param_on_missing_curve_fails() {
        let mut store = ObjectStore::new();
        store.curve_delete(0x05);
        let resp = handle_set_param(&param_apdu(0x05, 0x01), &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_delete_missing_curve_fails() {
        let mut store = ObjectStore::new();
        store.curve_delete(0x05);
        let apdu = ParsedApdu {
            cla: 0x80,
            ins: INS_MGMT,
            p1: P1_CURVE,
            p2: P2_DELETE_OBJECT,
            data: vec![TAG_1, 0x01, 0x05],
            le: None,
        };
        let resp = handle_delete(&apdu, &mut store);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_list_reflects_state_with_set_indicator_values() {
        // 0x02 = SET, 0x01 = NOT_SET (kSE05x_SetIndicator). A created
        // but param-less curve still lists as SET, as on hardware.
        let mut store = ObjectStore::new();
        store.curve_delete(0x01);
        store.curve_delete(0x05);
        store.curve_create(0x05); // param-less

        let resp = handle_list(&store);
        assert_eq!(resp.sw, 0x9000);
        let tlvs = crate::tlv::parse_tlvs(&resp.data).unwrap();
        let list = &tlv::find_tlv(&tlvs, TAG_1).unwrap().value;
        assert_eq!(list.len(), 0x11);
        assert_eq!(list[0], 0x01, "P-192 deleted -> NOT_SET");
        assert_eq!(list[1], 0x02, "P-224 default-provisioned -> SET");
        assert_eq!(list[2], 0x02, "P-256 default-provisioned -> SET");
        assert_eq!(list[4], 0x02, "param-less P-521 still lists as SET");
        assert_eq!(list[5], 0x01, "brainpool never created -> NOT_SET");
    }
}
