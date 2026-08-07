/* applet.rs
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

/// Applet personality selection.
///
/// The simulator can present itself as any of the three parts that were
/// bench-characterized on real silicon (August 2026, see
/// SE050Sim/HARDWARE_VALIDATION.md): an SE050C running applet 3.1.1, an
/// SE051 running applet 7.2.0, or an SE050E running applet 7.2.0 with
/// the RSA feature bits disabled. Almost all behavior is identical
/// across the three; the differences the simulator models are:
///
/// * SELECT / GetVersion version bytes (the SE050E's appletConfig word
///   clears the RSA_PLAIN and RSA_CRT bits: 0x3f9f vs the SE051's
///   0x3fff).
/// * GetFreeMemory per-type values. All three parts reply with a 2-byte
///   value (the SE050E clamps PERSISTENT at 0x7FFF); the v04.07.01
///   middleware parses U16 for every applet below minor version 0x10
///   and U32 only for the SE052F family.
/// * GetRandom maximum request size (880 bytes on the SE050C, 1018 on
///   the SE051 and SE050E).
/// * ReadType secure-object type codes for EC keys (generic 0x01/0x03
///   on 3.x, curve-specific on 7.2).
/// * CreateECCurve on an already existing curve: applet 7.2 refuses
///   with SW 0x6985; applet 3.1.1 returns 0x9000 and silently resets
///   the curve to a parameter-less state (subsequent key generation on
///   it fails 0x6985 until the parameters are uploaded again).
/// * RSA: the SE050E refuses key generation with SW 0x6985 and key
///   import with SW 0x6A80; wolfSSL's wolfcrypt suite consequently
///   fails its RSA test with WC_HW_E against real SE050E silicon.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppletVersion {
    /// SE050C, applet 3.1.1 (ATR historical bytes "JCOP4").
    V3_1_1,
    /// SE051, applet 7.2.0 (ATR historical bytes "eSE051"). Default.
    V7_2_0,
    /// SE050E, applet 7.2.0 with RSA disabled in appletConfig (ATR
    /// historical bytes also read "eSE051" on real parts).
    V7_2_0E,
}

impl AppletVersion {
    /// Read the personality from the SE050_SIM_APPLET environment
    /// variable. Unset selects 7.2.0, matching the version the
    /// simulator has always advertised; see `from_token` for the
    /// accepted values.
    pub fn from_env() -> Self {
        match std::env::var("SE050_SIM_APPLET") {
            Ok(v) => Self::from_token(&v),
            Err(_) => AppletVersion::V7_2_0,
        }
    }

    /// Parse a personality token. Accepts "e", "se050e", "7.2.0e" --
    /// any value ending in "e" or "E" -- for the SE050E; "3", "3.1.1"
    /// for the SE050C; and anything else ("7", "7.2", "7.2.0",
    /// unrecognized) for the SE051.
    pub fn from_token(token: &str) -> Self {
        let t = token.trim().to_ascii_lowercase();
        if t.ends_with('e') {
            AppletVersion::V7_2_0E
        } else if t.starts_with('3') {
            AppletVersion::V3_1_1
        } else {
            AppletVersion::V7_2_0
        }
    }

    /// 7-byte version blob returned by SELECT and GetVersion:
    /// major, minor, patch, appletConfig (2B), secureBox (2B).
    /// Captured from real parts: SE050C applet 3.1.1 returns
    /// 03 01 01 6f ff 01 0b, SE051 applet 7.2.0 returns
    /// 07 02 00 3f ff ff ff, SE050E applet 7.2.0 returns
    /// 07 02 00 3f 9f ff ff (appletConfig clears RSA_PLAIN 0x0020
    /// and RSA_CRT 0x0040).
    pub fn version_bytes(self) -> [u8; 7] {
        match self {
            AppletVersion::V3_1_1 => [0x03, 0x01, 0x01, 0x6F, 0xFF, 0x01, 0x0B],
            AppletVersion::V7_2_0 => [0x07, 0x02, 0x00, 0x3F, 0xFF, 0xFF, 0xFF],
            AppletVersion::V7_2_0E => [0x07, 0x02, 0x00, 0x3F, 0x9F, 0xFF, 0xFF],
        }
    }

    /// Largest GetRandom request the applet serves; one byte more
    /// returns SW 0x6985 (bench-measured: 880 on SE050C 3.1.1, 1018 on
    /// SE051 7.2.0 and SE050E).
    pub fn get_random_max(self) -> usize {
        match self {
            AppletVersion::V3_1_1 => 880,
            AppletVersion::V7_2_0 | AppletVersion::V7_2_0E => 1018,
        }
    }

    /// Whether the applet supports RSA at all. The SE050E's applet
    /// build has the RSA_PLAIN / RSA_CRT feature bits cleared
    /// (bench-verified: keygen refuses 0x6985, import refuses 0x6A80).
    pub fn supports_rsa(self) -> bool {
        !matches!(self, AppletVersion::V7_2_0E)
    }

    /// Whether this is a 7.2-generation applet (SE051 or SE050E).
    /// Gates the 7.2-specific read behaviors: curve-specific ReadType
    /// codes and ReadObjectAttributes support. Bench-verified: the
    /// SE050E reports the same curve-specific type codes as the SE051
    /// (P-256 pair 0x29, P-521 pair 0x31).
    pub fn is_v7(self) -> bool {
        !matches!(self, AppletVersion::V3_1_1)
    }

    /// GetFreeMemory reply for a memory type, as measured on the bench
    /// parts. All three parts reply with a 2-byte big-endian value; the
    /// SE050E reports PERSISTENT clamped at 0x7FFF. (An earlier revision
    /// emitted 4 bytes for 7.2.0 after misreading the middleware's
    /// SE052F-only U32 parse path; the v04.07.01 middleware rejects
    /// TLV values longer than 2 bytes for these applets.)
    pub fn free_memory_bytes(self, memory_type: u8) -> Option<Vec<u8>> {
        let (persistent, transient_reset, transient_deselect): (u16, u16, u16) =
            match self {
                AppletVersion::V3_1_1 => (31304, 575, 560),
                AppletVersion::V7_2_0 => (21000, 605, 592),
                AppletVersion::V7_2_0E => (32767, 796, 784),
            };
        let value = match memory_type {
            0x01 => persistent,
            0x02 => transient_reset,
            0x03 => transient_deselect,
            _ => return None,
        };
        Some(value.to_be_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_token_mapping() {
        for (token, expected) in [
            ("3", AppletVersion::V3_1_1),
            ("3.1.1", AppletVersion::V3_1_1),
            ("7", AppletVersion::V7_2_0),
            ("7.2.0", AppletVersion::V7_2_0),
            ("e", AppletVersion::V7_2_0E),
            ("E", AppletVersion::V7_2_0E),
            ("se050e", AppletVersion::V7_2_0E),
            ("SE050E", AppletVersion::V7_2_0E),
            ("7.2.0e", AppletVersion::V7_2_0E),
            // The ending-in-e rule takes precedence over the leading-3
            // rule, matching the documented behavior.
            ("3e", AppletVersion::V7_2_0E),
            (" se050e ", AppletVersion::V7_2_0E),
            ("bogus", AppletVersion::V7_2_0),
            ("", AppletVersion::V7_2_0),
        ] {
            assert_eq!(AppletVersion::from_token(token), expected,
                       "token {:?}", token);
        }
    }

    #[test]
    fn test_personality_traits() {
        assert!(AppletVersion::V3_1_1.supports_rsa());
        assert!(AppletVersion::V7_2_0.supports_rsa());
        assert!(!AppletVersion::V7_2_0E.supports_rsa());
        // The SE050E is a 7.2-generation part: it must get the
        // curve-specific ReadType codes, not the 3.x generic ones.
        assert!(!AppletVersion::V3_1_1.is_v7());
        assert!(AppletVersion::V7_2_0.is_v7());
        assert!(AppletVersion::V7_2_0E.is_v7());
        // All personalities reply GetFreeMemory as 2-byte values.
        for v in [
            AppletVersion::V3_1_1,
            AppletVersion::V7_2_0,
            AppletVersion::V7_2_0E,
        ] {
            for mem_type in [0x01u8, 0x02, 0x03] {
                assert_eq!(v.free_memory_bytes(mem_type).unwrap().len(), 2);
            }
            assert!(v.free_memory_bytes(0x04).is_none());
        }
    }
}
