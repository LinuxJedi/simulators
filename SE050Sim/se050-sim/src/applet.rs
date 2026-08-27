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
/// The simulator can present itself as any of the four parts that were
/// bench-characterized on real silicon (August 2026, see
/// SE050Sim/HARDWARE_VALIDATION.md): an SE050C running applet 3.1.1, an
/// SE051 running applet 7.2.0, an SE050E running applet 7.2.0 with the
/// RSA feature bits disabled, or an SE052F running applet 7.2.22. Almost
/// all behavior is identical across the four; the differences the
/// simulator models are:
///
/// * SELECT / GetVersion version bytes. The appletConfig word carries
///   the feature bits: SE051 0x3fff, SE050E 0x3f9f (clears RSA_PLAIN and
///   RSA_CRT), SE052F 0x26f2 (clears EDDSA, DH_MONT, DES, MIFARE and
///   RFU1 but keeps both RSA bits).
/// * GetFreeMemory reply *width* and per-type values. The 3.1.1, 7.2.0
///   and SE050E parts all reply with a 2-byte value (the SE050E clamps
///   PERSISTENT at 0x7FFF). The SE052F replies with 4 bytes -- its
///   PERSISTENT figure of 86336 does not fit in a U16 at all. See
///   `free_memory_is_u32`.
/// * GetRandom maximum request size (880 bytes on the SE050C, 1018 on
///   the SE051 and SE050E, 1003 on the SE052F).
/// * ReadType secure-object type codes for EC keys (generic 0x01/0x03
///   on 3.x, curve-specific on 7.2 and later).
/// * CreateECCurve on an already existing curve: applets 7.2 and later
///   refuse with SW 0x6985; applet 3.1.1 returns 0x9000 and silently
///   resets the curve to a parameter-less state (subsequent key
///   generation on it fails 0x6985 until the parameters are uploaded
///   again).
/// * RSA: the SE050E refuses key generation with SW 0x6985 and key
///   import with SW 0x6A80; wolfSSL's wolfcrypt suite consequently
///   fails its RSA test with WC_HW_E against real SE050E silicon. The
///   SE052F has RSA but restricts it -- see `rsa_min_key_bits` and
///   `supports_rsa_public_import`.
/// * Ed25519 / X25519: absent on the SE052F, which refuses key writes
///   on those curves with SW 0x6985 (see `supports_25519`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppletVersion {
    /// SE050C, applet 3.1.1 (ATR historical bytes "JCOP4").
    V3_1_1,
    /// SE051, applet 7.2.0 (ATR historical bytes "eSE051"). Default.
    V7_2_0,
    /// SE050E, applet 7.2.0 with RSA disabled in appletConfig (ATR
    /// historical bytes also read "eSE051" on real parts).
    V7_2_0E,
    /// SE052F, applet 7.2.22. Keeps RSA (with restrictions) but has no
    /// Ed25519 / X25519, and is the only part whose GetFreeMemory reply
    /// is 4 bytes wide. Real parts ship locked behind Platform SCP03 and
    /// their ATR historical bytes also read "SE051".
    V7_2_22F,
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

    /// Parse a personality token. Accepts "f", "52f", "se052f" -- any
    /// value ending in "f" -- plus exactly "7.2.22", for the SE052F; "e",
    /// "se050e", "7.2.0e" -- any value ending in "e" -- for the SE050E;
    /// "3", "3.1.1" for the SE050C; and anything else ("7", "7.2",
    /// "7.2.0", unrecognized) for the SE051.
    ///
    /// The suffix rules are checked before the leading-digit rule, so
    /// "3f" selects the SE052F and "3e" the SE050E.
    pub fn from_token(token: &str) -> Self {
        let t = token.trim().to_ascii_lowercase();
        if t.ends_with('f') || t == "7.2.22" {
            AppletVersion::V7_2_22F
        } else if t.ends_with('e') {
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
    /// and RSA_CRT 0x0040), SE052F applet 7.2.22 returns
    /// 07 02 16 26 f2 ff ff (appletConfig clears EDDSA 0x0004,
    /// DH_MONT 0x0008, DES 0x0100, MIFARE 0x0800, RFU1 0x1000 and the
    /// undocumented bit 0x0001, keeping both RSA bits).
    ///
    /// The patch byte matters beyond cosmetics: the v04.07.01
    /// middleware's SE05X_CHECK_52F_VERSION treats a patch of
    /// 0x10..=0x1F as the SE052 family, which switches GetFreeMemory to
    /// a U32 parse (see `free_memory_is_u32`).
    pub fn version_bytes(self) -> [u8; 7] {
        match self {
            AppletVersion::V3_1_1 => [0x03, 0x01, 0x01, 0x6F, 0xFF, 0x01, 0x0B],
            AppletVersion::V7_2_0 => [0x07, 0x02, 0x00, 0x3F, 0xFF, 0xFF, 0xFF],
            AppletVersion::V7_2_0E => [0x07, 0x02, 0x00, 0x3F, 0x9F, 0xFF, 0xFF],
            AppletVersion::V7_2_22F => [0x07, 0x02, 0x16, 0x26, 0xF2, 0xFF, 0xFF],
        }
    }

    /// Largest GetRandom request the applet serves; one byte more
    /// returns SW 0x6985 (bench-measured: 880 on SE050C 3.1.1, 1018 on
    /// SE051 7.2.0 and SE050E, 1003 on the SE052F).
    ///
    /// The SE052F figure was measured over Platform SCP03, which is the
    /// only channel a real SE052F serves -- the part ships locked and
    /// refuses plain GetRandom outright, so its plain-channel cap could
    /// not be measured. R-MAC and R-ENC overhead is the likely reason it
    /// sits below the 1018 the other 7.2 parts allow in plain mode.
    pub fn get_random_max(self) -> usize {
        match self {
            AppletVersion::V3_1_1 => 880,
            AppletVersion::V7_2_0 | AppletVersion::V7_2_0E => 1018,
            AppletVersion::V7_2_22F => 1003,
        }
    }

    /// Whether the applet supports the 25519 curves (Ed25519 signing and
    /// X25519 key agreement). The SE052F's appletConfig clears both
    /// EDDSA (0x0004) and DH_MONT (0x0008); bench-verified that key
    /// generation on either curve is refused with SW 0x6985. Key import
    /// on those curves is refused the same way here, which follows from
    /// the feature bits being clear but was not separately measured.
    pub fn supports_25519(self) -> bool {
        !matches!(self, AppletVersion::V7_2_22F)
    }

    /// Smallest RSA key size the applet will generate. Bench-verified on
    /// the SE052F: 1024-bit CRT key generation is refused 0x6985 while
    /// 2048-bit CRT generation (and RSASign with it) works.
    pub fn rsa_min_key_bits(self) -> u16 {
        match self {
            AppletVersion::V7_2_22F => 2048,
            _ => 1024,
        }
    }

    /// Whether the applet accepts an RSA *public* key import (modulus +
    /// exponent). Bench-verified on the SE052F: refused with SW 0x6A80,
    /// while key generation on the same part works. Private-component
    /// import was not exercised on that part and is left enabled.
    pub fn supports_rsa_public_import(self) -> bool {
        !matches!(self, AppletVersion::V7_2_22F)
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

    /// Whether GetFreeMemory replies with a 4-byte (U32) value instead
    /// of the usual 2-byte (U16) one.
    ///
    /// `Se05x_API_GetFreeMemory` picks its parser from
    /// `SE05X_CHECK_52F_VERSION(applet_version)`, which tests
    /// `(applet_version >> 8) & 0xFF` for the range 0x10..=0x1F. Because
    /// `applet_version` is `major<<24 | minor<<16 | patch<<8`, that byte
    /// is the applet *patch* number, which NXP overloads to mark the
    /// SE052 family. Applet 7.2.22 (patch 0x16) therefore takes the
    /// `tlvGet_U32` branch, while 3.1.1 / 7.2.0 / SE050E (patch 0x00)
    /// take `tlvGet_U16`.
    ///
    /// Getting this wrong is a hard failure rather than a subtle one:
    /// `tlvGet_U32` only accepts a 4-byte TLV value and `tlvGet_U16`
    /// only a 2-byte one, so a mismatched width makes the host call fail
    /// outright. Bench-confirmed on real SE052F silicon, where the call
    /// returns 0x9000 through the U32 path.
    pub fn free_memory_is_u32(self) -> bool {
        matches!(self, AppletVersion::V7_2_22F)
    }

    /// GetFreeMemory reply for a memory type, as measured on the bench
    /// parts. The 3.1.1, 7.2.0 and SE050E parts reply with a 2-byte
    /// big-endian value (the SE050E reports PERSISTENT clamped at
    /// 0x7FFF); the SE052F replies with 4 bytes, and its PERSISTENT
    /// figure of 86336 could not be expressed in 2 bytes at all, which
    /// is precisely why the U32 path exists.
    pub fn free_memory_bytes(self, memory_type: u8) -> Option<Vec<u8>> {
        let (persistent, transient_reset, transient_deselect): (u32, u32, u32) =
            match self {
                AppletVersion::V3_1_1 => (31304, 575, 560),
                AppletVersion::V7_2_0 => (21000, 605, 592),
                AppletVersion::V7_2_0E => (32767, 796, 784),
                AppletVersion::V7_2_22F => (86336, 1157, 1152),
            };
        let value = match memory_type {
            0x01 => persistent,
            0x02 => transient_reset,
            0x03 => transient_deselect,
            _ => return None,
        };
        Some(if self.free_memory_is_u32() {
            value.to_be_bytes().to_vec()
        } else {
            (value as u16).to_be_bytes().to_vec()
        })
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
            ("f", AppletVersion::V7_2_22F),
            ("F", AppletVersion::V7_2_22F),
            ("52f", AppletVersion::V7_2_22F),
            ("se052f", AppletVersion::V7_2_22F),
            ("SE052F", AppletVersion::V7_2_22F),
            ("7.2.22", AppletVersion::V7_2_22F),
            (" se052f ", AppletVersion::V7_2_22F),
            // The version token matches exactly: a longer string that
            // merely starts with it must not select the SE052F.
            ("7.2.220", AppletVersion::V7_2_0),
            ("7.2.22e", AppletVersion::V7_2_0E),
            // The suffix rules take precedence over the leading-3 rule,
            // matching the documented behavior.
            ("3e", AppletVersion::V7_2_0E),
            ("3f", AppletVersion::V7_2_22F),
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
        // The SE052F keeps both RSA appletConfig bits, unlike the E.
        assert!(AppletVersion::V7_2_22F.supports_rsa());
        // The SE050E and SE052F are 7.2-generation parts: they must get
        // the curve-specific ReadType codes, not the 3.x generic ones.
        assert!(!AppletVersion::V3_1_1.is_v7());
        assert!(AppletVersion::V7_2_0.is_v7());
        assert!(AppletVersion::V7_2_0E.is_v7());
        assert!(AppletVersion::V7_2_22F.is_v7());
        // 25519 curves: present everywhere except the SE052F.
        assert!(AppletVersion::V3_1_1.supports_25519());
        assert!(AppletVersion::V7_2_0.supports_25519());
        assert!(AppletVersion::V7_2_0E.supports_25519());
        assert!(!AppletVersion::V7_2_22F.supports_25519());
        // RSA restrictions are SE052F-only.
        assert_eq!(AppletVersion::V7_2_0.rsa_min_key_bits(), 1024);
        assert_eq!(AppletVersion::V7_2_22F.rsa_min_key_bits(), 2048);
        assert!(AppletVersion::V7_2_0.supports_rsa_public_import());
        assert!(!AppletVersion::V7_2_22F.supports_rsa_public_import());
        for mem_type in [0x01u8, 0x02, 0x03] {
            assert!(AppletVersion::V7_2_22F.free_memory_bytes(mem_type).is_some());
        }
    }

    #[test]
    fn test_free_memory_width_per_applet() {
        // A mismatched width is a hard host-side failure: tlvGet_U16
        // rejects a 4-byte value and tlvGet_U32 rejects a 2-byte one.
        for (v, want_len) in [
            (AppletVersion::V3_1_1, 2usize),
            (AppletVersion::V7_2_0, 2),
            (AppletVersion::V7_2_0E, 2),
            (AppletVersion::V7_2_22F, 4),
        ] {
            for mem_type in [0x01u8, 0x02, 0x03] {
                assert_eq!(
                    v.free_memory_bytes(mem_type).unwrap().len(),
                    want_len,
                    "{:?} type {:#04x}", v, mem_type
                );
            }
            assert!(v.free_memory_bytes(0x04).is_none(), "{:?}", v);
        }
        // The SE052F's PERSISTENT figure does not fit in a U16, which is
        // why the applet reports it over four bytes in the first place.
        let bytes = AppletVersion::V7_2_22F.free_memory_bytes(0x01).unwrap();
        assert_eq!(bytes, vec![0x00, 0x01, 0x51, 0x40]);
        assert_eq!(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                   86336);
        assert!(86336u32 > u16::MAX as u32);
    }
}
