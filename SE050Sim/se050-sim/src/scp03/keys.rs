/* keys.rs
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

//! Static Platform SCP03 key material (ENC / MAC / DEK) and the key version
//! number. On real silicon these live in the GlobalPlatform card manager,
//! not in applet object space, so they are held here as configuration rather
//! than in the ObjectStore.
//!
//! Defaults mirror the keys the NXP Plug & Trust SDK (v04.07.01) compiles in
//! for a 07_02 build, taken from sss/ex/inc/ex_sss_tp_scp03_keys.h. A 07_02
//! build selects the SE050E OEF 0001A921 set; the 03_XX build selects the
//! SE050_DEVKIT set. Every value can be overridden at runtime via env vars,
//! mirroring the SDK's own EX_SSS_BOOT_SCP03_PATH key-file mechanism:
//!   SE050_SIM_SCP03_ENC / _MAC / _DEK  (hex, 16/24/32 bytes)
//!   SE050_SIM_SCP03_KVN                (u8, e.g. 0x0B)

use crate::applet::AppletVersion;

/// SE05x platform SCP key version number
/// (ex_sss_auth.h EX_SSS_AUTH_SE05X_KEY_VERSION_NO). Bench-verified: the
/// SE050E returns this KVN in the INITIALIZE UPDATE key-info bytes when the
/// host sends P1=0x00.
pub const DEFAULT_KVN: u8 = 0x0B;

/// SCP03 "i" parameter reported in the INITIALIZE UPDATE key-info bytes.
/// Bench-verified 0x00 on the SE050E (random card challenge, no pseudo-random
/// bit, so no 3-byte sequence counter is appended to the response).
pub const I_PARAM: u8 = 0x00;

/// 10-byte key diversification data returned by INITIALIZE UPDATE. On real
/// silicon this is chip-specific and not validated by the host in platform
/// SCP (diversification is off). The value here is the constant the bench
/// SE050E returned; a fixed placeholder is sufficient for interop.
pub const KEY_DIVERSIFICATION_DATA: [u8; 10] =
    [0x90, 0x03, 0x20, 0x19, 0x07, 0x38, 0x24, 0x20, 0x25, 0x02];

// SE050E OEF 0001A921 set (Plug & Trust v04.07.01, 07_02 build default).
const SE050E_ENC: [u8; 16] = [
    0xD2, 0xDB, 0x63, 0xE7, 0xA0, 0xA5, 0xAE, 0xD7, 0x2A, 0x64, 0x60, 0xC4, 0xDF, 0xDC, 0xAF, 0x64,
];
const SE050E_MAC: [u8; 16] = [
    0x73, 0x8D, 0x5B, 0x79, 0x8E, 0xD2, 0x41, 0xB0, 0xB2, 0x47, 0x68, 0x51, 0x4B, 0xFB, 0xA9, 0x5B,
];
const SE050E_DEK: [u8; 16] = [
    0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8, 0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F,
];

// SE050_DEVKIT set (Plug & Trust v04.07.01, 03_XX build default).
const DEVKIT_ENC: [u8; 16] = [
    0x35, 0xC2, 0x56, 0x45, 0x89, 0x58, 0xA3, 0x4F, 0x61, 0x36, 0x15, 0x5F, 0x82, 0x09, 0xD6, 0xCD,
];
const DEVKIT_MAC: [u8; 16] = [
    0xAF, 0x17, 0x7D, 0x5D, 0xBD, 0xF7, 0xC0, 0xD5, 0xC1, 0x0A, 0x05, 0xB9, 0xF1, 0x60, 0x7F, 0x78,
];
const DEVKIT_DEK: [u8; 16] = [
    0xA1, 0xBC, 0x84, 0x38, 0xBF, 0x77, 0x93, 0x5B, 0x36, 0x1A, 0x44, 0x25, 0xFE, 0x79, 0xFA, 0x29,
];

/// Static Platform SCP03 keys plus the key version number.
#[derive(Debug, Clone)]
pub struct Scp03Config {
    pub kvn: u8,
    pub enc: Vec<u8>,
    pub mac: Vec<u8>,
    /// DEK is stored for completeness (PUT KEY) but is unused today.
    pub dek: Vec<u8>,
}

impl Scp03Config {
    /// Build the key set for the given applet personality, applying any env
    /// overrides. Re-read on every INITIALIZE UPDATE, matching the
    /// AppletVersion::from_env per-APDU idiom.
    pub fn from_env(version: AppletVersion) -> Self {
        let (enc, mac, dek) = if matches!(version, AppletVersion::V3_1_1) {
            (DEVKIT_ENC, DEVKIT_MAC, DEVKIT_DEK)
        } else {
            (SE050E_ENC, SE050E_MAC, SE050E_DEK)
        };
        Scp03Config {
            kvn: env_u8("SE050_SIM_SCP03_KVN").unwrap_or(DEFAULT_KVN),
            enc: env_key("SE050_SIM_SCP03_ENC").unwrap_or_else(|| enc.to_vec()),
            mac: env_key("SE050_SIM_SCP03_MAC").unwrap_or_else(|| mac.to_vec()),
            dek: env_key("SE050_SIM_SCP03_DEK").unwrap_or_else(|| dek.to_vec()),
        }
    }
}

/// Parse a hex env var into a 16/24/32-byte AES key. A malformed value falls
/// back to the compiled-in default, but warns: silently using a different key
/// than the operator intended shows up much later as an unexplained
/// authentication failure.
fn env_key(name: &str) -> Option<Vec<u8>> {
    let raw = std::env::var(name).ok()?;
    match hex::decode(raw.trim()) {
        Ok(bytes) if matches!(bytes.len(), 16 | 24 | 32) => Some(bytes),
        Ok(bytes) => {
            log::warn!(
                "{} is {} bytes; expected a 16, 24 or 32 byte hex key. Using the default.",
                name,
                bytes.len()
            );
            None
        }
        Err(e) => {
            log::warn!("{} is not valid hex ({}). Using the default.", name, e);
            None
        }
    }
}

fn env_u8(name: &str) -> Option<u8> {
    let raw = std::env::var(name).ok()?;
    let raw = raw.trim();
    let raw = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(raw);
    u8::from_str_radix(raw, 16).ok()
}
