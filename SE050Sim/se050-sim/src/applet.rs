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
/// The simulator can present itself as either of the two applet
/// generations that were bench-characterized on real silicon (August
/// 2026, see SE050Sim/HARDWARE_VALIDATION.md): an SE050C running applet
/// 3.1.1 or an SE051 running applet 7.2.0. Almost all behavior is
/// identical between the two; the differences the simulator models are:
///
/// * SELECT / GetVersion version bytes.
/// * GetFreeMemory response width (2 bytes on 3.x, 4 bytes on 7.2) and
///   the reported per-type values.
/// * GetRandom maximum request size (880 bytes on the SE050C, 1018 on
///   the SE051).
/// * ReadType secure-object type codes for EC keys (generic 0x01/0x03
///   on 3.x, curve-specific on 7.2).
/// * CreateECCurve on an already existing curve: applet 7.2 refuses
///   with SW 0x6985; applet 3.1.1 returns 0x9000 and silently resets
///   the curve to a parameter-less state (subsequent key generation on
///   it fails 0x6985 until the parameters are uploaded again).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppletVersion {
    /// SE050C, applet 3.1.1 (ATR historical bytes "JCOP4").
    V3_1_1,
    /// SE051, applet 7.2.0 (ATR historical bytes "eSE051"). Default.
    V7_2_0,
}

impl AppletVersion {
    /// Read the personality from the SE050_SIM_APPLET environment
    /// variable. Accepts "3", "3.1.1" (SE050C) and "7", "7.2", "7.2.0"
    /// (SE051). Unset or unrecognized values select 7.2.0, matching the
    /// version the simulator has always advertised.
    pub fn from_env() -> Self {
        match std::env::var("SE050_SIM_APPLET") {
            Ok(v) if v.starts_with('3') => AppletVersion::V3_1_1,
            _ => AppletVersion::V7_2_0,
        }
    }

    /// 7-byte version blob returned by SELECT and GetVersion:
    /// major, minor, patch, appletConfig (2B), secureBox (2B).
    /// Captured from real parts: SE050C applet 3.1.1 returns
    /// 03 01 01 6f ff 01 0b, SE051 applet 7.2.0 returns
    /// 07 02 00 3f ff ff ff.
    pub fn version_bytes(self) -> [u8; 7] {
        match self {
            AppletVersion::V3_1_1 => [0x03, 0x01, 0x01, 0x6F, 0xFF, 0x01, 0x0B],
            AppletVersion::V7_2_0 => [0x07, 0x02, 0x00, 0x3F, 0xFF, 0xFF, 0xFF],
        }
    }

    /// Largest GetRandom request the applet serves; one byte more
    /// returns SW 0x6985 (bench-measured: 880 on SE050C 3.1.1, 1018 on
    /// SE051 7.2.0).
    pub fn get_random_max(self) -> usize {
        match self {
            AppletVersion::V3_1_1 => 880,
            AppletVersion::V7_2_0 => 1018,
        }
    }

    /// GetFreeMemory reply for a memory type, as measured on the bench
    /// parts. Applet 3.x replies with a 2-byte value, 7.2 with 4 bytes
    /// (the v04.07.01 middleware parses U16 vs U32 accordingly).
    pub fn free_memory_bytes(self, memory_type: u8) -> Option<Vec<u8>> {
        let (persistent, transient_reset, transient_deselect): (u32, u32, u32) =
            match self {
                AppletVersion::V3_1_1 => (31304, 575, 560),
                AppletVersion::V7_2_0 => (21000, 605, 592),
            };
        let value = match memory_type {
            0x01 => persistent,
            0x02 => transient_reset,
            0x03 => transient_deselect,
            _ => return None,
        };
        Some(match self {
            AppletVersion::V3_1_1 => (value as u16).to_be_bytes().to_vec(),
            AppletVersion::V7_2_0 => value.to_be_bytes().to_vec(),
        })
    }
}
