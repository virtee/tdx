// SPDX-License-Identifier: Apache-2.0

use crate::vm::linux::types::Capabilities;

/// Trust Domain eXtensions sub-ioctl() commands
#[repr(u32)]
pub enum CmdId {
    GetCapabilities = 0,
}

/// Contains information for the sub-ioctl() command to be run. This is
/// equivalent to `struct kvm_tdx_cmd` in the kernel.
#[derive(Default)]
#[repr(C)]
pub struct Cmd {
    /// TDX command identifier
    pub id: u32,

    /// Flags for sub-command. If sub-command doesn't use it, set to zero.
    pub flags: u32,

    /// A u64 representing a generic pointer to the respective ioctl input.
    /// This data is read differently according to the TDX ioctl identifier.
    pub data: u64,

    /// Auxiliary error code. The sub-command may return TDX SEAMCALL status
    /// code in addition to -Exxx.
    pub error: u64,

    /// Reserved.
    pub _unused: u64,
}

impl From<&Capabilities> for Cmd {
    fn from(caps: &Capabilities) -> Self {
        Self {
            id: CmdId::GetCapabilities as u32,
            flags: 0,
            data: caps as *const Capabilities as _,
            error: 0,
            _unused: 0,
        }
    }
}
