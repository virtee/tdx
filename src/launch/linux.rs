// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

pub const NR_CPUID_CONFIGS: usize = 24;

/// Trust Domain eXtensions sub-ioctl() commands
#[repr(u32)]
pub enum CmdId {
    GetCapabilities,
    InitVm,
    InitVcpu,
    InitMemRegion,
    FinalizeVm,
}

/// Contains information for the sub-ioctl() command to be run. This is
/// equivalent to `struct kvm_tdx_cmd` in the kernel.
#[derive(Default)]
#[repr(C)]
pub struct Cmd<'a, T: 'a> {
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

    _phantom: PhantomData<&'a T>,
}

impl<'a, T: 'a> Cmd<'a, T> {
    pub fn from(id: CmdId, data: &'a T) -> Self {
        Self {
            id: id as u32,
            flags: 0,
            data: data as *const T as _,
            error: 0,
            _phantom: PhantomData,
        }
    }
}

impl Default for super::bindings::kvm_tdx_capabilities {
    fn default() -> Self {
        Self {
            supported_attrs: 0,
            supported_xfam: 0,
            reserved: [0; 254],
            cpuid: kvm_bindings::kvm_cpuid2::default(),
        }
    }
}
