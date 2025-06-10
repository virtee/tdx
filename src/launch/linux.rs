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

#[derive(Debug)]
pub struct TdxError {
    pub code: i32,
    pub message: String,
}

impl From<kvm_ioctls::Error> for TdxError {
    fn from(kvm_err: kvm_ioctls::Error) -> Self {
        TdxError::from(kvm_err.errno())
    }
}

impl From<std::io::Error> for TdxError {
    fn from(err: std::io::Error) -> Self {
        TdxError::from(err.raw_os_error().unwrap())
    }
}

impl From<i32> for TdxError {
    fn from(errno: i32) -> Self {
        match errno {
            7 => TdxError {
                code: 7,
                message: String::from("Invalid value for NR_CPUID_CONFIGS"),
            },
            25 => TdxError {
                code: 25,
                message: String::from("Inappropriate ioctl for device. Ensure the proper VM type is being used for the ioctl"),
            },
            _ => TdxError {
                code: errno,
                message: format!("errno: {}", errno),
            },
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
