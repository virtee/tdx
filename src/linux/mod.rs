// SPDX-License-Identifier: Apache-2.0

/// Trust Domain eXtensions sub-ioctl() commands
#[repr(u32)]
pub enum CmdId {
    GetCapabilities = 0,
    InitVm = 1,
    InitVcpu = 2,
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
