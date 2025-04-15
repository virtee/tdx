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

    /// Reserved.
    pub _unused: u64,

    _phantom: PhantomData<&'a T>,
}

impl<'a, T: 'a> Cmd<'a, T> {
    pub fn from(id: CmdId, data: &'a T) -> Self {
        Self {
            id: id as u32,
            flags: 0,
            data: data as *const T as _,
            error: 0,
            _unused: 0,
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

/// CPUID_CONFIG is designed to enumerate how the host VMM may configure the
/// virtualization done by the Intel TDX module for a single CPUID leaf and
/// sub-leaf. This is equivalent to `struct kvm_tdx_cpuid_config` in the kernel.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct CpuidConfig {
    /// EAX input value to CPUID
    pub leaf: u32,

    /// ECX input value to CPUID. A value of -1 indicates a CPUID leaf with
    /// no sub-leaves.
    pub sub_leaf: u32,

    /// CPUID configuration information for the EAX register.
    pub eax: u32,

    /// CPUID configuration information for the EBX register.
    pub ebx: u32,

    /// CPUID configuration information for the ECX register.
    pub ecx: u32,

    /// CPUID configuration information for the EDX register.
    pub edx: u32,
}

/// Provides information about the Intel TDX module. This is equivalent to
/// `struct kvm_tdx_capabilities` in the kernel.
#[derive(Debug)]
#[repr(C)]
pub struct Capabilities {
    /// Bitmap where if any certain bit is 0, it must be 0 in any TD's
    /// ATTRIBUTES, which specifies various guest TD attributes. The value of
    /// this field reflects the Intel TDX module capabilities and configuration
    /// and CPU capabilities.
    pub attrs_fixed0: u64,

    /// Bitmap where if any certain bit is 1, it must be 1 in any TD's
    /// ATTRIBUTES, which specifies various guest TD attributes. The value of
    /// this field reflects the Intel TDX module capabilities and configuration
    /// and CPU capabilities.
    pub attrs_fixed1: u64,

    /// Bitmap where if any certain bit is 0, it must be 0 in any TD's XFAM.
    /// XFAM (eXtended Features Available Mask) determines the set of extended
    /// features available for use by the guest TD.
    pub xfam_fixed0: u64,

    /// Bitmap where if any certain bit is 1, it must be 1 in any TD's XFAM.
    /// XFAM (eXtended Features Available Mask) determines the set of extended
    /// features available for use by the guest TD.
    pub xfam_fixed1: u64,

    /// Supported Guest Physical Address Width
    pub supported_gpaw: u32,

    /// Padding space. Ignored
    _padding: u32,

    /// Reserved space. Ignored.
    _reserved: [u64; 251],

    /// Number of CPUID_CONFIG entries
    pub nr_cpuid_configs: u32,

    /// Enumeration of the CPUID leaves/sub-leaves that contain bit fields whose
    /// virtualization by the Intel TDX module is either:
    ///
    /// - Directly configurable (CONFIG_DIRECT) by the host VMM
    /// - Bits that the host VMM may allow to be 1 (ALLOW_DIRECT) and their
    ///   native value, as returned by the CPU, is 1
    ///
    /// Note that the virtualization of many CPUID bit fields not enumerated in
    /// this list is configurable indirectly via the XFAM and ATTRIBUTES assigned
    /// to a TD by the host VMM.
    pub cpuid_configs: [CpuidConfig; NR_CPUID_CONFIGS],
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            attrs_fixed0: 0,
            attrs_fixed1: 0,
            xfam_fixed0: 0,
            xfam_fixed1: 0,
            supported_gpaw: 0,
            _padding: 0,
            _reserved: [0; 251],

            nr_cpuid_configs: NR_CPUID_CONFIGS as u32,
            cpuid_configs: [Default::default(); NR_CPUID_CONFIGS],
        }
    }
}

/// TDX specific VM initialization information
#[derive(Debug)]
#[repr(C)]
pub struct InitVm {
    /// Guest TD attributes
    pub attributes: u64,

    /// Software-defined ID for non-owner-defined configuration of the guest TD
    /// (runtime or OS configuration)
    pub mrconfigid: [u64; 6],

    /// Software-defined ID for the guest TD’s owner
    pub mrowner: [u64; 6],

    /// Software-defined ID for owner-defined configuration of the guest TD
    /// (specific to the workload)
    pub mrownerconfig: [u64; 6],

    /// reserved for future extensibility
    reserved: [u64; 1004],

    /// direct configuration of CPUID leaves/subleaves virtualization
    pub cpuid_nent: u32,

    _padding: u32,

    pub cpuid_entries: [kvm_bindings::kvm_cpuid_entry2; 256],
}

impl InitVm {
    pub fn new(cpuid_entries: &Vec<kvm_bindings::kvm_cpuid_entry2>) -> Self {
        Self {
            cpuid_nent: cpuid_entries.len() as u32,
            cpuid_entries: cpuid_entries.as_slice().try_into().unwrap(),
            ..Default::default()
        }
    }
}

impl Default for InitVm {
    fn default() -> Self {
        Self {
            // Set the SEPT_VE_DISABLE bit by default to prevent an Extended Page Table
            // (EPT) violation to #VE caused by guest TD access of PENDING pages
            attributes: super::AttributesFlags::SEPT_VE_DISABLE.bits(),
            mrconfigid: [0; 6],
            mrowner: [0; 6],
            mrownerconfig: [0; 6],
            reserved: [0; 1004],
            cpuid_nent: 0,
            _padding: 0,
            cpuid_entries: [Default::default(); 256],
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TdxInitMemRegion {
    /// Host physical address of the target page to be added to the TD
    pub source_addr: u64,

    /// Guest physical address to be mapped
    pub gpa: u64,

    /// Number of pages to be mapped
    pub nr_pages: u64,
}
