// SPDX-License-Identifier: Apache-2.0

mod linux;

use crate::linux::{Cmd, CmdId, TdxError};
use crate::vm::linux::types::{Capabilities, CpuidConfig, InitMemRegion, InitVm};
use bitflags::bitflags;
use kvm_ioctls::{Kvm, VmFd};
use std::arch::x86_64;

// Defined in linux/arch/x86/include/uapi/asm/kvm.h
const KVM_X86_TDX_VM: u64 = 2;

/// Handle to the TDX VM file descriptor
pub struct TdxVm {
    pub fd: VmFd,
}

impl TdxVm {
    /// Create a new TDX VM with KVM
    pub fn new(kvm_fd: &Kvm) -> Result<Self, TdxError> {
        let vm_fd = kvm_fd.create_vm_with_type(KVM_X86_TDX_VM)?;
        Ok(Self { fd: vm_fd })
    }

    /// Retrieve information about the Intel TDX module
    pub fn get_capabilities(&self) -> Result<TdxCapabilities, TdxError> {
        let caps = Capabilities::default();
        let mut cmd: Cmd = Cmd::from(&caps);

        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(TdxCapabilities {
            attributes: Attributes {
                fixed0: AttributesFlags::from_bits_truncate(caps.attrs_fixed0),
                fixed1: AttributesFlags::from_bits_truncate(caps.attrs_fixed1),
            },
            xfam: Xfam {
                fixed0: XFAMFlags::from_bits_truncate(caps.xfam_fixed0),
                fixed1: XFAMFlags::from_bits_truncate(caps.xfam_fixed1),
            },
            supported_gpaw: caps.supported_gpaw,
            cpuid_configs: Vec::from(caps.cpuid_configs),
        })
    }

    /// Do additional VM initialization that is specific to Intel TDX
    pub fn init_vm(&self, kvm_fd: &Kvm, caps: &TdxCapabilities) -> Result<(), TdxError> {
        let cpuid = kvm_fd
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let mut cpuid_entries: Vec<kvm_bindings::kvm_cpuid_entry2> =
            cpuid.as_slice().iter().map(|e| (*e).into()).collect();

        // resize to 256 entries to make sure that InitVm is 8KB
        cpuid_entries.resize(256, kvm_bindings::kvm_cpuid_entry2::default());

        // hex for Ob1100000001011111111 based on the XSAVE state-components architecture
        let xcr0_mask = 0x602ff;
        // hex for 0b11111110100000000 based on the XSAVE state-components architecture
        let xss_mask = 0x1FD00;

        let xfam_fixed0 = caps.xfam.fixed0.bits();
        let xfam_fixed1 = caps.xfam.fixed1.bits();

        // patch cpuid
        for entry in cpuid_entries.as_mut_slice() {
            // get the configurable cpuid bits (can be set to 0 or 1) reported by TDX Module from
            // TdxCapabilities
            for cpuid_config in &caps.cpuid_configs {
                // 0xffffffff means the cpuid leaf has no subleaf
                if cpuid_config.leaf == entry.function
                    && (cpuid_config.sub_leaf == 0xffffffff || cpuid_config.sub_leaf == entry.index)
                {
                    entry.eax |= cpuid_config.eax;
                    entry.ebx |= cpuid_config.ebx;
                    entry.ecx |= cpuid_config.ecx;
                    entry.edx |= cpuid_config.edx;
                }
            }

            // mandatory patches for TDX based on XFAM values reported by TdxCapabilities
            match entry.index {
                // XSAVE features and state-components
                0xD => {
                    if entry.index == 0 {
                        // XSAVE XCR0 LO
                        entry.eax &= (xfam_fixed0 as u32) & (xcr0_mask as u32);
                        entry.eax |= (xfam_fixed1 as u32) & (xcr0_mask as u32);
                        // XSAVE XCR0 HI
                        entry.edx &= ((xfam_fixed0 & xcr0_mask) >> 32) as u32;
                        entry.edx |= ((xfam_fixed1 & xcr0_mask) >> 32) as u32;
                    } else if entry.index == 1 {
                        // XSAVE XCR0 LO
                        entry.ecx &= (xfam_fixed0 as u32) & (xss_mask as u32);
                        entry.ecx |= (xfam_fixed1 as u32) & (xss_mask as u32);
                        // XSAVE XCR0 HI
                        entry.edx &= ((xfam_fixed0 & xss_mask) >> 32) as u32;
                        entry.edx |= ((xfam_fixed1 & xss_mask) >> 32) as u32;
                    }
                }
                0x8000_0008 => {
                    // host physical address bits supported
                    let phys_bits = unsafe { x86_64::__cpuid(0x8000_0008).eax } & 0xff;
                    entry.eax = (entry.eax & 0xffff_ff00) | (phys_bits as u32 & 0xff);
                }
                _ => (),
            }
        }

        let mut cmd = Cmd::from(&InitVm::new(&cpuid_entries));
        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    /// Add a 4KB private page to a TD, mapped to the specified guest address,
    /// filled with the given page image at the host address. If `measure_memory_regions`
    /// is `true`, also updates the TD measurement with the page properties.
    pub fn init_mem_region(
        &self,
        measure_memory_regions: bool,
        init_mem_region: &TdxInitMemRegion,
    ) -> Result<(), TdxError> {
        let init_mem_region = &InitMemRegion::from(init_mem_region);
        let mut cmd = Cmd::from(init_mem_region);
        cmd.flags = measure_memory_regions as u32;
        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }
        Ok(())
    }

    /// Complete measurement of the initial TD contents and mark it ready to run
    pub fn finalize_vm(&self) -> Result<(), TdxError> {
        let mut cmd = Cmd::default();
        cmd.id = CmdId::FinalizeVm as u32;
        unsafe {
            self.fd.encrypt_op(&mut cmd)?;
        }
        Ok(())
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct AttributesFlags: u64 {
        /// TD Under Debug (TUD) group

        /// Bit 0. Guest TD runs in off-TD debug mode
        const DEBUG = 1;

        /// Bits 3:1. Reserved for future TUD flags
        const TUD_RESERVED = 0x7 << 1;

        /// TD Under Profiling (TUP) group

        /// Bit 4. The TD participates in HGS+ operation
        const HGS_PLUS_PROF = 1 << 4;

        /// Bit 5. The TD participates in system profiling using performance monitoring
        /// counters
        const PERF_PROF = 1 << 5;

        /// Bit 6. The TD participates in system profiling using core out-of-band
        /// telemetry
        const PMT_PROF = 1 << 6;

        /// Bits 15:7. Reserved for future TUP flags
        const TUP_RESERVED = 0x1FF << 7;

        /// Security (SEC) group

        /// Bits 22:16. Reserved for future SEC flags that will indicate positive impact on
        /// TD security
        const SEC_RESERVED_P = 0x7F << 16;

        /// Bits 23:26. Reserved for future SEC flags that will indicate negative impact on
        /// TD security
        const SEC_RESERVED_N = 0xF << 23;

        /// Bit 27. TD is allowed to use Linear Address Space Separation
        const LASS = 1 << 27;

        /// Bit 28. Disable EPT violation conversion to #VE on guest TD access of
        /// PENDING pages
        const SEPT_VE_DISABLE = 1 << 28;

        /// Bit 29. TD is migratable (using a Migration TD)
        const MIGRATABLE = 1 << 29;

        /// Bit 30. TD is allowed to use Supervisor Protection Keys
        const PKS = 1 << 30;

        /// Bit 31. TD is allowed to use Key Locker
        const KL = 1 << 31;

        /// RESERVED Group

        /// Bits 55:32. Reserved for future expansion of the SEC group
        const SEC_EXP_RESERVED = 0xFFFFFF << 32;

        /// OTHER group

        /// Bits 61:32. Reserved for future OTHER flags
        const OTHER_RESERVED = 0x3FFFFFFF << 32;

        /// Bit 62. The TD is a TDX Connet Provisioning Agent
        const TPA = 1 << 62;

        /// Bit 63. TD is allowed to use Perfmon and PERF_METRICS capabilities
        const PERFMON = 1 << 63;
    }

    #[derive(Debug)]
    pub struct XFAMFlags: u64 {
        /// Bit 0. Always enabled
        const FP = 1;

        /// Bit 1. Always enabled
        const SSE = 1 << 1;

        /// Bit 2. Execution is directly controlled by XCR0
        const AVX = 1 << 2;

        /// Bits 4:3. Being deprecated
        const MPX = 0x3 << 3;

        /// Bits 7:5. Execution is directly contrtolled by XCR0. May be enabled only if
        /// AVX is enabled
        const AVX512 = 0x7 << 5;

        /// Bit 8. Execution is controlled by IA32_RTIT_CTL
        const PT = 1 << 8;

        /// Bit 9. Execution is controlled by CR4.PKE
        const PK = 1 << 9;

        /// Bit 10. Execution is controlled by IA32_PASID MSR
        const ENQCMD = 1 << 10;

        /// Bits 12:11. Execution is controlled by CR4.CET
        const CET = 0x3 << 11;

        /// Bit 13. Hardware Duty Cycle is controlled by package-scope IA32_PKG_HDC_CTL
        /// and LP-scope IA32_PM_CTL1 MSRs
        const HDC = 1 << 13;

        /// Bit 14. Execution is controlled by CR4.UINTR
        const ULI = 1 << 14;

        /// Bit 15. Execution is controlled by IA32_LBR_CTL
        const LBR = 1 << 15;

        /// Bit 16. Execution of Hardware-Controlled Performance State is controlled by
        /// IA32_HWP MSRs
        const HWP = 1 << 16;

        /// Bits 18:17. Advanced Matrix Extensions (AMX) is directly controlled by XCR0
        const AMX = 0x3 << 17;
    }
}

/// Reflects the Intel TDX module capabilities and configuration and CPU
/// capabilities
#[derive(Debug)]
pub struct Attributes {
    pub fixed0: AttributesFlags,
    pub fixed1: AttributesFlags,
}

/// Determines the set of extended features available for use by the guest TD
#[derive(Debug)]
pub struct Xfam {
    pub fixed0: XFAMFlags,
    pub fixed1: XFAMFlags,
}

/// Provides information about the Intel TDX module
#[derive(Debug)]
pub struct TdxCapabilities {
    pub attributes: Attributes,
    pub xfam: Xfam,

    /// supported Guest Physical Address Width
    pub supported_gpaw: u32,

    pub cpuid_configs: Vec<CpuidConfig>,
}

/// Information to encrypt a contiguous memory region
#[derive(Debug)]
pub struct TdxInitMemRegion {
    /// private page image
    pub host_address: u64,

    /// guest address to map the private page image to
    pub guest_address: u64,

    /// number of 4KB private pages
    pub nr_pages: u64,
}

impl TdxInitMemRegion {
    pub fn new(host_address: u64, guest_address: u64, nr_pages: u64) -> Self {
        Self {
            host_address,
            guest_address,
            nr_pages,
        }
    }
}
