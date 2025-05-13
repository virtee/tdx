// SPDX-License-Identifier: Apache-2.0

mod bindings;
mod linux;

use bindings::{kvm_tdx_capabilities, kvm_tdx_init_mem_region, kvm_tdx_init_vm};
use kvm_bindings::kvm_enable_cap;
use linux::{Cmd, CmdId, TdxError, NR_CPUID_CONFIGS};

use bitflags::bitflags;
use kvm_ioctls::VmFd;

// Defined in linux/arch/x86/include/uapi/asm/kvm.h
pub const KVM_X86_TDX_VM: u64 = 5;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = size_in_bytes.div_ceil(size_of::<T>());
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * std::mem::size_of::<F>();
    let vec_size_bytes = std::mem::size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Handle to the TDX VM file descriptor
pub struct TdxVm {}

impl TdxVm {
    /// Create a new TDX VM with KVM
    pub fn new(vm_fd: &VmFd) -> Result<Self, TdxError> {
        let mut cap: kvm_enable_cap = kvm_enable_cap {
            cap: kvm_bindings::KVM_CAP_X2APIC_API,
            ..Default::default()
        };
        cap.args[0] = (1 << 0) | (1 << 1);
        vm_fd.enable_cap(&cap).unwrap();

        Ok(Self {})
    }

    /// Retrieve information about the Intel TDX module
    pub fn get_capabilities(&self, fd: &VmFd) -> Result<TdxCapabilities, TdxError> {
        let mut caps = kvm_tdx_capabilities::default();

        let mut defaults = Vec::with_capacity(NR_CPUID_CONFIGS);
        (0..NR_CPUID_CONFIGS)
            .for_each(|_| defaults.push(kvm_bindings::kvm_cpuid_entry2::default()));
        let mut cpuid_entries = vec_with_array_field::<
            kvm_tdx_capabilities,
            kvm_bindings::kvm_cpuid_entry2,
        >(NR_CPUID_CONFIGS);
        cpuid_entries[0].cpuid.nent = NR_CPUID_CONFIGS as u32;
        cpuid_entries[0].cpuid.padding = 0;
        unsafe {
            let cpuid_entries_slice: &mut [kvm_bindings::kvm_cpuid_entry2] = cpuid_entries[0]
                .cpuid
                .entries
                .as_mut_slice(NR_CPUID_CONFIGS);
            cpuid_entries_slice.copy_from_slice(defaults.as_slice());
        }
        caps.cpuid.nent = NR_CPUID_CONFIGS as u32;
        caps.cpuid.padding = 0;
        let mut cmd: Cmd<kvm_tdx_capabilities> =
            Cmd::from(CmdId::GetCapabilities, &cpuid_entries[0]);

        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(TdxCapabilities {
            attributes: AttributesFlags::from_bits_truncate(cpuid_entries[0].supported_attrs),
            xfam: XFAMFlags::from_bits_truncate(cpuid_entries[0].supported_xfam),
            cpuid_configs: unsafe {
                cpuid_entries[0]
                    .cpuid
                    .entries
                    .as_slice(cpuid_entries[0].cpuid.nent as usize)
                    .to_vec()
            },
        })
    }

    /// Do additional VM initialization that is specific to Intel TDX
    pub fn init_vm(
        &self,
        fd: &VmFd,
        caps: &TdxCapabilities,
        cpuid: kvm_bindings::CpuId,
    ) -> Result<(), TdxError> {
        let mut defaults: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid.as_slice().to_vec();
        defaults.resize(
            kvm_bindings::KVM_MAX_CPUID_ENTRIES,
            kvm_bindings::kvm_cpuid_entry2::default(),
        );

        let mut entries = vec_with_array_field::<kvm_tdx_init_vm, kvm_bindings::kvm_cpuid_entry2>(
            kvm_bindings::KVM_MAX_CPUID_ENTRIES,
        );
        entries[0].cpuid.nent = defaults.len() as u32;
        entries[0].cpuid.padding = 0;
        entries[0].attributes = caps.attributes.bits();
        entries[0].xfam = caps.xfam.bits();
        unsafe {
            let entries_slice: &mut [kvm_bindings::kvm_cpuid_entry2] = entries[0]
                .cpuid
                .entries
                .as_mut_slice(kvm_bindings::KVM_MAX_CPUID_ENTRIES);
            entries_slice.copy_from_slice(defaults.as_slice());
        }

        Self::tdx_filter_cpuid(&mut entries[0].cpuid, &caps.cpuid_configs);

        let mut cmd: Cmd<kvm_tdx_init_vm> = Cmd::from(CmdId::InitVm, &entries[0]);
        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    fn tdx_filter_cpuid(
        cpuids: &mut kvm_bindings::kvm_cpuid2,
        caps: &Vec<kvm_bindings::kvm_cpuid_entry2>,
    ) {
        let mut found = Vec::new();
        let entries = unsafe { cpuids.entries.as_mut_slice(cpuids.nent as usize) };
        for entry in &*entries {
            let conf = Self::cpuid_find_entry(caps, entry.function, entry.index);
            if conf.is_none() {
                continue;
            }
            let conf = conf.unwrap();

            found.push(kvm_bindings::kvm_cpuid_entry2 {
                function: entry.function,
                index: entry.index,
                flags: entry.flags,
                eax: entry.eax & conf.eax,
                ebx: entry.ebx & conf.ebx,
                ecx: entry.ecx & conf.ecx,
                edx: entry.edx & conf.edx,
                ..Default::default()
            });
        }

        for (i, entry) in found.iter().enumerate() {
            entries[i] = *entry;
        }
        cpuids.nent = found.len() as u32;
    }

    fn cpuid_find_entry(
        entries: &Vec<kvm_bindings::kvm_cpuid_entry2>,
        function: u32,
        index: u32,
    ) -> Option<kvm_bindings::kvm_cpuid_entry2> {
        for entry in entries {
            if entry.function == function && entry.index == index {
                return Some(*entry);
            }
        }
        None
    }

    /// Encrypt a memory continuous region
    pub fn init_mem_region(
        &self,
        fd: &VmFd,
        gpa: u64,
        nr_pages: u64,
        attributes: u32,
        source_addr: u64,
    ) -> Result<(), TdxError> {
        const TDVF_SECTION_ATTRIBUTES_MR_EXTEND: u32 = 1u32 << 0;
        let mem_region = kvm_tdx_init_mem_region {
            source_addr,
            gpa,
            nr_pages,
        };

        let mut cmd: Cmd<kvm_tdx_init_mem_region> = Cmd::from(CmdId::InitMemRegion, &mem_region);

        // determines if we also extend the measurement
        cmd.flags = if attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND > 0 {
            1
        } else {
            0
        };

        unsafe {
            fd.encrypt_op(&mut cmd)?;
        }

        Ok(())
    }

    /// Complete measurement of the initial TD contents and mark it ready to run
    pub fn finalize(&self, fd: &VmFd) -> Result<(), TdxError> {
        let mut cmd: Cmd<u64> = Cmd::from(CmdId::FinalizeVm, &0);
        unsafe {
            fd.encrypt_op(&mut cmd)?;
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

/// Provides information about the Intel TDX module
#[derive(Debug)]
pub struct TdxCapabilities {
    pub attributes: AttributesFlags,
    pub xfam: XFAMFlags,
    pub cpuid_configs: Vec<kvm_bindings::kvm_cpuid_entry2>,
}

/// Manually create the wrapper for KVM_MEMORY_ENCRYPT_OP since `kvm_ioctls` doesn't
/// support `.encrypt_op` for vcpu fds
use vmm_sys_util::*;
ioctl_iowr_nr!(
    KVM_MEMORY_ENCRYPT_OP,
    kvm_bindings::KVMIO,
    0xba,
    std::os::raw::c_ulong
);

pub struct TdxVcpu {}

impl TdxVcpu {
    pub fn init(fd: &kvm_ioctls::VcpuFd, hob_address: u64) -> Result<(), TdxError> {
        let mut cmd: Cmd<u64> = Cmd::from(CmdId::InitVcpu, &hob_address);
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(fd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            // can't return `ret` because it will just return -1 and not give the error
            // code. `cmd.error` will also just be 0.
            return Err(TdxError::from(errno::Error::last()));
        }
        Ok(())
    }
}
