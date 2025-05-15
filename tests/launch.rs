// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;
use vmm_sys_util::*;

use tdx::launch::{TdxVcpu, TdxVm};
use tdx::tdvf;

// `mov eax,1000h` will set the value in the register eax (and rax since they both share the bottom 32 bits) to 1000h
// `jmp *%rax` will jump the program to the address that rax contains, which in this case will be 1000h
const FIRMWARE: &[u8; 7] = &[
    0xb8, 0x00, 0x10, 0x00, 0x00, // mov eax, 1000h
    0xff, 0xe0, // jmp *%rax
];

#[test]
fn launch() {
    const KVM_CAP_GUEST_MEMFD: u32 = 234;
    const KVM_CAP_MEMORY_MAPPING: u32 = 236;

    // create vm
    let kvm_fd = Kvm::new().unwrap();
    let vm_fd = kvm_fd
        .create_vm_with_type(tdx::launch::KVM_X86_TDX_VM)
        .unwrap();

    let mut cap: kvm_bindings::kvm_enable_cap = kvm_bindings::kvm_enable_cap {
        ..Default::default()
    };
    cap.cap = kvm_bindings::KVM_CAP_SPLIT_IRQCHIP;
    cap.args[0] = 24;
    vm_fd.enable_cap(&cap).unwrap();

    let tdx_vm = TdxVm::new(&vm_fd).unwrap();
    let _caps = tdx_vm.get_capabilities(&vm_fd).unwrap();
    let cpuid = kvm_fd
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    let _ = tdx_vm.init_vm(&vm_fd, &_caps, cpuid).unwrap();

    // get tdvf sections
    let mut firmware = std::fs::File::open("/usr/share/edk2/ovmf/OVMF.inteltdx.fd").unwrap();
    let sections = tdvf::parse_sections(&mut firmware).unwrap();
    let hob_section = tdvf::get_hob_section(&sections).unwrap();

    // create vcpu
    let mut vcpufd = vm_fd.create_vcpu(10).unwrap();
    let mut cpuid = kvm_fd
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    // set the X2APIC bit for CPUID[0x1] so the kernel can call KVM_SET_MSRS without failing
    for entry in cpuid.as_mut_slice().iter_mut() {
        if entry.index == 0x1 {
            entry.ecx &= 1 << 21;
        }
    }
    vcpufd.set_cpuid2(&cpuid).unwrap();
    TdxVcpu::init(&vcpufd, hob_section.memory_address).unwrap();

    // map memory to guest
    if !check_extension(KVM_CAP_GUEST_MEMFD) {
        panic!("KVM_CAP_GUEST_MEMFD isn't supported, which is required by TDX");
    }

    // In TDX you cannot modify the registers directly since they are
    // confidential. Therefore, if you want the VM to run custom code,
    // you need to map it to the reset vector on the guest: 0xfffffff0.

    // Start with the first 4k of memory (4G - 4k) as all 0s.
    let firmware_code = &mut [0u8; 4096].to_vec();

    // Map the firmware we want the VM to run on boot to the reset
    // vector, which is at 4G - 16B (0xfffffff0).
    for (idx, b) in FIRMWARE.iter().enumerate() {
        firmware_code[4096 - 16 + idx] = *b;
    }

    let firmware_userspace = ram_mmap(firmware_code.len() as u64);
    // (4 << 30) - 0x1000
    let guest_addr = 0xfffff000u64;

    // copy the firmware code into the memory allocated for `firmware_userspace`
    let address_space: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(firmware_userspace as *mut u8, firmware_code.len())
    };
    address_space[..firmware_code.len()].copy_from_slice(&firmware_code[..]);
    let firmware_userspace = address_space as *const [u8] as *const u8 as u64;

    let gmem = kvm_bindings::kvm_create_guest_memfd {
        size: firmware_code.len() as u64,
        flags: 0,
        reserved: [0; 6],
    };

    let gmem = vm_fd.create_guest_memfd(gmem).unwrap();
    let region = kvm_bindings::kvm_userspace_memory_region2 {
        slot: 0 as u32,
        // KVM_MEM_GUEST_MEMFD
        flags: 1 << 2,
        guest_phys_addr: guest_addr,
        memory_size: firmware_code.len() as u64,
        userspace_addr: firmware_userspace,
        guest_memfd_offset: 0,
        guest_memfd: gmem as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    unsafe {
        vm_fd.set_user_memory_region2(region).unwrap();
    }

    let attr = kvm_bindings::kvm_memory_attributes {
        address: guest_addr,
        size: firmware_code.len() as u64,
        // KVM_MEMORY_ATTRIBUTE_PRIVATE
        attributes: 1 << 3,
        flags: 0,
    };
    vm_fd.set_memory_attributes(attr).unwrap();

    if check_extension(KVM_CAP_MEMORY_MAPPING) {
        // TODO(jakecorrenti): the current CentOS SIG doesn't support the KVM_MEMORY_MAPPING or
        // KVM_TDX_EXTEND_MEMORY ioctls, which is what we would typically use here.
    } else {
        TdxVcpu::init_mem_region(&vcpufd, guest_addr, 1, 1, firmware_userspace).unwrap();
    }

    // finalize measurement
    tdx_vm.finalize(&vm_fd).unwrap();

    // run the vCPU

    // TDX will not allow the host to access private memory. In this case, we
    // are trying to jump to address 0x1000 which we haven't mapped anything
    // to. Therefore, we shouldn't be able to access this area of memory, which
    // should cause a MemoryFault.
    let ret = vcpufd.run();
    assert!(matches!(
        ret,
        Ok(kvm_ioctls::VcpuExit::MemoryFault {
            flags: 8,
            gpa: 0x1000,
            size: 0x1000
        })
    ))
}

/// Round number down to multiple
pub fn align_down(n: usize, m: usize) -> usize {
    n / m * m
}

/// Round number up to multiple
pub fn align_up(n: usize, m: usize) -> usize {
    align_down(n + m - 1, m)
}

/// Reserve a new memory region of the requested size to be used for maping from the given fd (if
/// any)
pub fn mmap_reserve(size: usize, fd: i32) -> *mut libc::c_void {
    let mut flags = libc::MAP_PRIVATE;
    flags |= libc::MAP_ANONYMOUS;
    unsafe { libc::mmap(0 as _, size, libc::PROT_NONE, flags, fd, 0) }
}

/// Activate memory in a reserved region from the given fd (if any), to make it accessible.
pub fn mmap_activate(
    ptr: *mut libc::c_void,
    size: usize,
    fd: i32,
    map_flags: u32,
    map_offset: i64,
) -> *mut libc::c_void {
    let noreserve = map_flags & (1 << 3);
    let readonly = map_flags & (1 << 0);
    let shared = map_flags & (1 << 1);
    let sync = map_flags & (1 << 2);
    let prot = libc::PROT_READ | (if readonly == 1 { 0 } else { libc::PROT_WRITE });
    let mut map_synced_flags = 0;
    let mut flags = libc::MAP_FIXED;

    flags |= if fd == -1 { libc::MAP_ANONYMOUS } else { 0 };
    flags |= if shared >= 1 {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    flags |= if noreserve >= 1 {
        libc::MAP_NORESERVE
    } else {
        0
    };

    if shared >= 1 && sync >= 1 {
        map_synced_flags = libc::MAP_SYNC | libc::MAP_SHARED_VALIDATE;
    }

    unsafe { libc::mmap(ptr, size, prot, flags | map_synced_flags, fd, map_offset) }
}

/// A mmap() abstraction to map guest RAM, simplifying the flag handling, taking care of
/// alignment requirements and installing guard pages.
pub fn ram_mmap(size: u64) -> u64 {
    const ALIGN: u64 = 4096;
    const GUARD_PAGE_SIZE: u64 = 4096;
    let mut total = size + ALIGN;
    let guard_addr = mmap_reserve(total as usize, -1);
    if guard_addr == libc::MAP_FAILED {
        panic!("MMAP activate failed");
    }
    assert!(ALIGN.is_power_of_two());
    assert!(ALIGN >= GUARD_PAGE_SIZE);

    let offset = align_up(guard_addr as usize, ALIGN as usize) - guard_addr as usize;

    let addr = mmap_activate(guard_addr.wrapping_add(offset), size as usize, -1, 0, 0);

    if addr == libc::MAP_FAILED {
        unsafe { libc::munmap(guard_addr, total as usize) };
        panic!("MMAP activate failed");
    }

    if offset > 0 {
        unsafe { libc::munmap(guard_addr, offset as usize) };
    }

    total -= offset as u64;
    if total > size + GUARD_PAGE_SIZE {
        unsafe {
            libc::munmap(
                addr.wrapping_add(size as usize)
                    .wrapping_add(GUARD_PAGE_SIZE as usize),
                (total - size - GUARD_PAGE_SIZE) as usize,
            )
        };
    }

    addr as u64
}

// NOTE(jakecorrenti): This IOCTL needs to get re-implemented manually. We need to check if KVM_CAP_MEMORY_MAPPING
// and KVM_CAP_GUEST_MEMFD are supported on the host, but those values are not present in rust-vmm/kvm-{ioctls, bindings}
ioctl_io_nr!(KVM_CHECK_EXTENSION, kvm_bindings::KVMIO, 0x03);

fn check_extension(i: u32) -> bool {
    let kvm = Kvm::new().unwrap();
    (unsafe { ioctl::ioctl_with_val(&kvm, KVM_CHECK_EXTENSION(), i.into()) }) > 0
}
