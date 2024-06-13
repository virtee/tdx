// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;
use vmm_sys_util::*;

use tdx::launch::{TdxVcpu, TdxVm};
use tdx::tdvf;

// one page of `hlt`
const CODE: &[u8; 4096] = &[
    0xf4; 4096 // hlt
];

#[test]
fn launch() {
    const KVM_CAP_GUEST_MEMFD: u32 = 234;
    const KVM_CAP_MEMORY_MAPPING: u32 = 236;
    const CODE_MEM_ADDRESS: usize = 0x1000;

    // create vm
    let mut kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd, 100).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();

    // create vcpu
    let mut vcpufd = tdx_vm.fd.create_vcpu(10).unwrap();
    let tdx_vcpu = TdxVcpu::try_from((&mut vcpufd, &mut kvm_fd)).unwrap();
    let mut firmware = std::fs::File::open("./tests/data/OVMF.inteltdx.fd").unwrap();
    let sections = tdvf::parse_sections(&mut firmware).unwrap();
    let hob_section = tdvf::get_hob_section(&sections).unwrap();
    tdx_vcpu.init(hob_section.memory_address).unwrap();

    // code for the guest to run
    let userspace_addr = ram_mmap(CODE.len() as u64);
    let userspace_addr = unsafe { std::slice::from_raw_parts_mut(userspace_addr as *mut u8, CODE.len()) };
    userspace_addr[..CODE.len()].copy_from_slice(&CODE[..]);
    let userspace_addr = userspace_addr as *const [u8] as *const u8 as u64;
    // let code_addr_space: &mut [u8] =
    //     unsafe { std::slice::from_raw_parts_mut(userspace_addr as *mut u8, CODE.len()) };
    // code_addr_space[..CODE.len()].copy_from_slice(&CODE[..]);
    // let userspace_addr = code_addr_space as *const [u8] as *const u8 as u64;

    let code_gmem = KvmCreateGuestMemfd {
        size: CODE.len() as u64,
        flags: 0,
        reserved: [0; 6],
    };
    let code_gmem = linux_ioctls::create_guest_memfd(&tdx_vm.fd, &code_gmem);
    if code_gmem < 0 {
        panic!("create guest memfd for code failed");
    }

    let code_mem_region = KvmUserspaceMemoryRegion2 {
        slot: 22,
        flags: 1u32 << 2,
        guest_phys_addr: CODE_MEM_ADDRESS as u64,
        memory_size: CODE.len() as u64,
        userspace_addr,
        guest_memfd_offset: 0,
        guest_memfd: code_gmem as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    linux_ioctls::set_user_memory_region2(&tdx_vm.fd, &code_mem_region);

    let attr = KvmMemoryAttributes {
        address: CODE_MEM_ADDRESS as u64,
        size: CODE.len() as u64,
        attributes: 1u64 << 3,
        flags: 0,
    };
    linux_ioctls::set_memory_attributes(&tdx_vm.fd, &attr);
    tdx_vm.init_mem_region_raw(userspace_addr, CODE_MEM_ADDRESS as u64, CODE.len() as u64 / 4096, false).expect("INIT_MEM_REGION on code failed");

    // map memory to guest
    if !check_extension(KVM_CAP_GUEST_MEMFD) {
        panic!("KVM_CAP_GUEST_MEMFD isn't supported, which is required by TDX");
    }

    for (slot, section) in sections.iter().enumerate() {
        let userspace_address = ram_mmap(section.memory_data_size);
        set_user_memory_region2(&tdx_vm.fd, slot as u32, userspace_address, &section);
        set_memory_attributes(&tdx_vm.fd, &section);

        if check_extension(KVM_CAP_MEMORY_MAPPING) {
            // TODO(jakecorrenti): the current CentOS SIG doesn't support the KVM_MEMORY_MAPPING or
            // KVM_TDX_EXTEND_MEMORY ioctls, which is what we would typically use here.
        } else {
            tdx_vm.init_mem_region(&section, userspace_address).unwrap();
        }
    }

    // finalize measurement
    tdx_vm.finalize().unwrap();

    loop {
        match tdx_vcpu.fd.run().expect("run failed") {
            kvm_ioctls::VcpuExit::Hlt => {
                break;
            }
            _ => panic!("Unexpected exit reason: {:?}", errno::Error::last()),
        }
    }
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

// FIXME: All of the following code is not currently upstream at rust-vmm/kvm-ioctls. Therefore, we need to implement it ourselves.
// The work is currently ongoing as of 06/06/2024 and can be found at this link: https://github.com/rust-vmm/kvm-ioctls/pull/264
#[repr(C)]
#[derive(Debug)]
struct KvmCreateGuestMemfd {
    size: u64,
    flags: u64,
    reserved: [u64; 6],
}

ioctl_iowr_nr!(
    KVM_CREATE_GUEST_MEMFD,
    kvm_bindings::KVMIO,
    0xd4,
    KvmCreateGuestMemfd
);

fn create_guest_memfd(vmfd: &kvm_ioctls::VmFd, section: &tdvf::TdvfSection) -> i32 {
    let gmem = KvmCreateGuestMemfd {
        size: section.memory_data_size,
        flags: 0,
        reserved: [0; 6],
    };
    linux_ioctls::create_guest_memfd(&vmfd, &gmem)
}

#[repr(C)]
#[derive(Debug)]
struct KvmUserspaceMemoryRegion2 {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    pad2: [u64; 14],
}

ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION2,
    kvm_bindings::KVMIO,
    0x49,
    KvmUserspaceMemoryRegion2
);

fn set_user_memory_region2(
    vmfd: &kvm_ioctls::VmFd,
    slot: u32,
    userspace_address: u64,
    section: &tdvf::TdvfSection,
) {
    const KVM_MEM_GUEST_MEMFD: u32 = 1 << 2;
    let mem_region = KvmUserspaceMemoryRegion2 {
        slot,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: section.memory_address,
        memory_size: section.memory_data_size,
        userspace_addr: userspace_address,
        guest_memfd_offset: 0,
        guest_memfd: create_guest_memfd(vmfd, section) as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    linux_ioctls::set_user_memory_region2(vmfd, &mem_region)
}

#[repr(C)]
#[derive(Debug)]
struct KvmMemoryAttributes {
    address: u64,
    size: u64,
    attributes: u64,
    flags: u64,
}

ioctl_iow_nr!(
    KVM_SET_MEMORY_ATTRIBUTES,
    kvm_bindings::KVMIO,
    0xd2,
    KvmMemoryAttributes
);

fn set_memory_attributes(vmfd: &kvm_ioctls::VmFd, section: &tdvf::TdvfSection) {
    const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
    let attr = KvmMemoryAttributes {
        address: section.memory_address,
        size: section.memory_data_size,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE,
        flags: 0,
    };
    linux_ioctls::set_memory_attributes(vmfd, &attr)
}

mod linux_ioctls {
    use super::*;

    pub fn create_guest_memfd(fd: &kvm_ioctls::VmFd, gmem: &KvmCreateGuestMemfd) -> i32 {
        unsafe { ioctl::ioctl_with_ref(fd, KVM_CREATE_GUEST_MEMFD(), gmem) }
    }

    pub fn set_user_memory_region2(fd: &kvm_ioctls::VmFd, mem_region: &KvmUserspaceMemoryRegion2) {
        let ret = unsafe { ioctl::ioctl_with_ref(fd, KVM_SET_USER_MEMORY_REGION2(), mem_region) };
        if ret != 0 {
            panic!("Error: set_user_memory_region2: {}", errno::Error::last())
        }
    }

    pub fn set_memory_attributes(fd: &kvm_ioctls::VmFd, attr: &KvmMemoryAttributes) {
        let ret = unsafe { ioctl::ioctl_with_ref(fd, KVM_SET_MEMORY_ATTRIBUTES(), attr) };
        if ret != 0 {
            panic!("Error: set_memory_attributes: {}", errno::Error::last())
        }
    }
}
