// SPDX-License-Identifier: Apache-2.0

mod linux;

use crate::linux::{Cmd, CmdId, TdxError};
use kvm_bindings::*;
use vmm_sys_util::*;

vmm_sys_util::ioctl_iowr_nr!(KVM_MEMORY_ENCRYPT_OP, KVMIO, 0xba, std::os::raw::c_ulong);

pub struct TdxVcpu {
    pub fd: kvm_ioctls::VcpuFd,
}

impl TdxVcpu {
    pub fn new(vm: &crate::vm::TdxVm, id: u64) -> Result<TdxVcpu, TdxError> {
        let vcpufd = vm.fd.create_vcpu(id)?;
        Ok(Self { fd: vcpufd })
    }

    /// TDX specific VCPU initialization using a TDVF HOB address
    pub fn init_vcpu(&self, hob_addr: u64) -> Result<(), TdxError> {
        let mut cmd = Cmd {
            id: CmdId::InitVcpu as u32,
            flags: 0,
            data: hob_addr as *const u64 as _,
            error: 0,
            _unused: 0,
        };
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(&self.fd, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            return Err(TdxError::from(ret));
        }
        Ok(())
    }
}
