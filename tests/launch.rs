// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::vcpu::TdxVcpu;
use tdx::vm::TdxVm;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();
    let tdx_vcpu = TdxVcpu::new(&tdx_vm, 0).unwrap();
    let _ = tdx_vcpu.init_vcpu(0).unwrap();
}
